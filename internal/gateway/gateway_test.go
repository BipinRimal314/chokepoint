package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/BipinRimal314/chokepoint/internal/detect"
	"github.com/BipinRimal314/chokepoint/internal/jsonrpc"
	"github.com/BipinRimal314/chokepoint/internal/policy"
	"github.com/BipinRimal314/chokepoint/internal/proxy"
)

func mustPolicy(t *testing.T, src string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return p
}

// toolCall builds a tools/call request message.
func toolCall(t *testing.T, id int, name string, args map[string]any) *jsonrpc.Message {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params":  map[string]any{"name": name, "arguments": args},
	})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := jsonrpc.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func intercept(t *testing.T, g *Gateway, msg *jsonrpc.Message) proxy.Interception {
	t.Helper()
	got, err := g.Intercept(context.Background(), proxy.ClientToServer, msg)
	if err != nil {
		t.Fatalf("Intercept: %v", err)
	}
	return got
}

func TestForwardsWhenPolicyAllows(t *testing.T) {
	g := New(Options{
		Policy:   mustPolicy(t, "default_effect: allow\nrules: []\n"),
		Detector: detect.NewSession(detect.Config{}),
	})

	got := intercept(t, g, toolCall(t, 1, "read_file", map[string]any{"path": "/tmp/a"}))
	if got.Decision != proxy.Forward {
		t.Errorf("decision = %v, want Forward", got.Decision)
	}
}

func TestDeniedCallGetsCorrelatedJSONRPCError(t *testing.T) {
	g := New(Options{
		Policy: mustPolicy(t, `
default_effect: allow
rules:
  - name: no-shell
    match: tool == "shell"
    effect: deny
    message: shell is unavailable; use read_file
`),
		Detector: detect.NewSession(detect.Config{}),
	})

	got := intercept(t, g, toolCall(t, 77, "shell", map[string]any{"cmd": "rm -rf /"}))
	if got.Decision != proxy.Reject {
		t.Fatalf("decision = %v, want Reject", got.Decision)
	}

	reply, err := jsonrpc.Parse(got.Message)
	if err != nil {
		t.Fatalf("denial does not parse: %v", err)
	}
	if !reply.IsResponse() {
		t.Error("denial is not a response")
	}
	if reply.IDKey() != "77" {
		t.Errorf("id = %s, want 77", reply.ID)
	}

	var errObj struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	}
	if err := json.Unmarshal(reply.Error, &errObj); err != nil {
		t.Fatal(err)
	}
	if errObj.Code != jsonrpc.CodePolicyDenied {
		t.Errorf("code = %d, want %d", errObj.Code, jsonrpc.CodePolicyDenied)
	}
	if !strings.Contains(errObj.Message, "read_file") {
		t.Errorf("message = %q, want actionable guidance", errObj.Message)
	}
	if errObj.Data["rule"] != "no-shell" {
		t.Errorf("data.rule = %v, want no-shell", errObj.Data["rule"])
	}
}

func TestDecompositionSweepIsStoppedMidSession(t *testing.T) {
	// The end-to-end claim: every call is an ordinary read of an ordinary
	// path, allowed on its own. Only the accumulated breadth trips the rule.
	g := New(Options{
		Policy: mustPolicy(t, `
default_effect: allow
rules:
  - name: halt-sweep
    match: decomposition_score > 0.6 && session_targets > 12
    effect: deny
    message: session breadth looks like a decomposed sweep
`),
		Detector: detect.NewSession(detect.Config{}),
	})

	tools := []string{"read_file", "list_dir", "grep", "stat"}
	var denied int
	var firstDenialAt = -1

	for i := 0; i < 40; i++ {
		msg := toolCall(t, i, tools[i%len(tools)], map[string]any{
			"path": "/srv/data/file" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
		})
		got := intercept(t, g, msg)
		if got.Decision == proxy.Reject {
			denied++
			if firstDenialAt < 0 {
				firstDenialAt = i
			}
		}
	}

	if denied == 0 {
		t.Fatal("a 40-call sweep across distinct targets was never stopped")
	}
	// It must not fire immediately: the first handful of calls of any session
	// look novel, and blocking those would break every agent on startup.
	if firstDenialAt < detect.MinCallsForScore {
		t.Errorf("first denial at call %d, want at least %d", firstDenialAt, detect.MinCallsForScore)
	}
}

func TestRepetitiveWorkloadIsNotStopped(t *testing.T) {
	// The false-positive side of the same claim. A legitimate agent polling
	// one file must never trip the breadth rule.
	g := New(Options{
		Policy: mustPolicy(t, `
default_effect: allow
rules:
  - name: halt-sweep
    match: decomposition_score > 0.6 && session_targets > 12
    effect: deny
`),
		Detector: detect.NewSession(detect.Config{}),
	})

	for i := 0; i < 100; i++ {
		got := intercept(t, g, toolCall(t, i, "read_file", map[string]any{
			"path": "/app/config.yaml",
		}))
		if got.Decision == proxy.Reject {
			t.Fatalf("repetitive workload denied at call %d", i)
		}
	}
}

func TestNonToolMethodsPassThroughUngated(t *testing.T) {
	g := New(Options{
		Policy:   mustPolicy(t, "default_effect: deny\nrules: []\n"),
		Detector: detect.NewSession(detect.Config{}),
	})

	raw, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": "2025-06-18"},
	})
	msg, err := jsonrpc.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Even with default deny, the handshake must survive — gating it would
	// mean the session never establishes and no policy ever runs.
	got := intercept(t, g, msg)
	if got.Decision != proxy.Forward {
		t.Errorf("initialize decision = %v, want Forward", got.Decision)
	}
}

func TestResourceReadsCountTowardTheSession(t *testing.T) {
	// An agent that enumerates resources instead of calling tools is doing
	// the same sweep by another route.
	det := detect.NewSession(detect.Config{})
	g := New(Options{Detector: det})

	for i := 0; i < 5; i++ {
		raw, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": i, "method": "resources/read",
			"params": map[string]any{"uri": "file:///srv/x" + string(rune('a'+i))},
		})
		msg, err := jsonrpc.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		intercept(t, g, msg)
	}

	if got := det.Len(); got != 5 {
		t.Errorf("detector saw %d calls, want 5", got)
	}
	if got := det.Vector().Get(detect.FeatSecondaryEventCount); got != 5 {
		t.Errorf("secondary_event_count = %v, want 5", got)
	}
}

func TestErrorResponseIsRecordedAsPeripheral(t *testing.T) {
	// An agent probing for what it is allowed to do generates errors; a
	// detector blind to them misses the probe.
	det := detect.NewSession(detect.Config{})
	g := New(Options{Detector: det})

	intercept(t, g, toolCall(t, 5, "read_file", map[string]any{"path": "/x"}))

	raw, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 5,
		"error": map[string]any{"code": -32602, "message": "no such file"},
	})
	resp, err := jsonrpc.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Intercept(context.Background(), proxy.ServerToClient, resp); err != nil {
		t.Fatalf("Intercept: %v", err)
	}

	if got := det.Vector().Get(detect.FeatPeripheralEventCount); got != 1 {
		t.Errorf("peripheral_event_count = %v, want 1", got)
	}
}

func TestMalformedParamsAreForwardedNotRejected(t *testing.T) {
	// The upstream server owns its tool schemas; chokepoint must not become a
	// second, divergent validator.
	g := New(Options{
		Policy:   mustPolicy(t, "default_effect: allow\nrules: []\n"),
		Detector: detect.NewSession(detect.Config{}),
	})

	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"not-an-object"}`)
	msg, err := jsonrpc.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := intercept(t, g, msg); got.Decision != proxy.Forward {
		t.Errorf("decision = %v, want Forward", got.Decision)
	}
}

func TestNoPolicyMeansTransparent(t *testing.T) {
	g := New(Options{Detector: detect.NewSession(detect.Config{})})
	got := intercept(t, g, toolCall(t, 1, "anything", map[string]any{"path": "/x"}))
	if got.Decision != proxy.Forward {
		t.Errorf("decision = %v, want Forward with no policy", got.Decision)
	}
}
