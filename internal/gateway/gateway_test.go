package gateway

import (
	"context"
	"encoding/json"
	"fmt"
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

// mustScope builds a working set the way the CLI does: from the policy's own
// declaration, validated before the gateway is constructed.
func mustScope(t *testing.T, p *policy.Policy) detect.Scope {
	t.Helper()
	sc, err := detect.NewScope(p.Workspace)
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}
	return sc
}

const scopedPolicy = `
default_effect: allow
workspace:
  - /srv/data
rules:
  - name: outside-workspace
    match: scope_declared && out_of_scope.size() > 0
    effect: deny
    message: that path is outside the declared workspace
`

// TestSingleToolSweepIsStoppedByScope is the end-to-end payoff of Step 2.
//
// The same sweep the scorer cannot catch — one tool, any number of targets,
// pinned at 0.400 forever by TestSingleToolSweepIsUnderThreshold — is stopped
// on its first out-of-bounds call, because scope does not ask how varied the
// behaviour looks.
func TestSingleToolSweepIsStoppedByScope(t *testing.T) {
	pol := mustPolicy(t, scopedPolicy)
	g := New(Options{
		Policy:   pol,
		Scope:    mustScope(t, pol),
		Detector: detect.NewSession(detect.Config{}),
	})

	// Ten in-bounds reads: allowed, and they build exactly the session shape
	// the scorer sees as a single-tool sweep.
	for i := 0; i < 10; i++ {
		msg := toolCall(t, i, "read_file", map[string]any{
			"path": fmt.Sprintf("/srv/data/f%02d", i),
		})
		if got := intercept(t, g, msg); got.Decision != proxy.Forward {
			t.Fatalf("in-bounds call %d was not forwarded", i)
		}
	}

	// The eleventh reads the same file with the same tool, one directory over.
	// Nothing about the behaviour changed; only the destination did.
	got := intercept(t, g, toolCall(t, 10, "read_file",
		map[string]any{"path": "/home/u/.ssh/id_rsa"}))
	if got.Decision != proxy.Reject {
		t.Fatal("out-of-bounds call was forwarded; scope did not fire")
	}

	reply, err := jsonrpc.Parse(got.Message)
	if err != nil {
		t.Fatalf("denial does not parse: %v", err)
	}
	var errObj struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(reply.Error, &errObj); err != nil {
		t.Fatal(err)
	}
	if errObj.Data["rule"] != "outside-workspace" {
		t.Errorf("data.rule = %v, want outside-workspace", errObj.Data["rule"])
	}
	// The agent has to know which argument was the problem to correct itself.
	offending, _ := errObj.Data["out_of_scope"].([]any)
	if len(offending) != 1 || offending[0] != "/home/u/.ssh/id_rsa" {
		t.Errorf("data.out_of_scope = %v, want the offending path", errObj.Data["out_of_scope"])
	}

	// And the score never rose above the shipped threshold throughout.
	if score := g.assess().Score; score >= 0.45 {
		t.Errorf("score = %.3f; the premise is that this sweep stays under 0.45", score)
	}
}

// TestTraversalOutOfWorkspaceIsDenied checks the whole path end to end, since
// each layer normalising correctly is worth nothing if the gateway compares
// something else.
func TestTraversalOutOfWorkspaceIsDenied(t *testing.T) {
	pol := mustPolicy(t, scopedPolicy)
	g := New(Options{
		Policy:   pol,
		Scope:    mustScope(t, pol),
		Detector: detect.NewSession(detect.Config{}),
	})

	got := intercept(t, g, toolCall(t, 1, "read_file",
		map[string]any{"path": "/srv/data/../../etc/shadow"}))
	if got.Decision != proxy.Reject {
		t.Error("a traversal out of the workspace was forwarded")
	}

	// A traversal that stays inside is ordinary work and must not be denied.
	got = intercept(t, g, toolCall(t, 2, "read_file",
		map[string]any{"path": "/srv/data/sub/../f01"}))
	if got.Decision != proxy.Forward {
		t.Error("a traversal that resolves back inside the workspace was denied")
	}
}

// TestScopeFactsAreAbsentWithoutAWorkspace pins the default. A deployment that
// declared no working set must see no scope facts at all, so that a policy
// copied from a scoped deployment fails inert rather than closed.
func TestScopeFactsAreAbsentWithoutAWorkspace(t *testing.T) {
	g := New(Options{
		Policy: mustPolicy(t, `
default_effect: allow
rules:
  - name: outside-workspace
    match: scope_declared && out_of_scope.size() > 0
    effect: deny
`),
		Detector: detect.NewSession(detect.Config{}),
	})

	got := intercept(t, g, toolCall(t, 1, "read_file",
		map[string]any{"path": "/home/u/.ssh/id_rsa"}))
	if got.Decision != proxy.Forward {
		t.Error("a scope rule fired on a deployment with no declared workspace")
	}

	rep := g.scopeReport()
	if rep.Declared || rep.OutOfScope != 0 {
		t.Errorf("scopeReport = %+v, want undeclared and empty", rep)
	}
	if out := g.outOfScope([]string{"/home/u/.ssh/id_rsa"}); out != nil {
		t.Errorf("outOfScope = %v, want nil without a declared workspace", out)
	}
}

// TestObserverSeesScopeFacts keeps telemetry honest: an operator watching the
// decision stream should be able to see a session leaving its working set
// without waiting for a denial.
func TestObserverSeesScopeFacts(t *testing.T) {
	pol := mustPolicy(t, `
default_effect: allow
workspace:
  - /srv/data
rules: []
`)
	rec := &recordingObserver{}
	g := New(Options{
		Policy:   pol,
		Scope:    mustScope(t, pol),
		Detector: detect.NewSession(detect.Config{}),
		Observer: rec,
	})

	for i, path := range []string{"/srv/data/a", "/etc/passwd", "/etc/passwd", "/root/.aws/creds"} {
		intercept(t, g, toolCall(t, i, "read_file", map[string]any{"path": path}))
	}

	if len(rec.decisions) != 4 {
		t.Fatalf("observed %d decisions, want 4", len(rec.decisions))
	}
	if d := rec.decisions[0]; !d.ScopeDeclared || d.OutOfScope != 0 || d.SessionOutOfScope != 0 {
		t.Errorf("first decision = %+v, want declared and in scope", d)
	}
	if d := rec.decisions[1]; d.OutOfScope != 1 || d.SessionOutOfScope != 1 {
		t.Errorf("second decision: OutOfScope = %d SessionOutOfScope = %d, want 1 and 1",
			d.OutOfScope, d.SessionOutOfScope)
	}
	// The same path again is not a new place.
	if d := rec.decisions[2]; d.SessionOutOfScope != 1 {
		t.Errorf("third decision: SessionOutOfScope = %d, want 1 — a repeat is not a new place",
			d.SessionOutOfScope)
	}
	if d := rec.decisions[3]; d.SessionOutOfScope != 2 {
		t.Errorf("fourth decision: SessionOutOfScope = %d, want 2", d.SessionOutOfScope)
	}
}

type recordingObserver struct {
	decisions []DecisionEvent
}

func (r *recordingObserver) ToolCallDecided(e DecisionEvent)   { r.decisions = append(r.decisions, e) }
func (r *recordingObserver) ToolCallCompleted(CompletionEvent) {}

// TestMultiTargetCallIsDeniedOnAnyTarget pins the asymmetry documented on
// outOfScope: enforcement examines every target on a call, while the session
// counts see only the one target retained per observation.
func TestMultiTargetCallIsDeniedOnAnyTarget(t *testing.T) {
	pol := mustPolicy(t, scopedPolicy)
	g := New(Options{
		Policy:   pol,
		Scope:    mustScope(t, pol),
		Detector: detect.NewSession(detect.Config{}),
	})

	// One argument is inside the workspace, the other is not.
	got := intercept(t, g, toolCall(t, 1, "copy_file", map[string]any{
		"path":   "/srv/data/a",
		"target": "/etc/cron.d/backdoor",
	}))
	if got.Decision != proxy.Reject {
		t.Fatal("a call with one out-of-scope target was forwarded")
	}
	if out := g.outOfScope([]string{"/srv/data/a", "/etc/cron.d/backdoor"}); len(out) != 1 {
		t.Errorf("outOfScope = %v, want just the out-of-bounds target", out)
	}
}
