package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/BipinRimal314/chokepoint/internal/gateway"
	"github.com/BipinRimal314/chokepoint/internal/policy"
)

func decision() gateway.DecisionEvent {
	return gateway.DecisionEvent{
		ID:                "7",
		Tool:              "read_file",
		Method:            "tools/call",
		Targets:           []string{"/srv/data/a", "/etc/passwd"},
		Effect:            policy.EffectDeny,
		Rule:              "outside-declared-workspace",
		Score:             0.677,
		SessionCalls:      42,
		SessionTargets:    40,
		ScopeDeclared:     true,
		OutOfScope:        1,
		SessionOutOfScope: 3,
	}
}

func attrMap(t *testing.T, attrs []Attr) map[string]any {
	t.Helper()
	m := make(map[string]any, len(attrs))
	for _, a := range attrs {
		if _, dup := m[a.Key]; dup {
			t.Errorf("attribute %q appears twice", a.Key)
		}
		m[a.Key] = a.Value
	}
	return m
}

// TestGenAIAttributesMakeTheLogIngestible pins the keys external tooling
// depends on.
//
// ai-trace-auditor's OTel ingestor classifies a span as a tool call from
// gen_ai.operation.name or the presence of gen_ai.tool.name, and its flat-list
// can_parse requires at least one gen_ai.* attribute on the first span. Drop
// these and the log still looks fine, still parses as JSON, and silently stops
// being recognised as tool calls by anything that did not hear of chokepoint.
// That is a failure worth a test rather than a comment.
func TestGenAIAttributesMakeTheLogIngestible(t *testing.T) {
	m := attrMap(t, Attributes(decision()))

	if m[KeyGenAIOperation] != OperationToolCall {
		t.Errorf("%s = %v, want %q", KeyGenAIOperation, m[KeyGenAIOperation], OperationToolCall)
	}
	if m[KeyGenAIToolName] != "read_file" {
		t.Errorf("%s = %v, want read_file", KeyGenAIToolName, m[KeyGenAIToolName])
	}
	if m[KeyGenAIToolCall] != "7" {
		t.Errorf("%s = %v, want the request id", KeyGenAIToolCall, m[KeyGenAIToolCall])
	}
	for _, k := range []string{KeyGenAIOperation, KeyGenAIToolName, KeyGenAIToolCall} {
		if !strings.HasPrefix(k, "gen_ai.") {
			t.Errorf("key %q is not a gen_ai.* semantic convention", k)
		}
	}
}

// TestAbsentFactsAreOmittedNotZeroed is the same distinction the metrics layer
// makes with NaN and the report makes with "not scoreable". In an evidence log
// it matters more: a recorded 0.0 is an assertion that the session was measured
// and found unremarkable.
func TestAbsentFactsAreOmittedNotZeroed(t *testing.T) {
	ev := decision()
	ev.ScoreUnavailable = true
	ev.Rule = ""
	ev.Targets = nil
	ev.ScopeDeclared = false
	m := attrMap(t, Attributes(ev))

	for _, key := range []string{KeyScore, KeyRule, KeyTargets,
		KeyScopeDeclared, KeyOutOfScope, KeySessionOutOf} {
		if _, present := m[key]; present {
			t.Errorf("%s was recorded for a decision that has no such fact", key)
		}
	}
	// The facts that always exist are still there.
	if m[KeyEffect] == nil || m[KeySessionCalls] == nil {
		t.Errorf("a decision with no score should still record its effect and call count: %v", m)
	}
}

func TestScopeFactsOnlyAppearWhenAWorkspaceWasDeclared(t *testing.T) {
	declared := attrMap(t, Attributes(decision()))
	if declared[KeyScopeDeclared] != true {
		t.Errorf("%s = %v, want true", KeyScopeDeclared, declared[KeyScopeDeclared])
	}
	if declared[KeyOutOfScope] != 1 || declared[KeySessionOutOf] != 3 {
		t.Errorf("scope counts not recorded: %v", declared)
	}

	ev := decision()
	ev.ScopeDeclared = false
	if _, present := attrMap(t, Attributes(ev))[KeyOutOfScope]; present {
		t.Error("out-of-scope count recorded for a deployment with no declared workspace")
	}
}

// records parses the writer's output back into span records.
func records(t *testing.T, b *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line is not valid JSON: %v\n%s", err, line)
		}
		out = append(out, rec)
	}
	return out
}

func TestWriterEmitsOneParsableLinePerDecision(t *testing.T) {
	var b bytes.Buffer
	w := New(&b, Options{})

	for i := 0; i < 3; i++ {
		w.ToolCallDecided(decision())
	}

	recs := records(t, &b)
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}
	if w.Written() != 3 {
		t.Errorf("Written() = %d, want 3", w.Written())
	}

	// One trace per session, a distinct span per call — otherwise a consumer
	// cannot tell one session's calls apart from another's, or sees three
	// records collapse into one span.
	seen := map[string]bool{}
	for _, r := range recs {
		if r["traceId"] != w.TraceID() {
			t.Errorf("traceId = %v, want the session's %v", r["traceId"], w.TraceID())
		}
		id, _ := r["spanId"].(string)
		if id == "" {
			t.Error("record has no spanId")
		}
		if seen[id] {
			t.Errorf("spanId %q reused between records", id)
		}
		seen[id] = true
	}
}

func TestDeniedCallIsMarkedAsAnErrorStatus(t *testing.T) {
	var b bytes.Buffer
	w := New(&b, Options{})

	w.ToolCallDecided(decision()) // deny
	allowed := decision()
	allowed.Effect = policy.EffectAllow
	allowed.Rule = ""
	w.ToolCallDecided(allowed)

	recs := records(t, &b)
	status, ok := recs[0]["status"].(map[string]any)
	if !ok {
		t.Fatalf("denial has no status: %v", recs[0])
	}
	if status["code"] != float64(2) {
		t.Errorf("status.code = %v, want 2 (error)", status["code"])
	}
	if !strings.Contains(status["message"].(string), "outside-declared-workspace") {
		t.Errorf("status.message = %v, want it to name the rule", status["message"])
	}
	if _, present := recs[1]["status"]; present {
		t.Errorf("an allowed call should carry no error status: %v", recs[1])
	}
}

// TestOTLPValueEncoding checks the tagged union, since a consumer reads the
// type from which field is set. Integers go as strings because OTLP/JSON says
// so: a JSON number loses 64-bit precision past 2^53.
func TestOTLPValueEncoding(t *testing.T) {
	var b bytes.Buffer
	New(&b, Options{}).ToolCallDecided(decision())

	rec := records(t, &b)[0]
	attrs, ok := rec["attributes"].([]any)
	if !ok {
		t.Fatalf("attributes is not a list: %v", rec["attributes"])
	}

	byKey := map[string]map[string]any{}
	for _, a := range attrs {
		m := a.(map[string]any)
		byKey[m["key"].(string)] = m["value"].(map[string]any)
	}

	if got := byKey[KeySessionCalls]["intValue"]; got != "42" {
		t.Errorf("intValue = %v (%T), want the string \"42\"", got, got)
	}
	if got := byKey[KeyScore]["doubleValue"]; got != 0.677 {
		t.Errorf("doubleValue = %v, want 0.677", got)
	}
	if got := byKey[KeyScopeDeclared]["boolValue"]; got != true {
		t.Errorf("boolValue = %v, want true", got)
	}
	arr, ok := byKey[KeyTargets]["arrayValue"].(map[string]any)
	if !ok {
		t.Fatalf("targets is not an arrayValue: %v", byKey[KeyTargets])
	}
	vals := arr["values"].([]any)
	if len(vals) != 2 {
		t.Fatalf("targets has %d values, want 2", len(vals))
	}
	if vals[0].(map[string]any)["stringValue"] != "/srv/data/a" {
		t.Errorf("first target = %v", vals[0])
	}
}

// TestWriteFailureIsReportedOnceNotPerCall keeps a broken log from becoming a
// second outage. It must be loud, and it must be loud exactly once — this runs
// in the request path of every tool call.
func TestWriteFailureIsReportedOnceNotPerCall(t *testing.T) {
	var calls int
	w := New(failingWriter{}, Options{OnError: func(error) { calls++ }})

	for i := 0; i < 5; i++ {
		w.ToolCallDecided(decision())
	}

	if calls != 1 {
		t.Errorf("OnError called %d times, want exactly 1", calls)
	}
	if w.Written() != 0 {
		t.Errorf("Written() = %d, want 0 — nothing was actually written", w.Written())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk is gone") }

// TestCompletionsAreNotRecorded documents the deliberate gap. The log answers
// what was permitted and what was refused; upstream success is a different fact
// and correlating it would cost the append-only property.
func TestCompletionsAreNotRecorded(t *testing.T) {
	var b bytes.Buffer
	w := New(&b, Options{})
	w.ToolCallCompleted(gateway.CompletionEvent{ID: "7", Tool: "read_file"})

	if b.Len() != 0 {
		t.Errorf("a completion wrote a record: %s", b.String())
	}
}
