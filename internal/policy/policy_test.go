package policy

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

func TestFirstMatchWins(t *testing.T) {
	p := mustParse(t, `
default_effect: allow
rules:
  - name: deny-shell
    match: tool == "shell"
    effect: deny
    message: shell is not available; use the file tools
  - name: allow-everything-else
    effect: allow
`)

	got := p.Evaluate(Request{Tool: "shell", Method: "tools/call"})
	if got.Effect != EffectDeny {
		t.Errorf("effect = %v, want deny", got.Effect)
	}
	if got.Rule != "deny-shell" {
		t.Errorf("rule = %q, want deny-shell", got.Rule)
	}
	if !strings.Contains(got.Message, "file tools") {
		t.Errorf("message = %q, want actionable guidance", got.Message)
	}

	if got := p.Evaluate(Request{Tool: "read_file"}); got.Effect != EffectAllow {
		t.Errorf("effect = %v, want allow", got.Effect)
	}
}

func TestDefaultEffectIsAllowSoInstallingIsSafe(t *testing.T) {
	// A proxy that blocks everything until configured cannot be introduced
	// into a working system.
	p := mustParse(t, "rules: []\n")
	if p.DefaultEffect != EffectAllow {
		t.Errorf("default = %v, want allow", p.DefaultEffect)
	}
	if got := p.Evaluate(Request{Tool: "anything"}); got.Effect != EffectAllow {
		t.Errorf("effect = %v, want allow", got.Effect)
	}
}

func TestDefaultEffectDenyIsHonoured(t *testing.T) {
	p := mustParse(t, `
default_effect: deny
rules:
  - name: allow-reads
    match: tool == "read_file"
    effect: allow
`)
	if got := p.Evaluate(Request{Tool: "read_file"}); got.Effect != EffectAllow {
		t.Errorf("read_file effect = %v, want allow", got.Effect)
	}
	if got := p.Evaluate(Request{Tool: "write_file"}); got.Effect != EffectDeny {
		t.Errorf("write_file effect = %v, want deny", got.Effect)
	}
}

func TestAuditRecordsAndContinues(t *testing.T) {
	// Audit is how a rule is observed before it is armed.
	p := mustParse(t, `
default_effect: allow
rules:
  - name: watch-writes
    match: tool.startsWith("write")
    effect: audit
  - name: deny-etc
    match: targets.exists(t, t.startsWith("/etc/"))
    effect: deny
`)

	got := p.Evaluate(Request{Tool: "write_file", Targets: []string{"/etc/passwd"}})
	if got.Effect != EffectDeny {
		t.Fatalf("effect = %v, want deny", got.Effect)
	}
	if !reflect.DeepEqual(got.Audited, []string{"watch-writes"}) {
		t.Errorf("audited = %v, want [watch-writes]", got.Audited)
	}
}

func TestRulesCanReferenceSessionStateAndScore(t *testing.T) {
	// The rule the whole project exists to make expressible.
	p := mustParse(t, `
default_effect: allow
rules:
  - name: halt-decomposed-sweep
    match: decomposition_score > 0.7 && session_targets > 20
    effect: deny
    message: session shows decomposition-like breadth; stopping
`)

	safe := p.Evaluate(Request{Tool: "read_file", DecompositionScore: 0.2, SessionTargets: 30})
	if safe.Effect != EffectAllow {
		t.Errorf("low score effect = %v, want allow", safe.Effect)
	}

	narrow := p.Evaluate(Request{Tool: "read_file", DecompositionScore: 0.9, SessionTargets: 5})
	if narrow.Effect != EffectAllow {
		t.Errorf("narrow session effect = %v, want allow", narrow.Effect)
	}

	sweep := p.Evaluate(Request{Tool: "read_file", DecompositionScore: 0.9, SessionTargets: 30})
	if sweep.Effect != EffectDeny {
		t.Errorf("sweep effect = %v, want deny", sweep.Effect)
	}
}

func TestRulesCanInspectArguments(t *testing.T) {
	p := mustParse(t, `
default_effect: allow
rules:
  - name: no-recursive-delete
    match: tool == "delete" && has(args.recursive) && args.recursive == true
    effect: deny
`)

	if got := p.Evaluate(Request{Tool: "delete", Args: map[string]any{"recursive": true}}); got.Effect != EffectDeny {
		t.Errorf("recursive delete effect = %v, want deny", got.Effect)
	}
	if got := p.Evaluate(Request{Tool: "delete", Args: map[string]any{"recursive": false}}); got.Effect != EffectAllow {
		t.Errorf("non-recursive delete effect = %v, want allow", got.Effect)
	}
	if got := p.Evaluate(Request{Tool: "delete"}); got.Effect != EffectAllow {
		t.Errorf("delete with no args effect = %v, want allow", got.Effect)
	}
}

func TestUnknownVariableIsALoadTimeError(t *testing.T) {
	// A policy engine that fails open on a typo reports protection it is not
	// providing. This must fail loudly, at load, not silently at midnight.
	_, err := Parse([]byte(`
rules:
  - name: typo
    match: tolo == "shell"
    effect: deny
`))
	if err == nil {
		t.Fatal("expected a compile error for an undeclared variable")
	}
	if !strings.Contains(err.Error(), "tolo") {
		t.Errorf("err = %v, want it to name the offending identifier", err)
	}
}

func TestNonBooleanMatchIsRejected(t *testing.T) {
	_, err := Parse([]byte(`
rules:
  - name: not-a-predicate
    match: tool
    effect: deny
`))
	if err == nil {
		t.Fatal("expected an error for a non-boolean match")
	}
	if !strings.Contains(err.Error(), "bool") {
		t.Errorf("err = %v, want a message about the expected type", err)
	}
}

func TestUnknownEffectIsRejected(t *testing.T) {
	_, err := Parse([]byte(`
rules:
  - name: bad
    match: 'tool == "x"'
    effect: quarantine
`))
	if err == nil || !strings.Contains(err.Error(), "unknown effect") {
		t.Fatalf("err = %v, want an unknown-effect error", err)
	}
}

func TestUnknownYAMLKeyIsRejected(t *testing.T) {
	// Same failure class as a misspelled variable: a setting that looks
	// applied but is not.
	_, err := Parse([]byte(`
rules:
  - name: typo-key
    matches: 'tool == "x"'
    effect: deny
`))
	if err == nil {
		t.Fatal("expected an error for an unknown key")
	}
}

func TestMissingNameIsRejected(t *testing.T) {
	// Rules are identified by name in audit records; an unnamed rule produces
	// an unattributable decision.
	_, err := Parse([]byte(`
rules:
  - match: 'tool == "x"'
    effect: deny
`))
	if err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("err = %v, want a missing-name error", err)
	}
}

func TestRuntimeErrorDoesNotAbortEvaluation(t *testing.T) {
	// A type mismatch on a dynamic field must not take down every agent
	// behind the proxy.
	p := mustParse(t, `
default_effect: allow
rules:
  - name: fragile
    match: args.count > 5
    effect: deny
  - name: catch-all-audit
    effect: audit
`)

	got := p.Evaluate(Request{Tool: "x", Args: map[string]any{"count": "not-a-number"}})
	if got.Effect != EffectAllow {
		t.Errorf("effect = %v, want allow (fail open on rule error)", got.Effect)
	}
	var sawError bool
	for _, a := range got.Audited {
		if strings.Contains(a, "fragile") && strings.Contains(a, "evaluation error") {
			sawError = true
		}
	}
	if !sawError {
		t.Errorf("audited = %v, want the failing rule recorded", got.Audited)
	}
}

func TestExtractTargets(t *testing.T) {
	args := map[string]any{
		"path":    "/etc/passwd",
		"options": map[string]any{"url": "https://api.internal/v1"},
		"items":   []any{map[string]any{"file": "/tmp/a"}, map[string]any{"file": "/tmp/b"}},
		"count":   7,
		"empty":   "",
	}

	got := ExtractTargets(args)
	want := []string{"/etc/passwd", "/tmp/a", "/tmp/b", "https://api.internal/v1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("targets = %v, want %v", got, want)
	}
}

func TestExtractTargetsIsDeterministic(t *testing.T) {
	// Map iteration order is randomised; an audit record that reorders between
	// runs over identical input is not usable as evidence.
	args := map[string]any{
		"path": "/a", "file": "/b", "uri": "/c", "host": "/d", "target": "/e",
	}
	first := ExtractTargets(args)
	for i := 0; i < 50; i++ {
		if got := ExtractTargets(args); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d gave %v, want %v", i, got, first)
		}
	}
}

func TestExtractTargetsIsDepthBounded(t *testing.T) {
	// A deeply nested argument object must not become an unbounded walk.
	deep := map[string]any{"path": "/visible"}
	nested := any(map[string]any{"path": "/too-deep"})
	for i := 0; i < 20; i++ {
		nested = map[string]any{"inner": nested}
	}
	deep["nest"] = nested

	got := ExtractTargets(deep)
	for _, target := range got {
		if target == "/too-deep" {
			t.Fatal("extraction went past the depth bound")
		}
	}
	if len(got) != 1 || got[0] != "/visible" {
		t.Errorf("targets = %v, want [/visible]", got)
	}
}

func TestEmptyMatchIsCatchAll(t *testing.T) {
	p := mustParse(t, `
default_effect: allow
rules:
  - name: deny-all
    effect: deny
`)
	if got := p.Evaluate(Request{Tool: "anything"}); got.Effect != EffectDeny {
		t.Errorf("effect = %v, want deny", got.Effect)
	}
}

func TestWorkspaceIsCarriedAsData(t *testing.T) {
	// This package holds the declaration and never interprets it. Normalising a
	// path and testing containment belongs to detect, because doing it against
	// raw strings is defeated by one "../".
	p := mustParse(t, `
default_effect: allow
workspace:
  - /srv/data
  - https://api.example.com/v1
rules: []
`)
	want := []string{"/srv/data", "https://api.example.com/v1"}
	if !reflect.DeepEqual(p.Workspace, want) {
		t.Errorf("Workspace = %v, want %v", p.Workspace, want)
	}
}

func TestScopeRulesReadSessionAndCallFacts(t *testing.T) {
	p := mustParse(t, `
default_effect: allow
workspace:
  - /srv/data
rules:
  - name: outside-workspace
    match: scope_declared && out_of_scope.size() > 0
    effect: deny
    message: outside the declared workspace
  - name: wandering-session
    match: scope_declared && session_out_of_scope > 5
    effect: deny
`)

	inside := p.Evaluate(Request{
		Tool: "read_file", ScopeDeclared: true, Targets: []string{"/srv/data/a"},
	})
	if inside.Effect != EffectAllow {
		t.Errorf("in-scope call: effect = %v, want allow", inside.Effect)
	}

	outside := p.Evaluate(Request{
		Tool: "read_file", ScopeDeclared: true,
		Targets: []string{"/etc/passwd"}, OutOfScope: []string{"/etc/passwd"},
	})
	if outside.Effect != EffectDeny || outside.Rule != "outside-workspace" {
		t.Errorf("out-of-scope call: effect = %v rule = %q, want deny outside-workspace",
			outside.Effect, outside.Rule)
	}

	session := p.Evaluate(Request{
		Tool: "read_file", ScopeDeclared: true, SessionOutOfScope: 9,
	})
	if session.Effect != EffectDeny || session.Rule != "wandering-session" {
		t.Errorf("wandering session: effect = %v rule = %q, want deny wandering-session",
			session.Effect, session.Rule)
	}
}

// TestScopeRulesAreInertWithoutAWorkspace is the deployment-safety property.
// The same policy on a deployment that declared no working set must not deny
// everything — a scope rule with nothing to compare against protects nothing,
// and should say so by not firing rather than by blocking the world.
func TestScopeRulesAreInertWithoutAWorkspace(t *testing.T) {
	p := mustParse(t, `
default_effect: allow
rules:
  - name: outside-workspace
    match: scope_declared && out_of_scope.size() > 0
    effect: deny
`)
	got := p.Evaluate(Request{Tool: "read_file", Targets: []string{"/etc/passwd"}})
	if got.Effect != EffectAllow {
		t.Errorf("effect = %v, want allow — an undeclared workspace must not deny", got.Effect)
	}
}

// TestUnguardedScopeRuleStillEvaluates records the sharp edge deliberately: a
// rule that omits scope_declared is a valid expression, so it is the policy
// author's job to guard it. The example policy shows the guarded form.
func TestUnguardedScopeRuleStillEvaluates(t *testing.T) {
	p := mustParse(t, `
default_effect: allow
rules:
  - name: unguarded
    match: out_of_scope.size() == 0
    effect: deny
`)
	if got := p.Evaluate(Request{Tool: "read_file"}); got.Effect != EffectDeny {
		t.Errorf("effect = %v, want deny — an unguarded rule matches on an empty list", got.Effect)
	}
}

func TestRateWindowParsing(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		want    time.Duration
		wantErr bool
	}{
		{"absent", "rules: []\n", 0, false},
		{"seconds", "rate_window: 30s\nrules: []\n", 30 * time.Second, false},
		{"minutes", "rate_window: 5m\nrules: []\n", 5 * time.Minute, false},
		// A window that fails to parse must stop the load. Falling back to a
		// default would leave the operator with a rate limit measured over a
		// span they did not choose and were never told about.
		{"malformed", "rate_window: 30 seconds\nrules: []\n", 0, true},
		{"zero", "rate_window: 0s\nrules: []\n", 0, true},
		{"negative", "rate_window: -1m\nrules: []\n", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse([]byte(tc.yaml))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) succeeded, want an error", tc.yaml)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := p.RateWindowDuration(); got != tc.want {
				t.Errorf("RateWindowDuration() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRateRulesReadWindowCounts(t *testing.T) {
	p, err := Parse([]byte(`
default_effect: allow
rate_window: 1m
rules:
  - name: burst
    match: calls_in_window > 100
    effect: deny
    message: slow down
  - name: fan-out
    match: targets_in_window > 50
    effect: deny
    message: too many distinct targets at once
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	cases := []struct {
		name       string
		req        Request
		wantEffect Effect
		wantRule   string
	}{
		{"quiet", Request{CallsInWindow: 10, TargetsInWindow: 10}, EffectAllow, ""},
		{"burst", Request{CallsInWindow: 101, TargetsInWindow: 1}, EffectDeny, "burst"},
		// Narrow and fast is a retry loop; wide and fast is a sweep. The second
		// rule catches the sweep that stayed under the call limit.
		{"fan-out", Request{CallsInWindow: 60, TargetsInWindow: 60}, EffectDeny, "fan-out"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.Evaluate(tc.req)
			if got.Effect != tc.wantEffect || got.Rule != tc.wantRule {
				t.Errorf("Evaluate = %s/%q, want %s/%q",
					got.Effect, got.Rule, tc.wantEffect, tc.wantRule)
			}
		})
	}
}
