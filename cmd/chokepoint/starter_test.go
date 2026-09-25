package main

import (
	"strings"
	"testing"

	"github.com/BipinRimal314/chokepoint/internal/detect"
	"github.com/BipinRimal314/chokepoint/internal/policy"
)

// TestStarterPolicyDecisions pins what the policy `chokepoint init` writes
// actually does, one call at a time, with a real workspace check.
func TestStarterPolicyDecisions(t *testing.T) {
	pol, err := policy.Parse([]byte(starterPolicy("/home/u/project", "enforce", "/home/u/.local/state/chokepoint")))
	if err != nil {
		t.Fatalf("starter policy does not load: %v", err)
	}
	scope, err := detect.NewScope(pol.Workspace)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		tool, target string
		want         policy.Effect
		rule         string
	}{
		{"read_text_file", "/home/u/project/src/main.go", policy.EffectAllow, ""},
		{"read_text_file", "/home/u/project/.env.example", policy.EffectAllow, ""},
		{"read_text_file", "/home/u/project/.env", policy.EffectDeny, "no-secrets"},
		{"read_text_file", "/home/u/project/deploy/server.pem", policy.EffectDeny, "no-secrets"},
		{"read_text_file", "/home/u/.ssh/id_ed25519", policy.EffectDeny, "no-secrets"},
		{"read_text_file", "/home/u/.aws/credentials", policy.EffectDeny, "no-secrets"},
		{"resources/read", "file:///etc/shadow", policy.EffectDeny, "no-secrets"},
		{"fetch", "http://169.254.169.254/latest/meta-data/", policy.EffectDeny, "no-cloud-metadata"},
		{"fetch", "https://example.com/", policy.EffectDeny, "outside-workspace"},
		{"read_text_file", "/etc/passwd", policy.EffectDeny, "outside-workspace"},
		{"read_text_file", "/home/u/project/../other/x", policy.EffectDeny, "outside-workspace"},
		{"write_file", "/home/u/project/notes.md", policy.EffectAllow, ""},
		// The agent may not change what watches it.
		{"write_file", "/home/u/project/chokepoint.yaml", policy.EffectDeny, "protect-agent-config"},
		{"Edit", "/home/u/project/.mcp.json", policy.EffectDeny, "protect-agent-config"},
		{"Write", "/home/u/project/.claude/settings.local.json", policy.EffectDeny, "protect-agent-config"},
		{"Bash", "/home/u/project/.mcp.json", policy.EffectDeny, "protect-agent-config"},
		{"move_file", "/home/u/.local/state/chokepoint/project-1a2b3c4d-filesystem.jsonl", policy.EffectDeny, "protect-agent-config"},
		{"Bash", "/home/u/.local/state/chokepoint", policy.EffectDeny, "protect-agent-config"},
		{"delete_directory", "/home/u/.local/state", policy.EffectDeny, "protect-agent-config"},
		// A folder that happens to be called chokepoint is not the log folder.
		{"write_file", "/home/u/project/cmd/chokepoint/main.go", policy.EffectAllow, ""},
		{"write_file", `C:\Users\u\project\.mcp.json`, policy.EffectDeny, "protect-agent-config"},
		// Reading the policy is not changing it.
		{"read_text_file", "/home/u/project/chokepoint.yaml", policy.EffectAllow, ""},
		{"read_text_file", `C:\Users\u\.ssh\id_ed25519`, policy.EffectDeny, "no-secrets"},
	}
	for _, c := range cases {
		var outside []string
		if r := detect.ParseResource(c.target); !scope.Contains(r) {
			outside = []string{c.target}
		}
		if strings.HasPrefix(c.target, "C:") {
			// Windows paths: only the pattern rules are under test here.
			outside = nil
		}
		d := pol.Evaluate(policy.Request{
			Tool:          c.tool,
			Targets:       []string{c.target},
			ScopeDeclared: true,
			OutOfScope:    outside,
			ArgsValid:     true,
		})
		if d.Effect != c.want || d.Rule != c.rule {
			t.Errorf("%s(%s) = %s by %q, want %s by %q", c.tool, c.target, d.Effect, d.Rule, c.want, c.rule)
		}
	}

	if d := pol.Evaluate(policy.Request{Tool: "write_file", Targets: []string{"/home/u/project/a"}, ScopeDeclared: true, ArgsValid: true}); len(d.Audited) != 1 {
		t.Errorf("a write was not recorded by watch-changes: %+v", d)
	}
}

// TestSelfProtectionHoldsInMonitorMode pins the one rule the starter policy
// enforces in monitor mode.
func TestSelfProtectionHoldsInMonitorMode(t *testing.T) {
	pol, err := policy.Parse([]byte(starterPolicy("/home/u/project", "monitor", "/home/u/.local/state/chokepoint")))
	if err != nil {
		t.Fatal(err)
	}
	d := pol.Evaluate(policy.Request{Tool: "Write", Targets: []string{"/home/u/project/chokepoint.yaml"}, ScopeDeclared: true, ArgsValid: true})
	if d.Rule != "protect-agent-config" || !d.AlwaysEnforce {
		t.Errorf("decision = %+v, want protect-agent-config, always enforced", d)
	}
	d = pol.Evaluate(policy.Request{Tool: "Read", Targets: []string{"/home/u/project/.env"}, ScopeDeclared: true, ArgsValid: true})
	if d.Rule != "no-secrets" || d.AlwaysEnforce {
		t.Errorf("no-secrets should not be always enforced unless the user uncomments it: %+v", d)
	}
}
