package main

import (
	"testing"

	"github.com/BipinRimal314/chokepoint/internal/detect"
	"github.com/BipinRimal314/chokepoint/internal/policy"
)

// TestStarterPolicyDecisions pins what the policy `chokepoint init` writes
// actually does, one call at a time, with a real workspace check.
func TestStarterPolicyDecisions(t *testing.T) {
	pol, err := policy.Parse([]byte(starterPolicy("/home/u/project", "enforce")))
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
	}
	for _, c := range cases {
		var outside []string
		if r := detect.ParseResource(c.target); !scope.Contains(r) {
			outside = []string{c.target}
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
