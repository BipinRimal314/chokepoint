package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// TestWrapAndUnwrap pins the round trip on a Claude Code style config: local
// servers are wrapped, a remote one is left alone, wrapping twice changes
// nothing, and unwrap restores the original commands.
func TestWrapAndUnwrap(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	t.Chdir(dir)

	if err := cmdInit(nil); err != nil {
		t.Fatal(err)
	}
	original := `{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv"], "env": {"A": "1"}},
    "remote": {"type": "http", "url": "https://mcp.example.com"}
  },
  "otherSetting": true
}`
	if err := os.WriteFile(".mcp.json", []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cmdWrap([]string{".mcp.json"}); err != nil {
		t.Fatal(err)
	}
	cfg := readConfig(t)
	fs := cfg["mcpServers"].(map[string]any)["filesystem"].(map[string]any)
	if !isChokepoint(fs["command"].(string)) {
		t.Fatalf("filesystem not wrapped: %v", fs)
	}
	args := toStrings(fs["args"])
	if args[0] != "--policy" || args[2] != "--audit-log" || args[4] != "--" || args[5] != "npx" {
		t.Errorf("wrapped args = %v", args)
	}
	if fs["env"].(map[string]any)["A"] != "1" || cfg["otherSetting"] != true {
		t.Error("wrap lost settings it should not touch")
	}
	if _, has := cfg["mcpServers"].(map[string]any)["remote"].(map[string]any)["command"]; has {
		t.Error("a remote server was given a command")
	}
	// Windows has no permission bits; a folder in the user's profile is
	// private by its ACL instead.
	if info, err := os.Stat(filepath.Join(dir, "state", "chokepoint")); err != nil {
		t.Error(err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("audit directory mode = %v, want 0700", info.Mode().Perm())
	}
	if got, _ := os.ReadFile(".mcp.json.chokepoint-backup"); string(got) != original {
		t.Error("backup does not hold the original")
	}

	wrapped, _ := os.ReadFile(".mcp.json")
	if err := cmdWrap([]string{".mcp.json"}); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(".mcp.json"); string(again) != string(wrapped) {
		t.Error("wrapping twice changed the config")
	}

	if err := cmdUnwrap([]string{".mcp.json"}); err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	_ = json.Unmarshal([]byte(original), &want)
	if got := readConfig(t); !reflect.DeepEqual(got, want) {
		t.Errorf("unwrap did not restore the original:\n got %v\nwant %v", got, want)
	}
}

func TestInitRefusesToOverwrite(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := cmdInit(nil); err != nil {
		t.Fatal(err)
	}
	if err := cmdInit(nil); err == nil {
		t.Error("init overwrote an existing policy")
	}
}

func readConfig(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(".mcp.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestLogNameCannotEscapeTheAuditDirectory pins that a server name from a
// config file, which a cloned repository controls, cannot steer where the
// audit log is written.
func TestLogNameCannotEscapeTheAuditDirectory(t *testing.T) {
	for _, server := range []string{"../../.bashrc", "a/b", `..\..\x`, "/etc/passwd", ".."} {
		name := logName("/home/u/evil/.mcp.json", server)
		if filepath.Base(name) != name || filepath.Clean(filepath.Join("/audit", name)) != filepath.Join("/audit", name) {
			t.Errorf("server %q gave log name %q", server, name)
		}
	}
}
