package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/BipinRimal314/chokepoint/internal/audit"
	"github.com/BipinRimal314/chokepoint/internal/policy"
)

// subcommands are dispatched on the first argument. Anything else is the
// proxy itself, so existing `chokepoint --policy ... -- server` invocations
// are unchanged.
var subcommands = map[string]func(args []string) error{
	"init":   cmdInit,
	"wrap":   cmdWrap,
	"unwrap": cmdUnwrap,
	"report": cmdReport,
}

const defaultPolicyFile = "chokepoint.yaml"

// cmdInit writes a starter policy for the current folder.
func cmdInit(args []string) error {
	mode := string(policy.ModeEnforce)
	out := defaultPolicyFile
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--monitor":
			mode = string(policy.ModeMonitor)
		case "--output", "-o":
			if i+1 >= len(args) {
				return errors.New("--output needs a path")
			}
			i++
			out = args[i]
		default:
			return fmt.Errorf("init: unknown option %q", args[i])
		}
	}

	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	// O_EXCL: never overwrite a policy someone has edited.
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; not overwriting it", out)
		}
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(starterPolicy(dir, mode)); err != nil {
		return err
	}
	fmt.Printf("wrote %s (mode: %s, workspace: %s)\n", out, mode, dir)
	fmt.Println("next: chokepoint wrap .mcp.json   # route your MCP servers through it")
	return nil
}

// cmdWrap routes every local MCP server in a client config through chokepoint.
//
// Claude Code (.mcp.json), Claude Desktop (claude_desktop_config.json) and
// Cursor (.cursor/mcp.json) share the shape {"mcpServers": {name: {command,
// args, env}}}. Each stdio server's command becomes chokepoint, with the
// original command after "--". Remote servers (a url, no command) are left
// alone: chokepoint proxies stdio.
func cmdWrap(args []string) error {
	config, policyPath := ".mcp.json", defaultPolicyFile
	var positional []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			if i+1 >= len(args) {
				return errors.New("--policy needs a path")
			}
			i++
			policyPath = args[i]
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("wrap: unknown option %q", args[i])
			}
			positional = append(positional, args[i])
		}
	}
	if len(positional) > 1 {
		return errors.New("wrap takes one config file")
	}
	if len(positional) == 1 {
		config = positional[0]
	}

	policyAbs, err := filepath.Abs(policyPath)
	if err != nil {
		return err
	}
	// Load it now: wrapping servers behind a policy that does not compile
	// would make every one of them fail to start.
	if _, err := policy.Load(policyAbs); err != nil {
		return fmt.Errorf("%w\n(create one with: chokepoint init)", err)
	}
	self, err := executable()
	if err != nil {
		return err
	}
	logDir, err := auditDir()
	if err != nil {
		return err
	}
	configAbs, err := filepath.Abs(config)
	if err != nil {
		return err
	}

	return rewriteServers(configAbs, func(name string, srv map[string]any) (string, bool) {
		command, _ := srv["command"].(string)
		if command == "" {
			return "skipped (remote server; chokepoint wraps local ones)", false
		}
		if isChokepoint(command) {
			return "already wrapped", false
		}
		orig := toStrings(srv["args"])
		logFile := filepath.Join(logDir, logName(configAbs, name))
		srv["command"] = self
		srv["args"] = append([]any{"--policy", policyAbs, "--audit-log", logFile, "--"},
			toAny(append([]string{command}, orig...))...)
		return "wrapped; audit log " + logFile, true
	})
}

// cmdUnwrap restores every server wrap rewrote.
func cmdUnwrap(args []string) error {
	config := ".mcp.json"
	if len(args) > 1 {
		return errors.New("unwrap takes one config file")
	}
	if len(args) == 1 {
		config = args[0]
	}
	configAbs, err := filepath.Abs(config)
	if err != nil {
		return err
	}
	return rewriteServers(configAbs, func(_ string, srv map[string]any) (string, bool) {
		command, _ := srv["command"].(string)
		if !isChokepoint(command) {
			return "not wrapped", false
		}
		a := toStrings(srv["args"])
		for i, v := range a {
			if v == "--" && i+1 < len(a) {
				srv["command"] = a[i+1]
				srv["args"] = toAny(a[i+2:])
				if len(a[i+2:]) == 0 {
					delete(srv, "args")
				}
				return "unwrapped", true
			}
		}
		return "wrapped by hand without --; left alone", false
	})
}

// rewriteServers applies edit to each server in a config and writes the
// result back only if something changed, keeping the previous version as
// <config>.chokepoint-backup.
func rewriteServers(path string, edit func(name string, srv map[string]any) (string, bool)) error {
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(original, &doc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var servers map[string]map[string]any
	if raw, ok := doc["mcpServers"]; ok {
		if err := json.Unmarshal(raw, &servers); err != nil {
			return fmt.Errorf("%s: mcpServers: %w", path, err)
		}
	}
	if len(servers) == 0 {
		return fmt.Errorf("%s has no mcpServers", path)
	}

	names := make([]string, 0, len(servers))
	for n := range servers {
		names = append(names, n)
	}
	sort.Strings(names)
	changed := false
	for _, n := range names {
		note, did := edit(n, servers[n])
		changed = changed || did
		fmt.Printf("  %-20s %s\n", n, note)
	}
	if !changed {
		fmt.Println("nothing to change")
		return nil
	}

	if doc["mcpServers"], err = json.Marshal(servers); err != nil {
		return err
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".chokepoint-backup", original, info.Mode().Perm()); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	// Written beside the original and renamed over it, so a crash leaves
	// either the old config or the new one, never half of each.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".chokepoint-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(out, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	fmt.Printf("updated %s (previous version in %s.chokepoint-backup)\n", path, filepath.Base(path))
	fmt.Println("restart your agent so it picks up the change")
	return nil
}

// auditDir is where wrapped servers write their audit logs. Outside the
// project on purpose: the logs hold file paths and queries, and a project
// folder is one `git add .` away from publishing them.
func auditDir() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	switch {
	case base != "":
	case runtime.GOOS == "windows":
		// %LocalAppData%, which is per user and not roamed.
		dir, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		base = dir
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	dir := filepath.Join(base, "chokepoint")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// logName gives each (config, server) pair its own log, so two projects that
// both call a server "filesystem" never write into one file.
func logName(config, server string) string {
	sum := sha256.Sum256([]byte(config))
	project := filepath.Base(filepath.Dir(config))
	return fmt.Sprintf("%s-%s-%s.jsonl",
		unsafeName.ReplaceAllString(project, "_"), hex.EncodeToString(sum[:4]),
		unsafeName.ReplaceAllString(server, "_"))
}

func executable() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

// isChokepoint recognises a command wrap wrote: this binary, or any binary
// named chokepoint, as a config moved between machines may point at another.
func isChokepoint(command string) bool {
	if filepath.Base(command) == "chokepoint" {
		return true
	}
	self, err := executable()
	return err == nil && command == self
}

func toStrings(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// cmdReport reads audit logs and prints what the agent did and every breach.
func cmdReport(args []string) error {
	var files []string
	var since time.Duration
	all := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--all":
			all = true
		case "--since":
			if i+1 >= len(args) {
				return errors.New("--since needs a duration, e.g. 24h")
			}
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return err
			}
			since = d
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("report: unknown option %q", args[i])
			}
			files = append(files, args[i])
		}
	}
	if len(files) == 0 {
		dir, err := auditDir()
		if err != nil {
			return err
		}
		files, _ = filepath.Glob(filepath.Join(dir, "*.jsonl"))
		if len(files) == 0 {
			return fmt.Errorf("no audit logs in %s yet; wrap a config and use your agent first", dir)
		}
	}

	type sourced struct {
		audit.Entry
		source string
	}
	var entries []sourced
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return err
		}
		got, err := audit.Read(fh, func(line int, err error) {
			fmt.Fprintf(os.Stderr, "%s:%d: skipped unreadable record: %v\n", f, line, err)
		})
		fh.Close()
		if err != nil {
			return err
		}
		for _, e := range got {
			entries = append(entries, sourced{e, sourceName(f)})
		}
	}
	if since > 0 {
		cutoff := time.Now().Add(-since)
		kept := entries[:0]
		for _, e := range entries {
			if e.At.After(cutoff) {
				kept = append(kept, e)
			}
		}
		entries = kept
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].At.Before(entries[j].At) })

	var b bytes.Buffer
	if len(entries) == 0 {
		fmt.Fprintln(&b, "no tool calls recorded in that period")
		_, err := io.Copy(os.Stdout, &b)
		return err
	}

	sessions := map[string]bool{}
	byTool := map[string]int{}
	blocked, allowed := 0, 0
	byRule := map[string]int{}
	var changes int
	for _, e := range entries {
		sessions[e.Session] = true
		byTool[e.Tool]++
		if e.Breach() {
			byRule[e.Rule]++
			if e.Enforced {
				blocked++
			} else {
				allowed++
			}
		}
		for _, r := range e.Audited {
			if r == "watch-changes" {
				changes++
			}
		}
	}

	const stamp = "2006-01-02 15:04:05"
	fmt.Fprintf(&b, "chokepoint report: %d tool calls in %d sessions, %s to %s\n\n",
		len(entries), len(sessions), entries[0].At.Format(stamp), entries[len(entries)-1].At.Format(stamp))
	fmt.Fprintf(&b, "  breaches blocked:              %d\n", blocked)
	fmt.Fprintf(&b, "  breaches ALLOWED (monitor):    %d\n", allowed)
	fmt.Fprintf(&b, "  changes made (writes, edits):  %d\n\n", changes)

	if blocked+allowed > 0 {
		fmt.Fprintln(&b, "breaches by rule:")
		for _, r := range sortedKeys(byRule) {
			fmt.Fprintf(&b, "  %-28s %d\n", r, byRule[r])
		}
		fmt.Fprintln(&b, "\nevery breach:")
		for _, e := range entries {
			if !e.Breach() {
				continue
			}
			what := "BLOCKED"
			if !e.Enforced {
				what = "ALLOWED"
			}
			fmt.Fprintf(&b, "  %s  %-7s  %-14s %-22s %-22s %s\n",
				e.At.Format(stamp), what, e.source, e.Tool, e.Rule, strings.Join(e.Targets, ", "))
		}
		fmt.Fprintln(&b)
	}

	fmt.Fprintln(&b, "calls by tool:")
	for _, t := range sortedKeys(byTool) {
		fmt.Fprintf(&b, "  %-28s %d\n", t, byTool[t])
	}

	if all {
		fmt.Fprintln(&b, "\nevery call:")
		for _, e := range entries {
			fmt.Fprintf(&b, "  %s  %-5s  %-14s %-22s %s\n",
				e.At.Format(stamp), e.Effect, e.source, e.Tool, strings.Join(e.Targets, ", "))
		}
	}
	_, err := io.Copy(os.Stdout, &b)
	return err
}

// sourceName turns a log file name back into the server it came from.
func sourceName(file string) string {
	base := strings.TrimSuffix(filepath.Base(file), ".jsonl")
	if parts := strings.SplitN(base, "-", 3); len(parts) == 3 && len(parts[1]) == 8 {
		return parts[2]
	}
	return base
}

// sortedKeys orders by count descending, then name.
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}
