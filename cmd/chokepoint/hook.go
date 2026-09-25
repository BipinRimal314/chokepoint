package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BipinRimal314/chokepoint/internal/audit"
	"github.com/BipinRimal314/chokepoint/internal/detect"
	"github.com/BipinRimal314/chokepoint/internal/gateway"
	"github.com/BipinRimal314/chokepoint/internal/policy"
)

// The Claude Code hook: the same rules, audit log and report as the proxy,
// checked inside the agent's harness instead of in front of an MCP server.
//
// The two positions see different things. The hook sees every tool the
// harness runs, including its built-in Read, Bash and WebFetch, which never
// pass through MCP. The proxy sees any MCP client, sees a server's replies
// before the agent does, and can run where the agent cannot reach it. They
// can be used together; see `hook install`.

// hookEvent is the part of Claude Code's PreToolUse input the hook reads.
type hookEvent struct {
	SessionID     string         `json:"session_id"`
	Cwd           string         `json:"cwd"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
}

type hookConfig struct {
	policyPath string
	auditLog   string
	mode       string
	skipMCP    bool
}

// cmdHook dispatches `chokepoint hook`, `hook install` and `hook uninstall`.
func cmdHook(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "install":
			return cmdHookInstall(args[1:])
		case "uninstall":
			return cmdHookUninstall(args[1:])
		}
	}
	cfg := hookConfig{policyPath: defaultPolicyFile}
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "--policy":
			cfg.policyPath = next()
		case "--audit-log":
			cfg.auditLog = next()
		case "--mode":
			cfg.mode = next()
		case "--skip-mcp":
			cfg.skipMCP = true
		default:
			return hookFail(os.Stdout, fmt.Errorf("unknown option %q", args[i]))
		}
	}
	os.Exit(runHook(os.Stdin, os.Stdout, os.Stderr, cfg))
	return nil
}

// runHook evaluates one PreToolUse event and returns the exit code.
//
// It never fails open. Claude Code lets a call through when a hook exits
// with anything but 0 or 2 or prints invalid JSON, so every error here,
// including a panic, becomes an explicit deny with exit 2.
func runHook(stdin io.Reader, stdout, stderr io.Writer, cfg hookConfig) (code int) {
	defer func() {
		if r := recover(); r != nil {
			code = denyHook(stdout, stderr, fmt.Sprintf("chokepoint hook failed (%v); refusing rather than letting the call through unchecked", r))
		}
	}()

	var ev hookEvent
	if err := json.NewDecoder(stdin).Decode(&ev); err != nil {
		return denyHook(stdout, stderr, "chokepoint hook could not read its input ("+err.Error()+"); refusing")
	}
	if ev.HookEventName != "" && ev.HookEventName != "PreToolUse" {
		// Only PreToolUse can refuse a call. Anything else is not ours.
		return 0
	}
	if cfg.skipMCP && strings.HasPrefix(ev.ToolName, "mcp__") {
		// The MCP servers are wrapped by the proxy, which checks and records
		// these calls itself. Checking here too would log each one twice.
		return 0
	}

	pol, err := policy.Load(cfg.policyPath)
	if err != nil {
		return denyHook(stdout, stderr, "chokepoint policy did not load ("+err.Error()+"); refusing every call until it is fixed")
	}
	if cfg.mode != "" {
		pol.Mode = policy.Mode(cfg.mode)
		if err := pol.Mode.Valid(); err != nil {
			return denyHook(stdout, stderr, err.Error())
		}
	}
	scope, err := detect.NewScope(pol.Workspace)
	if err != nil {
		return denyHook(stdout, stderr, "chokepoint workspace is invalid ("+err.Error()+"); refusing")
	}

	targets, locations := hookTargets(ev)
	var outOfScope []string
	if scope.Declared() {
		for _, l := range locations {
			if r := detect.ParseResource(l); !r.Empty() && !scope.Contains(r) {
				outOfScope = append(outOfScope, l)
			}
		}
	}

	decision := pol.Evaluate(policy.Request{
		Tool:          ev.ToolName,
		Method:        "hook/PreToolUse",
		Args:          ev.ToolInput,
		Targets:       targets,
		ScopeDeclared: scope.Declared(),
		OutOfScope:    outOfScope,
		ArgsValid:     true,
	})
	deny := decision.Effect == policy.EffectDeny
	unenforced := deny && pol.Mode == policy.ModeMonitor && !decision.AlwaysEnforce

	if cfg.auditLog != "" {
		if err := recordHookDecision(cfg.auditLog, ev, decision, targets, len(outOfScope), unenforced); err != nil {
			// A decision that cannot be recorded is still made, but the
			// operator has to hear about it: the report will be missing it.
			fmt.Fprintf(stderr, "chokepoint: audit log: %v\n", err)
		}
	}

	if !deny || unenforced {
		// Exit 0 with no output is "no decision": Claude Code's own
		// permission rules and prompts still apply. Printing "allow" would
		// approve calls the user would otherwise be asked about.
		return 0
	}
	reason := "blocked by chokepoint policy"
	if decision.Message != "" {
		reason = "blocked by chokepoint: " + decision.Message
	}
	return denyHook(stdout, stderr, fmt.Sprintf("%s (rule %s)", reason, ruleName(decision.Rule)))
}

func ruleName(rule string) string {
	if rule == "" {
		return "default_effect"
	}
	return rule
}

// denyHook writes Claude Code's deny decision and returns exit code 2, which
// blocks the call even if the JSON were lost.
func denyHook(stdout, stderr io.Writer, reason string) int {
	out, _ := json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": reason,
		},
	})
	fmt.Fprintln(stdout, string(out))
	fmt.Fprintln(stderr, reason)
	return 2
}

// hookFail is for errors before an event is read, such as a bad flag in the
// installed command line. It still denies, for the same reason as runHook.
func hookFail(stdout io.Writer, err error) error {
	os.Exit(denyHook(stdout, os.Stderr, "chokepoint hook misconfigured ("+err.Error()+"); refusing"))
	return nil
}

func recordHookDecision(path string, ev hookEvent, d policy.Decision, targets []string, outOfScope int, unenforced bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	var writeErr error
	w := audit.New(f, audit.Options{
		TraceID: sessionTraceID(ev.SessionID),
		OnError: func(err error) { writeErr = err },
	})
	w.ToolCallDecided(gateway.DecisionEvent{
		Tool:             ev.ToolName,
		Method:           "hook/PreToolUse",
		Targets:          targets,
		Effect:           d.Effect,
		Rule:             d.Rule,
		Audited:          d.Audited,
		Unenforced:       unenforced,
		ScoreUnavailable: true,
		ScopeDeclared:    true,
		OutOfScope:       outOfScope,
	})
	return writeErr
}

// sessionTraceID maps a Claude session to one audit trace, so the report
// groups a session's calls although each is a separate process.
func sessionTraceID(session string) string {
	if session == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("claude-code:" + session))
	return hex.EncodeToString(sum[:16])
}

// hookTargets returns what a call touches, and the subset that are places,
// with relative paths resolved against the agent's working folder.
//
// The harness reports its working folder, which the proxy never learns, so
// here "." and "src/main.go" can be checked against the workspace instead of
// being refused for want of a base.
func hookTargets(ev hookEvent) (targets, locations []string) {
	cwd := ev.Cwd
	seen := map[string]bool{}
	add := func(t string, place bool) {
		if place {
			t = resolvePath(t, cwd)
		}
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		targets = append(targets, t)
		if place {
			locations = append(locations, t)
		}
	}

	places := map[string]bool{}
	for _, l := range policy.ExtractLocations(ev.ToolInput) {
		places[l] = true
	}
	for _, t := range policy.ExtractTargets(ev.ToolInput) {
		add(t, places[t])
	}

	in := ev.ToolInput
	str := func(k string) string { s, _ := in[k].(string); return s }
	switch ev.ToolName {
	case "Glob", "Grep":
		// Both search a folder, the working folder when none is given.
		root := str("path")
		if root == "" {
			root = "."
		}
		add(root, true)
		if ev.ToolName == "Glob" && str("pattern") != "" {
			base := root
			if strings.HasPrefix(str("pattern"), "/") || strings.HasPrefix(str("pattern"), "~") {
				base = ""
			}
			add(filepath.Join(base, str("pattern")), true)
		}
	case "Bash":
		for _, t := range shellPaths(str("command")) {
			add(t, !strings.Contains(t, "://") || strings.HasPrefix(t, "file://"))
			if strings.Contains(t, "://") && !strings.HasPrefix(t, "file://") {
				// A URL is a place too, but not one to resolve as a path.
				if !seen["url:"+t] {
					seen["url:"+t] = true
					locations = append(locations, t)
				}
			}
		}
	}
	return targets, locations
}

// resolvePath makes a path absolute against cwd and expands ~. URLs and
// anything else with a scheme are returned unchanged.
func resolvePath(p, cwd string) string {
	p = strings.TrimSpace(p)
	if p == "" || strings.Contains(p, "://") {
		return p
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	switch {
	case filepath.IsAbs(p):
	case strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`):
		// Rooted but not absolute: on Windows, "/etc/hosts" is the root of
		// the working folder's drive, not a path inside the working folder.
		p = filepath.VolumeName(cwd) + p
	case cwd != "":
		p = filepath.Join(cwd, p)
	}
	return filepath.Clean(p)
}

// shellPaths picks path- and URL-shaped words out of a shell command.
//
// This is a best effort, and the documentation says so: it sees
// `cat .env`, `curl https://x` and `echo x > .mcp.json`, but not a path the
// command builds at run time, and it ignores `cd`. A rule that must hold for
// shell commands should refuse the command outright.
func shellPaths(cmd string) []string {
	var out []string
	for _, word := range strings.FieldsFunc(cmd, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || strings.ContainsRune("|;&<>()`$\"'", r)
	}) {
		if strings.HasPrefix(word, "-") {
			// --output=/tmp/x carries its path after the "=".
			_, v, ok := strings.Cut(word, "=")
			if !ok {
				continue
			}
			word = v
		} else if k, v, ok := strings.Cut(word, "="); ok && !strings.ContainsAny(k, "/.") {
			// VAR=value and key=value arguments.
			word = v
		}
		// curl and httpie read a request body from @file.
		word = strings.TrimPrefix(word, "@")
		if word == "" {
			continue
		}
		if isShellDevice(word) {
			// 2>/dev/null and friends are not places the agent reaches.
			continue
		}
		// A word with a dot may be a file name: `sed -i ... chokepoint.yaml`
		// has no slash. Resolved against the working folder, words that are
		// not files (a version, a domain) land inside it and change nothing.
		if strings.ContainsAny(word, `/.\`) || strings.HasPrefix(word, "~") || hasDrive(word) {
			out = append(out, word)
		}
	}
	return out
}

// hasDrive reports a Windows drive prefix such as C:.
func hasDrive(p string) bool {
	return len(p) >= 2 && p[1] == ':' && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z'))
}

// isShellDevice reports the standard device files shell commands redirect to.
// Found by the real-agent test: `ls ... 2>/dev/null` was refused as leaving
// the workspace.
func isShellDevice(p string) bool {
	switch p {
	case "/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/tty",
		"/dev/zero", "/dev/random", "/dev/urandom":
		return true
	}
	return strings.HasPrefix(p, "/dev/fd/")
}

// cmdHookInstall adds the hook to a Claude Code settings file.
//
// It goes in .claude/settings.local.json by default: the command holds
// absolute paths to this machine's binary and policy, which do not belong in
// the shared, committed settings.json.
func cmdHookInstall(args []string) error {
	settings := filepath.Join(".claude", "settings.local.json")
	policyPath := defaultPolicyFile
	skip := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--settings":
			if i+1 >= len(args) {
				return errors.New("--settings needs a path")
			}
			i++
			settings = args[i]
		case "--policy":
			if i+1 >= len(args) {
				return errors.New("--policy needs a path")
			}
			i++
			policyPath = args[i]
		case "--skip-mcp":
			skip = "on"
		case "--all-tools":
			skip = "off"
		default:
			return fmt.Errorf("hook install: unknown option %q", args[i])
		}
	}
	policyAbs, err := filepath.Abs(policyPath)
	if err != nil {
		return err
	}
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
	settingsAbs, err := filepath.Abs(settings)
	if err != nil {
		return err
	}
	project := filepath.Dir(filepath.Dir(settingsAbs))

	// Both positions at once is supported. MCP calls are then left to the
	// proxy, so each call is checked and recorded once.
	skipMCP := skip == "on"
	if skip == "" && mcpConfigWrapped(filepath.Join(project, ".mcp.json")) {
		skipMCP = true
		fmt.Println("  .mcp.json is wrapped: MCP calls stay with the proxy, the hook checks the rest (--all-tools to check them here too)")
	}

	command := fmt.Sprintf("%s hook --policy %s --audit-log %s",
		shellQuote(self), shellQuote(policyAbs),
		shellQuote(filepath.Join(logDir, logName(filepath.Join(project, ".claude"), "claude-code"))))
	if skipMCP {
		command += " --skip-mcp"
	}

	return editJSONFile(settingsAbs, true, func(doc map[string]any) (string, bool) {
		pre := preToolUse(doc)
		kept, had := withoutChokepointHooks(pre)
		entry := map[string]any{
			"matcher": "*",
			"hooks":   []any{map[string]any{"type": "command", "command": command, "timeout": 30}},
		}
		if had && hookCommandIn(pre) == command {
			return "already installed", false
		}
		setPreToolUse(doc, append(kept, entry))
		if had {
			return "hook updated", true
		}
		return "hook installed: every Claude Code tool call is checked against " + policyAbs, true
	})
}

// cmdHookUninstall removes the hook and nothing else.
func cmdHookUninstall(args []string) error {
	settings := filepath.Join(".claude", "settings.local.json")
	if len(args) == 2 && args[0] == "--settings" {
		settings = args[1]
	} else if len(args) != 0 {
		return errors.New("usage: chokepoint hook uninstall [--settings PATH]")
	}
	settingsAbs, err := filepath.Abs(settings)
	if err != nil {
		return err
	}
	return editJSONFile(settingsAbs, false, func(doc map[string]any) (string, bool) {
		kept, had := withoutChokepointHooks(preToolUse(doc))
		if !had {
			return "no chokepoint hook installed", false
		}
		setPreToolUse(doc, kept)
		return "hook removed", true
	})
}

func preToolUse(doc map[string]any) []any {
	hooks, _ := doc["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	return pre
}

func setPreToolUse(doc map[string]any, pre []any) {
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
		doc["hooks"] = hooks
	}
	if len(pre) == 0 {
		delete(hooks, "PreToolUse")
		if len(hooks) == 0 {
			delete(doc, "hooks")
		}
		return
	}
	hooks["PreToolUse"] = pre
}

// withoutChokepointHooks drops matcher groups whose hooks run `chokepoint
// hook`, leaving every other hook the user has.
func withoutChokepointHooks(pre []any) (kept []any, had bool) {
	for _, g := range pre {
		if isChokepointHookGroup(g) {
			had = true
			continue
		}
		kept = append(kept, g)
	}
	return kept, had
}

func isChokepointHookGroup(g any) bool {
	return hookCommandIn([]any{g}) != ""
}

func hookCommandIn(pre []any) string {
	for _, g := range pre {
		group, _ := g.(map[string]any)
		hs, _ := group["hooks"].([]any)
		for _, h := range hs {
			m, _ := h.(map[string]any)
			c, _ := m["command"].(string)
			if strings.Contains(c, "chokepoint") && strings.Contains(c, " hook ") {
				return c
			}
		}
	}
	return ""
}

func mcpConfigWrapped(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var doc struct {
		MCPServers map[string]struct {
			Command string `json:"command"`
		} `json:"mcpServers"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	for _, s := range doc.MCPServers {
		if isChokepoint(s.Command) {
			return true
		}
	}
	return false
}

// shellQuote quotes a word for the POSIX shell Claude Code runs hooks with.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
