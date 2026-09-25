// Package policy evaluates rules against MCP tool calls using CEL.
//
// CEL rather than a bespoke matcher because the interesting rules are
// relational — "this tool, but only outside that directory", "this tool, but
// not once the session has already touched thirty distinct targets" — and a
// config format that grows predicates one at a time becomes a bad programming
// language. CEL is also non-Turing-complete and evaluates in bounded time,
// which matters when every rule runs in the request path of an agent.
package policy

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"gopkg.in/yaml.v3"
)

// Effect is what a matching rule does.
type Effect string

const (
	// EffectAllow permits the call and stops evaluation.
	EffectAllow Effect = "allow"
	// EffectDeny refuses the call, answering the agent with an error.
	EffectDeny Effect = "deny"
	// EffectAudit records the call and continues evaluating.
	//
	// Audit exists so a rule can be deployed and observed before it is armed.
	// Turning on a deny rule that has never been measured is how a proxy
	// becomes the thing that broke production.
	EffectAudit Effect = "audit"
)

// Rule is one policy entry.
type Rule struct {
	Name string `yaml:"name"`
	// Match is a CEL expression over the request context. Empty matches
	// everything, which is how a catch-all default rule is written.
	Match  string `yaml:"match"`
	Effect Effect `yaml:"effect"`
	// Message is returned to the agent on deny. A good one tells the agent
	// what to do instead, because the agent is the one that has to recover.
	Message string `yaml:"message"`
	// AlwaysEnforce keeps a deny rule blocking in monitor mode. Monitor mode
	// otherwise blocks nothing, which is what someone letting an agent run
	// unchecked wants; this is for the few things they still never want to
	// happen, such as reading credentials.
	AlwaysEnforce bool `yaml:"always_enforce"`

	program cel.Program
}

// Policy is an ordered rule set.
//
// Rules are evaluated in order and the first match wins. Order-dependence is
// deliberate: it makes "deny this one thing, allow the rest" expressible
// without negation, and it makes the effective policy readable top to bottom.
type Policy struct {
	// DefaultEffect applies when no rule matches. Defaults to allow, so that
	// installing chokepoint without writing a policy does not break a working
	// agent — the tool has to be safe to introduce before it can be adopted.
	DefaultEffect Effect `yaml:"default_effect"`
	// Workspace declares where the agent is supposed to reach: absolute paths
	// or URI prefixes. Calls landing outside it are reported to rules through
	// out_of_scope and session_out_of_scope.
	//
	// Held here as data and interpreted elsewhere. This package compiles
	// expressions and knows nothing about paths; normalising a target and
	// testing containment is detect's job, because doing it against raw strings
	// is defeated by a single "../". Callers pass this to detect.NewScope.
	//
	// Empty means undeclared, which is not the same as an empty working set:
	// scope_declared goes false and scope rules stay inert rather than denying
	// everything.
	Workspace []string `yaml:"workspace"`
	// RateWindow is how far back calls_in_window and targets_in_window look,
	// as a Go duration string ("30s", "5m"). Empty leaves the choice to the
	// caller, which is where the default lives — this package deliberately does
	// not import detect.
	//
	// The window is configuration; the limit is not. There is no max_calls
	// setting here on purpose — a rule saying calls_in_window > 200 keeps the
	// number where an operator can see it next to every other rule, and lets it
	// be combined with the tool, the scope and the score rather than standing
	// alone as a bucket that only knows how to count.
	RateWindow string `yaml:"rate_window"`
	// Mode is enforce, the default, or monitor. In monitor mode a call the
	// policy denies is still forwarded, and recorded as a violation that was
	// not enforced: for agents that must keep running unattended, where a
	// refused call would stop the work, but every breach still has to be
	// reported.
	Mode  Mode   `yaml:"mode"`
	Rules []Rule `yaml:"rules"`

	// rateWindow is RateWindow parsed, so a malformed duration is a load-time
	// error rather than a window that silently reverts to the default.
	rateWindow time.Duration
}

// RateWindowDuration is the configured window, or zero when none was set.
func (p *Policy) RateWindowDuration() time.Duration {
	if p == nil {
		return 0
	}
	return p.rateWindow
}

// Request is the evaluation context exposed to CEL expressions.
type Request struct {
	// Tool is the tool name, empty for non-tool requests.
	Tool string
	// Method is the JSON-RPC method, e.g. "tools/call".
	Method string
	// Args is the decoded arguments object.
	Args map[string]any
	// Targets are the target-like strings extracted from Args.
	Targets []string
	// SessionCalls is how many calls this session has made.
	SessionCalls int
	// SessionTargets is how many distinct targets this session has touched.
	SessionTargets int
	// CallsInWindow is how many calls fall inside the configured rate window,
	// and TargetsInWindow how many distinct targets they named. Both count the
	// call being evaluated, so a rule can refuse the request that completes a
	// burst rather than the one after it.
	CallsInWindow   int
	TargetsInWindow int
	// DecompositionScore is the detector's current assessment, in [0,1].
	DecompositionScore float64
	// ScopeDeclared is whether a workspace was declared at all. Rules must
	// guard on it: without it, a policy written for a scoped deployment denies
	// every call on an unscoped one.
	ScopeDeclared bool
	// OutOfScope holds this call's targets that fall outside the declared
	// workspace, as observed. Empty when none do or when none was declared.
	OutOfScope []string
	// SessionOutOfScope is how many distinct out-of-scope resources the session
	// has touched. Distinct rather than counted, so one path retried thirty
	// times is not thirty places.
	SessionOutOfScope int
	// ToolDefinitionChanged is true when the tool being called has advertised a
	// different definition since the session's first tools/list. This is the
	// rug pull: approved benign, mutated afterwards.
	ToolDefinitionChanged bool
	// SessionToolsChanged is how many distinct tools have been modified or
	// added since the first listing.
	SessionToolsChanged int
	// SchemaKnown is whether the tool advertised an inputSchema that compiled.
	// Rules must guard on it for the same reason they guard on scope_declared:
	// a tool with no schema produces no violations, and so does a call that is
	// perfectly valid, and a rule that cannot tell them apart denies every use
	// of an unschema'd tool.
	SchemaKnown bool
	// ArgsValid is whether the arguments satisfied that schema. True when
	// SchemaKnown is false, so an unguarded rule fails open rather than closed.
	ArgsValid bool
	// SchemaViolations describes what failed, bounded and sorted. Empty when
	// ArgsValid.
	SchemaViolations []string
}

// HasAlwaysEnforce reports whether any rule keeps blocking in monitor mode.
//
// When one does, a request chokepoint cannot read has to be refused in
// monitor mode too: it cannot be shown not to break that rule. Forwarding it
// let an ambiguous request read an SSH key past an always_enforce rule that
// blocked the same read written plainly.
func (p *Policy) HasAlwaysEnforce() bool {
	if p == nil {
		return false
	}
	for _, r := range p.Rules {
		if r.AlwaysEnforce {
			return true
		}
	}
	return false
}

// Mode says what a deny does.
type Mode string

const (
	// ModeEnforce refuses a denied call.
	ModeEnforce Mode = "enforce"
	// ModeMonitor forwards a denied call and records it as a violation.
	ModeMonitor Mode = "monitor"
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() error {
	switch m {
	case ModeEnforce, ModeMonitor:
		return nil
	}
	return fmt.Errorf("mode: must be %q or %q, got %q", ModeEnforce, ModeMonitor, m)
}

// Decision is the outcome of evaluating a policy.
type Decision struct {
	Effect Effect
	// Rule is the name of the rule that matched, empty when the default applied.
	Rule    string
	Message string
	// Audited lists audit rules that matched along the way.
	Audited []string
	// AlwaysEnforce is the matched rule's always_enforce: the deny stands
	// in monitor mode.
	AlwaysEnforce bool
}

// declarations are the variables every rule may reference.
//
// Declared explicitly, and with types, so that a typo in a rule is a load-time
// compile error rather than a silent false at midnight. A policy engine that
// fails open on a misspelled field is worse than no policy engine, because it
// reports protection it is not providing.
func declarations() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("tool", cel.StringType),
		cel.Variable("method", cel.StringType),
		cel.Variable("args", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("targets", cel.ListType(cel.StringType)),
		cel.Variable("session_calls", cel.IntType),
		cel.Variable("session_targets", cel.IntType),
		cel.Variable("calls_in_window", cel.IntType),
		cel.Variable("targets_in_window", cel.IntType),
		cel.Variable("decomposition_score", cel.DoubleType),
		cel.Variable("tool_definition_changed", cel.BoolType),
		cel.Variable("schema_known", cel.BoolType),
		cel.Variable("args_valid", cel.BoolType),
		cel.Variable("schema_violations", cel.ListType(cel.StringType)),
		cel.Variable("session_tools_changed", cel.IntType),
		cel.Variable("scope_declared", cel.BoolType),
		cel.Variable("out_of_scope", cel.ListType(cel.StringType)),
		cel.Variable("session_out_of_scope", cel.IntType),
	}
}

// Compile prepares every rule for evaluation.
//
// All rules are compiled up front rather than lazily on first match, so a
// broken expression is reported when the policy is loaded instead of the first
// time an agent happens to trigger it.
func (p *Policy) Compile() error {
	env, err := cel.NewEnv(declarations()...)
	if err != nil {
		return fmt.Errorf("build CEL environment: %w", err)
	}

	if p.DefaultEffect == "" {
		p.DefaultEffect = EffectAllow
	}
	if err := validEffect(p.DefaultEffect); err != nil {
		return fmt.Errorf("default_effect: %w", err)
	}

	if p.Mode == "" {
		p.Mode = ModeEnforce
	}
	if err := p.Mode.Valid(); err != nil {
		return err
	}

	if s := strings.TrimSpace(p.RateWindow); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("rate_window: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("rate_window: must be positive, got %s", s)
		}
		p.rateWindow = d
	}

	for i := range p.Rules {
		rule := &p.Rules[i]
		if rule.AlwaysEnforce && rule.Effect != EffectDeny {
			// Only a deny can be enforced; accepting it elsewhere would
			// promise protection the rule does not give.
			return fmt.Errorf("rule %q: always_enforce applies only to effect: deny", rule.Name)
		}
		if rule.Name == "" {
			return fmt.Errorf("rule %d: name is required", i)
		}
		if err := validEffect(rule.Effect); err != nil {
			return fmt.Errorf("rule %q: %w", rule.Name, err)
		}
		// An empty match is the catch-all form and needs no program.
		if strings.TrimSpace(rule.Match) == "" {
			continue
		}

		ast, issues := env.Compile(rule.Match)
		if issues != nil && issues.Err() != nil {
			return fmt.Errorf("rule %q: %w", rule.Name, issues.Err())
		}
		// A rule that returns a non-boolean is a mistake that would otherwise
		// surface as "never matches".
		if ast.OutputType() != cel.BoolType {
			return fmt.Errorf("rule %q: match must evaluate to bool, got %s",
				rule.Name, ast.OutputType())
		}

		prog, err := env.Program(ast)
		if err != nil {
			return fmt.Errorf("rule %q: build program: %w", rule.Name, err)
		}
		rule.program = prog
	}
	return nil
}

func validEffect(e Effect) error {
	switch e {
	case EffectAllow, EffectDeny, EffectAudit:
		return nil
	case "":
		return fmt.Errorf("effect is required (allow, deny, or audit)")
	default:
		return fmt.Errorf("unknown effect %q (want allow, deny, or audit)", e)
	}
}

// Evaluate returns the decision for req.
//
// Never returns an error. A rule that fails at runtime — a type mismatch on a
// dynamic field, say — is treated as not matching and recorded in the
// decision's Audited list. The alternative, aborting the session, would let a
// single bad expression take down every agent behind the proxy.
func (p *Policy) Evaluate(req Request) Decision {
	vars := map[string]any{
		"tool":                req.Tool,
		"method":              req.Method,
		"args":                req.Args,
		"targets":             req.Targets,
		"session_calls":       req.SessionCalls,
		"session_targets":     req.SessionTargets,
		"calls_in_window":     req.CallsInWindow,
		"targets_in_window":   req.TargetsInWindow,
		"decomposition_score": req.DecompositionScore,

		"tool_definition_changed": req.ToolDefinitionChanged,

		"schema_known":          req.SchemaKnown,
		"args_valid":            req.ArgsValid,
		"schema_violations":     req.SchemaViolations,
		"session_tools_changed": req.SessionToolsChanged,

		"scope_declared":       req.ScopeDeclared,
		"out_of_scope":         req.OutOfScope,
		"session_out_of_scope": req.SessionOutOfScope,
	}
	if vars["args"] == nil {
		vars["args"] = map[string]any{}
	}
	if req.Targets == nil {
		vars["targets"] = []string{}
	}
	if req.OutOfScope == nil {
		vars["out_of_scope"] = []string{}
	}
	if req.SchemaViolations == nil {
		vars["schema_violations"] = []string{}
	}

	var audited []string

	for i := range p.Rules {
		rule := &p.Rules[i]

		matched, err := rule.matches(vars)
		if err != nil {
			audited = append(audited, fmt.Sprintf("%s: evaluation error: %v", rule.Name, err))
			continue
		}
		if !matched {
			continue
		}

		switch rule.Effect {
		case EffectAudit:
			audited = append(audited, rule.Name)
			continue
		default:
			return Decision{
				Effect:        rule.Effect,
				Rule:          rule.Name,
				Message:       rule.Message,
				Audited:       audited,
				AlwaysEnforce: rule.AlwaysEnforce,
			}
		}
	}

	return Decision{Effect: p.DefaultEffect, Audited: audited}
}

// matches evaluates one rule's expression.
func (r *Rule) matches(vars map[string]any) (bool, error) {
	if r.program == nil {
		// Catch-all rule.
		return true, nil
	}
	out, _, err := r.program.Eval(vars)
	if err != nil {
		return false, err
	}
	return isTrue(out), nil
}

func isTrue(v ref.Val) bool {
	b, ok := v.(types.Bool)
	return ok && bool(b)
}

// Load reads and compiles a policy from a YAML file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return Parse(data)
}

// Parse reads and compiles a policy from YAML bytes.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	// KnownFields makes a typo'd key an error instead of a silently ignored
	// setting — the same failure class as a misspelled variable in a rule.
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.Compile(); err != nil {
		return nil, err
	}
	return &p, nil
}

// ExtractTargets pulls target-like strings out of a tool's arguments.
//
// Targets are what make a decomposed sweep visible: the same tool called with
// the same argument shape against thirty different paths is one tool and
// thirty targets. Keys are matched by name because MCP does not standardise
// argument schemas across servers, so the alternative is a per-server mapping
// nobody will maintain.
func ExtractTargets(args map[string]any) []string {
	return extract(args, func(string, string) bool { return true })
}

// ExtractLocations returns the targets that name a place, which are the only
// ones a declared workspace can be checked against.
//
// Not every target is a place. A SQL statement, a bucket name or an object key
// is something a call touches, and parsing one as a filesystem path puts it
// outside any workspace by construction: that denied every call to a database
// server, SELECT 1 included. So a value counts as a location when its key names
// one, or when the value is plainly an absolute path or a URI whatever key
// carries it. The second clause stops a path being moved out of scope by
// passing it under a key like "table".
func ExtractLocations(args map[string]any) []string {
	return extract(args, func(key, value string) bool {
		return locationKeys[key] || looksLikeLocation(value)
	})
}

// extract walks args and returns the sorted, distinct target values that keep
// accepts. keep is given the lowercased key and the value.
func extract(args map[string]any, keep func(key, value string) bool) []string {
	const maxDepth = 4
	seen := map[string]struct{}{}
	collect(args, 0, maxDepth, keep, seen)

	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	// Sorted so that a policy decision over the same call is identical run to
	// run, and so audit records can be compared.
	sort.Strings(out)
	return out
}

// targetKeys are argument names that conventionally carry a target.
var targetKeys = map[string]bool{
	"path": true, "file": true, "filename": true, "file_path": true,
	"uri": true, "url": true, "host": true, "hostname": true,
	"resource": true, "target": true, "directory": true, "dir": true,
	"query": true, "table": true, "key": true, "bucket": true,
	// Plurals carry batches. The reference filesystem server's
	// read_multiple_files takes {"paths": [...]}; without these, one batched
	// call reads any number of files with no target recorded at all.
	"paths": true, "files": true, "filenames": true, "file_paths": true,
	"uris": true, "urls": true, "hosts": true, "hostnames": true,
	"resources": true, "targets": true, "directories": true, "dirs": true,
}

// locationKeys are the target keys whose values name a place. The rest of
// targetKeys (query, table, key, bucket, host, target) routinely carry
// things that are not places; see ExtractLocations.
//
// host is left out deliberately: a bare hostname parses as a relative
// filesystem path, which no workspace can contain. A URL carries its host
// with a scheme and is checked.
var locationKeys = map[string]bool{
	"path": true, "file": true, "filename": true, "file_path": true,
	"uri": true, "url": true, "resource": true, "directory": true, "dir": true,
	"paths": true, "files": true, "filenames": true, "file_paths": true,
	"uris": true, "urls": true, "resources": true, "directories": true, "dirs": true,
}

// looksLikeLocation reports whether a value is unmistakably a place: an
// absolute POSIX or Windows path, a home-relative path, or a URI with a
// scheme. Relative values are not claimed, since "reports/q3.pdf" under "key"
// is an object key far more often than a file.
func looksLikeLocation(v string) bool {
	v = strings.TrimSpace(v)
	switch {
	case strings.HasPrefix(v, "/"), strings.HasPrefix(v, `\`), strings.HasPrefix(v, "~"):
		return true
	case len(v) >= 3 && v[1] == ':' && (v[2] == '/' || v[2] == '\\') && isASCIILetter(v[0]):
		return true
	}
	scheme, _, ok := strings.Cut(v, "://")
	return ok && len(scheme) > 1 && !strings.ContainsAny(scheme, " \t/")
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func collect(v any, depth, maxDepth int, keep func(key, value string) bool, out map[string]struct{}) {
	if depth > maxDepth {
		// Bounded so a deeply nested or self-referential argument object
		// cannot turn target extraction into an unbounded walk.
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			key := strings.ToLower(k)
			if targetKeys[key] {
				if s, ok := val.(string); ok {
					if s != "" && keep(key, s) {
						out[s] = struct{}{}
					}
					continue
				}
				if items, ok := val.([]any); ok {
					collectStrings(key, items, depth+1, maxDepth, keep, out)
					continue
				}
			}
			collect(val, depth+1, maxDepth, keep, out)
		}
	case []any:
		for _, item := range t {
			collect(item, depth+1, maxDepth, keep, out)
		}
	}
}

// collectStrings takes every non-empty string in a list held under a target
// key as a target, and walks anything else in it as ordinary arguments.
func collectStrings(key string, items []any, depth, maxDepth int, keep func(key, value string) bool, out map[string]struct{}) {
	if depth > maxDepth {
		return
	}
	for _, item := range items {
		if s, ok := item.(string); ok {
			if s != "" && keep(key, s) {
				out[s] = struct{}{}
			}
			continue
		}
		collect(item, depth+1, maxDepth, keep, out)
	}
}
