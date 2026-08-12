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
	Rules      []Rule `yaml:"rules"`

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

// Decision is the outcome of evaluating a policy.
type Decision struct {
	Effect Effect
	// Rule is the name of the rule that matched, empty when the default applied.
	Rule    string
	Message string
	// Audited lists audit rules that matched along the way.
	Audited []string
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
				Effect:  rule.Effect,
				Rule:    rule.Name,
				Message: rule.Message,
				Audited: audited,
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
	const maxDepth = 4
	seen := map[string]struct{}{}
	collect(args, 0, maxDepth, seen)

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
}

func collect(v any, depth, maxDepth int, out map[string]struct{}) {
	if depth > maxDepth {
		// Bounded so a deeply nested or self-referential argument object
		// cannot turn target extraction into an unbounded walk.
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok && targetKeys[strings.ToLower(k)] && s != "" {
				out[s] = struct{}{}
				continue
			}
			collect(val, depth+1, maxDepth, out)
		}
	case []any:
		for _, item := range t {
			collect(item, depth+1, maxDepth, out)
		}
	}
}
