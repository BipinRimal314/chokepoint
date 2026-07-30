// Package gateway joins the proxy, the policy engine, and the detector.
//
// It is the only place that understands MCP's specific message shapes. The
// proxy knows JSON-RPC and nothing about tools; the policy engine evaluates
// expressions over a struct; the detector consumes abstract calls. This package
// translates between them, which keeps each of those testable on its own.
package gateway

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/BipinRimal314/chokepoint/internal/detect"
	"github.com/BipinRimal314/chokepoint/internal/jsonrpc"
	"github.com/BipinRimal314/chokepoint/internal/policy"
	"github.com/BipinRimal314/chokepoint/internal/proxy"
)

// MCP method names the gateway treats specially.
const (
	methodToolsCall     = "tools/call"
	methodResourcesRead = "resources/read"
	methodPromptsGet    = "prompts/get"
)

// DecisionEvent reports what the gateway decided about one tool call.
type DecisionEvent struct {
	// ID is the JSON-RPC request id, used to correlate a later
	// CompletionEvent. Empty for notifications, which never complete.
	ID     string
	Tool   string
	Method string
	// Targets are the extracted targets. Deliberately not suitable as a
	// metric label — they are unbounded and would blow up cardinality — but
	// useful on a trace span, where high-cardinality detail belongs.
	Targets []string

	Effect  policy.Effect
	Rule    string
	Audited []string

	Score float64
	// ScoreUnavailable is true when the session is too short to score. The
	// difference matters: a 0.0 score and "not yet scoreable" are the same
	// number and completely different facts.
	ScoreUnavailable bool
	SessionCalls     int
	SessionTargets   int

	// ScopeDeclared is whether a working set was declared. Without it the two
	// fields below are zero and mean nothing, exactly as a 0.0 score does not
	// mean "safe" when the session is too short to score.
	ScopeDeclared bool
	// OutOfScope is how many of this call's targets fell outside the working
	// set. A count, not the targets themselves — those are attacker-influenced
	// and unbounded, so they go on the span with Targets, never on a label.
	OutOfScope int
	// SessionOutOfScope is distinct out-of-scope resources touched so far.
	SessionOutOfScope int
}

// CompletionEvent reports the upstream's answer to a forwarded call.
type CompletionEvent struct {
	ID      string
	Tool    string
	Errored bool
	Latency time.Duration
}

// Observer receives decisions and completions for logging, metrics, and traces.
//
// An interface rather than a direct dependency on the telemetry package, so the
// gateway is testable without standing up an exporter — and so that a
// deployment wanting neither pays for neither.
//
// Implementations must be safe for concurrent use and must not block: they are
// called from the request path, so a slow exporter would add latency to every
// tool call the agent makes.
type Observer interface {
	ToolCallDecided(DecisionEvent)
	ToolCallCompleted(CompletionEvent)
}

// Options configure a Gateway.
type Options struct {
	Policy   *policy.Policy
	Detector *detect.Session
	Weights  detect.Weights
	// Scope is the declared working set, built by the caller from
	// Policy.Workspace. It is passed in already validated rather than built
	// here, so a malformed declaration is a startup failure the operator sees
	// instead of a scope check that silently matches nothing.
	//
	// The zero Scope is undeclared: scope facts stay false and empty, and rules
	// guarding on scope_declared do not fire.
	Scope    detect.Scope
	Logger   *slog.Logger
	Observer Observer
}

// Gateway implements proxy.Interceptor.
type Gateway struct {
	opts Options

	mu sync.Mutex
	// pending correlates a request id to the tool it invoked, so the response
	// can be attributed when it arrives. MCP responses carry no method name,
	// so without this the reply to a tool call is anonymous.
	pending map[string]pendingCall
}

type pendingCall struct {
	tool    string
	startAt time.Time
}

// New returns a Gateway.
func New(opts Options) *Gateway {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Weights == (detect.Weights{}) {
		opts.Weights = detect.DefaultWeights()
	}
	return &Gateway{opts: opts, pending: make(map[string]pendingCall)}
}

// toolCallParams is the params shape of a tools/call request.
type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// Intercept implements proxy.Interceptor.
func (g *Gateway) Intercept(_ context.Context, dir proxy.Direction, msg *jsonrpc.Message) (proxy.Interception, error) {
	if dir == proxy.ServerToClient {
		g.completeResponse(msg)
		return proxy.Interception{Decision: proxy.Forward}, nil
	}
	return g.inspectRequest(msg)
}

// inspectRequest evaluates a client-to-server message.
func (g *Gateway) inspectRequest(msg *jsonrpc.Message) (proxy.Interception, error) {
	switch msg.Method {
	case methodToolsCall:
		return g.inspectToolCall(msg)

	case methodResourcesRead, methodPromptsGet:
		// Secondary requests are recorded but not gated. They still count
		// toward the session's behaviour: an agent that enumerates resources
		// instead of calling tools is doing the same sweep by another route,
		// and excluding it would leave an obvious blind spot.
		g.observe(detect.Call{
			Tool:         msg.Method,
			Target:       firstTarget(msg.Params),
			PayloadBytes: len(msg.Params),
			IsToolCall:   false,
			At:           time.Now(),
		})
		return proxy.Interception{Decision: proxy.Forward}, nil

	default:
		// Handshake, ping, cancellation, and anything this build predates.
		return proxy.Interception{Decision: proxy.Forward}, nil
	}
}

func (g *Gateway) inspectToolCall(msg *jsonrpc.Message) (proxy.Interception, error) {
	var params toolCallParams
	if len(msg.Params) > 0 {
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			// Malformed params are the upstream server's business to reject —
			// it owns the tool's schema. Forwarding keeps chokepoint from
			// becoming a second, divergent validator.
			g.opts.Logger.Debug("tools/call params did not decode", "error", err)
			return proxy.Interception{Decision: proxy.Forward}, nil
		}
	}

	targets := policy.ExtractTargets(params.Arguments)

	// Observed before evaluation so the score reflects this call. A sweep's
	// final call is the one worth stopping, and scoring it against a session
	// that excludes it would always be one call behind.
	g.observe(detect.Call{
		Tool:         params.Name,
		Target:       firstOf(targets),
		PayloadBytes: len(msg.Params),
		IsToolCall:   true,
		At:           time.Now(),
	})

	assessment := g.assess()
	scope := g.scopeReport()
	outOfScope := g.outOfScope(targets)

	decision := g.evaluate(policy.Request{
		Tool:               params.Name,
		Method:             msg.Method,
		Args:               params.Arguments,
		Targets:            targets,
		SessionCalls:       assessment.Calls,
		SessionTargets:     g.distinctTargets(),
		DecompositionScore: assessment.Score,
		ScopeDeclared:      scope.Declared,
		OutOfScope:         outOfScope,
		SessionOutOfScope:  scope.Distinct,
	})

	if g.opts.Observer != nil {
		g.opts.Observer.ToolCallDecided(DecisionEvent{
			ID:               msg.IDKey(),
			Tool:             params.Name,
			Method:           msg.Method,
			Targets:          targets,
			Effect:           decision.Effect,
			Rule:             decision.Rule,
			Audited:          decision.Audited,
			Score:            assessment.Score,
			ScoreUnavailable: assessment.BelowMinimum,
			SessionCalls:     assessment.Calls,
			SessionTargets:   g.distinctTargets(),

			ScopeDeclared:     scope.Declared,
			OutOfScope:        len(outOfScope),
			SessionOutOfScope: scope.Distinct,
		})
	}

	switch decision.Effect {
	case policy.EffectDeny:
		g.opts.Logger.Warn("tool call denied",
			"tool", params.Name,
			"rule", decision.Rule,
			"targets", targets,
			"decomposition_score", assessment.Score,
			"out_of_scope", len(outOfScope),
		)
		reply, err := g.denialFor(msg, decision, assessment, outOfScope)
		if err != nil {
			return proxy.Interception{}, err
		}
		return proxy.Interception{Decision: proxy.Reject, Message: reply}, nil

	default:
		if len(decision.Audited) > 0 {
			g.opts.Logger.Info("tool call audited",
				"tool", params.Name, "rules", decision.Audited)
		}
		g.trackPending(msg, params.Name)
		return proxy.Interception{Decision: proxy.Forward}, nil
	}
}

// denialFor builds the JSON-RPC error returned to the agent.
//
// The payload names the rule and the score because the agent is the party that
// has to change course, and "denied" with no reason produces either a retry
// loop or a give-up — both worse than an explanation.
func (g *Gateway) denialFor(msg *jsonrpc.Message, d policy.Decision, a detect.Assessment, outOfScope []string) ([]byte, error) {
	message := d.Message
	if message == "" {
		message = "blocked by chokepoint policy"
	}

	data := map[string]any{
		"rule": d.Rule,
	}
	if !a.BelowMinimum {
		data["decomposition_score"] = round3(a.Score)
		data["contributions"] = roundAll(a.Contributions)
	}
	// The offending targets are echoed back because they came from the agent in
	// the first place — this leaks nothing it did not already send — and an
	// agent told only "out of scope" cannot tell which of its arguments was the
	// problem.
	if len(outOfScope) > 0 {
		data["out_of_scope"] = outOfScope
	}

	return jsonrpc.ErrorResponse(msg.ID, jsonrpc.CodePolicyDenied, message, data)
}

func (g *Gateway) trackPending(msg *jsonrpc.Message, tool string) {
	key := msg.IDKey()
	if key == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pending[key] = pendingCall{tool: tool, startAt: time.Now()}
}

// completeResponse attributes a response to the request that caused it.
func (g *Gateway) completeResponse(msg *jsonrpc.Message) {
	key := msg.IDKey()
	if key == "" {
		return
	}

	g.mu.Lock()
	call, ok := g.pending[key]
	delete(g.pending, key)
	g.mu.Unlock()
	if !ok {
		return
	}

	if msg.Error != nil {
		// A failed call is a peripheral event in the schema. Recording it
		// matters because an agent probing for what it is allowed to do
		// generates errors, and a detector blind to them misses the probe.
		g.observe(detect.Call{
			Tool:       call.tool,
			IsToolCall: true,
			Errored:    true,
			At:         time.Now(),
		})
	}

	if g.opts.Observer != nil {
		g.opts.Observer.ToolCallCompleted(CompletionEvent{
			ID:      key,
			Tool:    call.tool,
			Errored: msg.Error != nil,
			Latency: time.Since(call.startAt),
		})
	}
}

func (g *Gateway) observe(c detect.Call) {
	if g.opts.Detector != nil {
		g.opts.Detector.Observe(c)
	}
}

func (g *Gateway) assess() detect.Assessment {
	if g.opts.Detector == nil {
		return detect.Assessment{Contributions: map[string]float64{}}
	}
	return g.opts.Detector.Assess(g.opts.Weights)
}

// scopeReport is the session's position relative to the declared working set.
func (g *Gateway) scopeReport() detect.ScopeReport {
	if g.opts.Detector == nil || !g.opts.Scope.Declared() {
		return detect.ScopeReport{FirstOutOfScope: -1}
	}
	return g.opts.Detector.ScopeReport(g.opts.Scope)
}

// outOfScope returns the targets of the current call that land outside the
// working set, in the form the agent sent them.
//
// This checks every target on the call, while the session-level counts from
// scopeReport see only the one target retained per observation. A call naming
// several targets is therefore denied on any of them, but contributes at most
// one to session_out_of_scope. Widening the observation to all targets would
// inflate the call counts the score and its calibration table are built on, so
// the per-call check is the one to trust for enforcement and the session count
// is a floor.
func (g *Gateway) outOfScope(targets []string) []string {
	if !g.opts.Scope.Declared() {
		return nil
	}
	var out []string
	for _, t := range targets {
		r := detect.ParseResource(t)
		if r.Empty() {
			// A target that names no resource is not evidence of anything. It
			// is neither inside the boundary nor outside it, and counting it as
			// an escape would make every malformed argument an alert.
			continue
		}
		if !g.opts.Scope.Contains(r) {
			out = append(out, t)
		}
	}
	return out
}

func (g *Gateway) distinctTargets() int {
	if g.opts.Detector == nil {
		return 0
	}
	return int(g.opts.Detector.Vector().Get(detect.FeatTargetBreadth))
}

func (g *Gateway) evaluate(req policy.Request) policy.Decision {
	if g.opts.Policy == nil {
		return policy.Decision{Effect: policy.EffectAllow}
	}
	return g.opts.Policy.Evaluate(req)
}

// firstTarget extracts a target from an arbitrary params object.
func firstTarget(params json.RawMessage) string {
	if len(params) == 0 {
		return ""
	}
	var decoded map[string]any
	if err := json.Unmarshal(params, &decoded); err != nil {
		return ""
	}
	return firstOf(policy.ExtractTargets(decoded))
}

func firstOf(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func round3(f float64) float64 {
	return float64(int(f*1000+0.5)) / 1000
}

func roundAll(m map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(m))
	for k, v := range m {
		out[k] = round3(v)
	}
	return out
}

// ToolNameFromMethod is a small helper for callers that log raw methods.
func ToolNameFromMethod(method string) string {
	if i := strings.LastIndex(method, "/"); i >= 0 {
		return method[i+1:]
	}
	return method
}
