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
	"github.com/BipinRimal314/chokepoint/internal/inventory"
	"github.com/BipinRimal314/chokepoint/internal/jsonrpc"
	"github.com/BipinRimal314/chokepoint/internal/policy"
	"github.com/BipinRimal314/chokepoint/internal/proxy"
)

// MCP method names the gateway treats specially.
const (
	methodToolsCall     = "tools/call"
	methodToolsList     = "tools/list"
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

	// CallsInWindow and TargetsInWindow are recent activity over the policy's
	// rate window. Recorded on every decision, not only on a rate denial: the
	// rate an allowed call arrived at is the baseline that makes a later denial
	// legible to whoever reads the log.
	CallsInWindow   int
	TargetsInWindow int
	// RateWindow is the span those two cover. Without it the counts are
	// uninterpretable — 200 calls is unremarkable over an hour and an incident
	// over a second — and the window is a policy setting that can change
	// between the decisions in one log.
	RateWindow time.Duration

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

	// ToolDefinitionChanged is true when this tool's advertised definition has
	// changed since the session's first tools/list.
	ToolDefinitionChanged bool
	// SessionToolsChanged is how many distinct tools have changed so far.
	SessionToolsChanged int
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

// Observers fans one event out to several observers, in order.
//
// A deployment can want traces and an evidence log at once, and they are
// different subsystems with different failure modes — one must not be reachable
// only by turning the other off.
type Observers []Observer

// ToolCallDecided implements Observer.
func (o Observers) ToolCallDecided(e DecisionEvent) {
	for _, obs := range o {
		obs.ToolCallDecided(e)
	}
}

// ToolCallCompleted implements Observer.
func (o Observers) ToolCallCompleted(e CompletionEvent) {
	for _, obs := range o {
		obs.ToolCallCompleted(e)
	}
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
	Scope detect.Scope
	// Inventory fingerprints advertised tool definitions and reports mutation.
	// Nil disables the check entirely, including the policy variables it feeds.
	Inventory *inventory.Registry
	Logger    *slog.Logger
	Observer  Observer
}

// Gateway implements proxy.Interceptor.
type Gateway struct {
	opts Options

	mu sync.Mutex
	// pending correlates a request id to the tool it invoked, so the response
	// can be attributed when it arrives. MCP responses carry no method name,
	// so without this the reply to a tool call is anonymous.
	pending map[string]pendingCall
	// listings holds the ids of in-flight tools/list requests, so the response
	// carrying the tool definitions can be recognised. MCP responses carry no
	// method name, so without this a tools/list result is indistinguishable
	// from any other result.
	listings map[string]struct{}
	// denials counts refusals by rule name, for the session report. Kept here
	// rather than recomputed from the detector because a denied call is not
	// distinguishable from an allowed one in the observation stream — the
	// detector records what was attempted, not what was permitted.
	denials map[string]int
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
	if opts.Inventory == nil {
		opts.Inventory = inventory.NewRegistry()
	}
	return &Gateway{
		opts:     opts,
		pending:  make(map[string]pendingCall),
		listings: make(map[string]struct{}),
		denials:  make(map[string]int),
	}
}

// toolCallParams is the params shape of a tools/call request.
type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// Intercept implements proxy.Interceptor.
func (g *Gateway) Intercept(_ context.Context, dir proxy.Direction, msg *jsonrpc.Message) (proxy.Interception, error) {
	if dir == proxy.ServerToClient {
		g.inspectToolListing(msg)
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

	case methodToolsList:
		// Not gated — an agent has to be able to discover its tools — but the
		// id is remembered so the definitions in the reply can be fingerprinted.
		g.trackListing(msg)
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

	// One clock reading for the observation and the rate window both. Calling
	// time.Now() again below would put this call fractionally in the past
	// relative to its own window, which is only ever wrong.
	now := time.Now()

	// Observed before evaluation so the score reflects this call. A sweep's
	// final call is the one worth stopping, and scoring it against a session
	// that excludes it would always be one call behind.
	g.observe(detect.Call{
		Tool:         params.Name,
		Target:       firstOf(targets),
		PayloadBytes: len(msg.Params),
		IsToolCall:   true,
		At:           now,
	})

	assessment := g.assess()
	scope := g.scopeReport()
	outOfScope := g.outOfScope(targets)
	// Read once. The policy request and the decision event both want it, and
	// asking twice used to mean walking the whole session twice.
	sessionTargets := g.distinctTargets()
	window := g.rateWindow()
	rate := g.countsInWindow(window, now)

	decision := g.evaluate(policy.Request{
		Tool:               params.Name,
		Method:             msg.Method,
		Args:               params.Arguments,
		Targets:            targets,
		SessionCalls:       assessment.Calls,
		SessionTargets:     sessionTargets,
		CallsInWindow:      rate.Calls,
		TargetsInWindow:    rate.Targets,
		DecompositionScore: assessment.Score,
		ScopeDeclared:      scope.Declared,
		OutOfScope:         outOfScope,
		SessionOutOfScope:  scope.Distinct,

		ToolDefinitionChanged: g.opts.Inventory.Changed(params.Name),
		SessionToolsChanged:   g.opts.Inventory.ChangedCount(),
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
			SessionTargets:   sessionTargets,

			CallsInWindow:   rate.Calls,
			TargetsInWindow: rate.Targets,
			RateWindow:      window,

			ScopeDeclared:     scope.Declared,
			OutOfScope:        len(outOfScope),
			SessionOutOfScope: scope.Distinct,

			ToolDefinitionChanged: g.opts.Inventory.Changed(params.Name),
			SessionToolsChanged:   g.opts.Inventory.ChangedCount(),
		})
	}

	switch decision.Effect {
	case policy.EffectDeny:
		g.recordDenial(decision.Rule)
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

// recordDenial counts one refusal. The default effect denying with no rule
// matched is attributed to "default_effect" rather than to an empty name, so
// the report distinguishes a deny-by-default deployment from a rule firing.
func (g *Gateway) recordDenial(rule string) {
	if rule == "" {
		rule = "default_effect"
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.denials[rule]++
}

// trackListing remembers a tools/list request id.
func (g *Gateway) trackListing(msg *jsonrpc.Message) {
	key := msg.IDKey()
	if key == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.listings[key] = struct{}{}
}

// toolListResult is the shape of a tools/list reply. Tools stay as raw JSON so
// the fingerprint covers fields this build has never heard of.
type toolListResult struct {
	Tools []json.RawMessage `json:"tools"`
}

// inspectToolListing fingerprints the definitions in a tools/list reply.
//
// The reply is always forwarded. Refusing it would break discovery for an agent
// that has done nothing wrong yet, and the mutation has already happened by the
// time it is visible — the useful moment to act is the next call to the tool
// that changed, which is where policy gets to decide.
func (g *Gateway) inspectToolListing(msg *jsonrpc.Message) {
	key := msg.IDKey()
	if key == "" || len(msg.Result) == 0 {
		return
	}

	g.mu.Lock()
	_, isListing := g.listings[key]
	delete(g.listings, key)
	g.mu.Unlock()
	if !isListing {
		return
	}

	var result toolListResult
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		g.opts.Logger.Debug("tools/list result did not decode", "error", err)
		return
	}

	for _, change := range g.opts.Inventory.Observe(result.Tools) {
		// Warn, not Info: a definition changing under a running session is the
		// rug pull this check exists for, and it is the operator's only notice.
		g.opts.Logger.Warn("tool definition changed since first listing",
			"tool", change.Tool,
			"kind", string(change.Kind),
			"listing", change.Listing,
			"was", change.Was,
			"now", change.Now,
		)
	}
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

// rateWindow is the policy's window, or the default when it set none.
//
// The default lives here rather than in policy because policy does not import
// detect, and it is detect that owns what the counters mean.
func (g *Gateway) rateWindow() time.Duration {
	if d := g.opts.Policy.RateWindowDuration(); d > 0 {
		return d
	}
	return detect.DefaultRateWindow
}

func (g *Gateway) countsInWindow(d time.Duration, now time.Time) detect.WindowCounts {
	if g.opts.Detector == nil {
		return detect.WindowCounts{}
	}
	return g.opts.Detector.CountsInWindow(d, now)
}

func (g *Gateway) distinctTargets() int {
	if g.opts.Detector == nil {
		return 0
	}
	return g.opts.Detector.DistinctTargets()
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
