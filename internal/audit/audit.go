// Package audit writes tool-call decisions as an append-only evidence log.
//
// The format is OTLP/JSON spans, one per line. That is not an arbitrary
// choice: it is what compliance tooling already reads, so the log is evidence
// rather than a file that would need a bespoke parser written for it. In
// particular ai-trace-auditor ingests flat OTLP span lists and classifies a
// span as a tool call from the OTel GenAI semantic conventions, so the
// attributes below are emitted under those names as well as chokepoint's own.
//
// Why a file at all, when the OTLP exporter already exists: the exporter needs
// a collector. An audit log is the artefact a regulator or a reviewer asks for,
// and requiring a running collector to produce one puts an operational
// dependency in front of a legal obligation. The file has no dependencies.
//
// It inherits the sensitivity of what it records. Tool arguments become
// targets, and targets are file paths, hostnames and query strings — treat the
// log as being as confidential as the data the agent was working on.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/BipinRimal314/chokepoint/internal/gateway"
	"github.com/BipinRimal314/chokepoint/internal/policy"
)

// Attr is one attribute in a neutral form.
//
// Value is a string, int, float64, or []string. It exists so that the
// attribute set has exactly one definition: the trace exporter and this writer
// both build from Attributes below, and cannot drift into describing the same
// decision differently.
type Attr struct {
	Key   string
	Value any
}

// Attribute keys. The gen_ai.* names are the OTel GenAI semantic conventions
// and are what makes a span recognisable as a tool call to tooling that did
// not know chokepoint existed. The mcp.* and chokepoint.* names carry what the
// conventions have no place for.
const (
	KeyGenAIOperation = "gen_ai.operation.name"
	KeyGenAIToolName  = "gen_ai.tool.name"
	KeyGenAIToolCall  = "gen_ai.tool.call.id"

	KeyMCPTool   = "mcp.tool.name"
	KeyMCPMethod = "mcp.method"

	KeyEffect         = "chokepoint.policy.effect"
	KeyRule           = "chokepoint.policy.rule"
	KeyTargets        = "chokepoint.targets"
	KeyScore          = "chokepoint.decomposition.score"
	KeySessionCalls   = "chokepoint.session.calls"
	KeySessionTargets = "chokepoint.session.targets"
	KeyScopeDeclared  = "chokepoint.scope.declared"
	KeyOutOfScope     = "chokepoint.scope.out_of_scope"
	KeySessionOutOf   = "chokepoint.scope.session_out_of_scope"
)

// OperationToolCall is the gen_ai.operation.name value for a tool call.
const OperationToolCall = "tool_call"

// Attributes is the canonical attribute set for one decision.
//
// Absent facts are omitted rather than sent as zero. A score of 0.0 and "not
// yet scoreable" are the same number and opposite facts, and an evidence log
// that cannot tell them apart is worse than one that says nothing.
func Attributes(ev gateway.DecisionEvent) []Attr {
	attrs := []Attr{
		{KeyGenAIOperation, OperationToolCall},
		{KeyGenAIToolName, ev.Tool},
		{KeyMCPTool, ev.Tool},
		{KeyMCPMethod, ev.Method},
		{KeyEffect, string(ev.Effect)},
		{KeySessionCalls, ev.SessionCalls},
		{KeySessionTargets, ev.SessionTargets},
	}
	if ev.ID != "" {
		attrs = append(attrs, Attr{KeyGenAIToolCall, ev.ID})
	}
	if ev.Rule != "" {
		attrs = append(attrs, Attr{KeyRule, ev.Rule})
	}
	if len(ev.Targets) > 0 {
		attrs = append(attrs, Attr{KeyTargets, ev.Targets})
	}
	if !ev.ScoreUnavailable {
		attrs = append(attrs, Attr{KeyScore, ev.Score})
	}
	if ev.ScopeDeclared {
		attrs = append(attrs,
			Attr{KeyScopeDeclared, true},
			Attr{KeyOutOfScope, ev.OutOfScope},
			Attr{KeySessionOutOf, ev.SessionOutOfScope},
		)
	}
	return attrs
}

// Writer records decisions as OTLP/JSON span lines.
//
// It implements gateway.Observer and, like every observer, must not block: it
// is called from the request path. Each record is one line, written and
// flushed as the decision is made, so a process that dies mid-session still
// leaves the evidence of everything it decided up to that point. An audit log
// that loses its tail on a crash is not an audit log.
type Writer struct {
	mu      sync.Mutex
	w       io.Writer
	enc     *json.Encoder
	traceID string
	// onError reports a write failure once. An evidence log that silently
	// stops recording is the failure mode worth shouting about, but shouting
	// once per call in the request path would be its own outage.
	onError   func(error)
	failed    bool
	written   int
	nowFunc   func() time.Time
	newSpanID func() string
}

// Options configure a Writer.
type Options struct {
	// OnError is called at most once, on the first write failure.
	OnError func(error)
}

// New returns a Writer emitting to w.
//
// All records from one Writer share a trace id, so a session's calls arrive at
// a consumer as one trace rather than as unrelated spans.
func New(w io.Writer, opts Options) *Writer {
	enc := json.NewEncoder(w)
	return &Writer{
		w:         w,
		enc:       enc,
		traceID:   randomHex(16),
		onError:   opts.OnError,
		nowFunc:   time.Now,
		newSpanID: func() string { return randomHex(8) },
	}
}

// TraceID is the id shared by every record this Writer emits.
func (w *Writer) TraceID() string { return w.traceID }

// Written is how many records have been emitted.
func (w *Writer) Written() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.written
}

// ToolCallDecided implements gateway.Observer.
func (w *Writer) ToolCallDecided(ev gateway.DecisionEvent) {
	now := w.nowFunc()
	nanos := strconv.FormatInt(now.UnixNano(), 10)

	rec := spanRecord{
		TraceID: w.traceID,
		SpanID:  w.newSpanID(),
		Name:    "mcp.tool_call",
		// 3 is SPAN_KIND_CLIENT: chokepoint is the caller of the upstream
		// tool server.
		Kind: 3,
		// A decision is a point in time, not an interval. The upstream latency
		// of an allowed call is a different fact and belongs on the trace
		// exporter's span, which correlates the response. Recording a
		// fabricated duration here to look more span-like would be inventing
		// evidence.
		StartTimeUnixNano: nanos,
		EndTimeUnixNano:   nanos,
		Attributes:        encodeAttrs(Attributes(ev)),
	}
	if ev.Effect == policy.EffectDeny {
		// 2 is STATUS_CODE_ERROR. A refusal is the record most likely to be
		// read, so it is marked rather than left to be inferred from an
		// attribute.
		rec.Status = &spanStatus{Code: 2, Message: "denied by policy: " + ev.Rule}
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.enc.Encode(rec); err != nil {
		w.reportLocked(fmt.Errorf("write audit record: %w", err))
		return
	}
	w.written++
}

// ToolCallCompleted implements gateway.Observer and does nothing.
//
// The log records decisions — what was permitted and what was refused — which
// is the question an audit asks. Whether the upstream then succeeded is
// visible in the trace exporter and the metrics, and correlating it here would
// mean holding records open and writing them out of order, which costs the
// append-only property that makes the log trustworthy.
func (w *Writer) ToolCallCompleted(gateway.CompletionEvent) {}

func (w *Writer) reportLocked(err error) {
	if w.failed || w.onError == nil {
		return
	}
	w.failed = true
	w.onError(err)
}

// spanRecord is one OTLP/JSON span.
type spanRecord struct {
	TraceID           string      `json:"traceId"`
	SpanID            string      `json:"spanId"`
	Name              string      `json:"name"`
	Kind              int         `json:"kind"`
	StartTimeUnixNano string      `json:"startTimeUnixNano"`
	EndTimeUnixNano   string      `json:"endTimeUnixNano"`
	Attributes        []jsonAttr  `json:"attributes"`
	Status            *spanStatus `json:"status,omitempty"`
}

type spanStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

type jsonAttr struct {
	Key   string    `json:"key"`
	Value jsonValue `json:"value"`
}

// jsonValue is OTLP's tagged union. Exactly one field is ever set.
type jsonValue struct {
	StringValue *string    `json:"stringValue,omitempty"`
	IntValue    *string    `json:"intValue,omitempty"`
	DoubleValue *float64   `json:"doubleValue,omitempty"`
	BoolValue   *bool      `json:"boolValue,omitempty"`
	ArrayValue  *jsonArray `json:"arrayValue,omitempty"`
}

type jsonArray struct {
	Values []jsonValue `json:"values"`
}

func encodeAttrs(attrs []Attr) []jsonAttr {
	out := make([]jsonAttr, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, jsonAttr{Key: a.Key, Value: encodeValue(a.Value)})
	}
	return out
}

func encodeValue(v any) jsonValue {
	switch t := v.(type) {
	case string:
		return jsonValue{StringValue: &t}
	case bool:
		return jsonValue{BoolValue: &t}
	case float64:
		return jsonValue{DoubleValue: &t}
	case int:
		// OTLP/JSON encodes 64-bit integers as strings, because JSON numbers
		// lose precision past 2^53 and a conforming consumer expects the
		// string form.
		s := strconv.Itoa(t)
		return jsonValue{IntValue: &s}
	case []string:
		vals := make([]jsonValue, 0, len(t))
		for _, s := range t {
			s := s
			vals = append(vals, jsonValue{StringValue: &s})
		}
		return jsonValue{ArrayValue: &jsonArray{Values: vals}}
	default:
		s := fmt.Sprint(v)
		return jsonValue{StringValue: &s}
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not recoverable here and not worth failing
		// the session over: the id only has to be unique enough to group one
		// session's records, so fall back to the clock.
		return hex.EncodeToString([]byte(strconv.FormatInt(time.Now().UnixNano(), 16)))[:n*2]
	}
	return hex.EncodeToString(b)
}
