// Package telemetry implements gateway.Observer as Prometheus metrics and
// OpenTelemetry spans.
//
// Both are optional and independently switchable. A deployment that wants
// neither pays for neither: with no metrics address and no OTLP endpoint, the
// gateway's Observer is nil and nothing here runs.
//
// # Cardinality
//
// Metric labels are restricted to values bounded by configuration: the tool
// name (fixed by the upstream server's tool list) and the policy rule name
// (fixed by the policy file). Extracted targets — file paths, URLs, hostnames —
// are deliberately never labels. They are attacker-influenced and unbounded,
// and a metrics backend given one series per distinct path is a denial of
// service against your own monitoring. Targets go on spans instead, where
// high-cardinality detail belongs.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/BipinRimal314/chokepoint/internal/gateway"
	"github.com/BipinRimal314/chokepoint/internal/policy"
)

// SpanTTL bounds how long an unanswered tool call's span is held open.
//
// A span is opened when a call is forwarded and closed when its response
// arrives. If the upstream never answers — it hung, it crashed, it lost the
// request — the span would otherwise be held forever: never exported, and
// leaking memory in a process meant to run for weeks. After this long it is
// closed and marked as such, so the trace records "no answer" rather than
// silently omitting the call.
const SpanTTL = 5 * time.Minute

// Options configure telemetry.
type Options struct {
	ServiceName string
	Version     string
	// MetricsAddr is a listen address for the /metrics endpoint, e.g.
	// ":9090". Empty disables the endpoint and all metric collection.
	MetricsAddr string
	// OTLPEndpoint is an OTLP/gRPC collector address, e.g. "localhost:4317".
	// Empty disables tracing.
	OTLPEndpoint string
	Logger       *slog.Logger
}

// Telemetry implements gateway.Observer.
type Telemetry struct {
	logger *slog.Logger

	registry *prometheus.Registry
	metrics  *metrics
	server   *http.Server
	// boundAddr is the address actually listened on, which differs from the
	// requested one whenever port 0 was asked for.
	boundAddr string

	tracer   trace.Tracer
	provider *sdktrace.TracerProvider

	mu    sync.Mutex
	spans map[string]*pendingSpan

	stopSweeper context.CancelFunc
	sweeperDone chan struct{}
}

type pendingSpan struct {
	span    trace.Span
	started time.Time
}

type metrics struct {
	toolCalls      *prometheus.CounterVec
	denials        *prometheus.CounterVec
	audits         *prometheus.CounterVec
	upstreamErrors *prometheus.CounterVec
	duration       *prometheus.HistogramVec

	decompositionScore prometheus.Gauge
	sessionCalls       prometheus.Gauge
	sessionTargets     prometheus.Gauge
	abandonedSpans     prometheus.Counter
}

func newMetrics(reg prometheus.Registerer) *metrics {
	factory := promauto(reg)
	return &metrics{
		toolCalls: factory.counterVec(prometheus.CounterOpts{
			Name: "chokepoint_tool_calls_total",
			Help: "Tool calls seen, by tool and policy effect.",
		}, []string{"tool", "effect"}),

		denials: factory.counterVec(prometheus.CounterOpts{
			Name: "chokepoint_policy_denials_total",
			Help: "Tool calls denied, by tool and the rule that denied them.",
		}, []string{"tool", "rule"}),

		audits: factory.counterVec(prometheus.CounterOpts{
			Name: "chokepoint_policy_audits_total",
			Help: "Audit-effect rule matches, by rule.",
		}, []string{"rule"}),

		upstreamErrors: factory.counterVec(prometheus.CounterOpts{
			Name: "chokepoint_upstream_errors_total",
			Help: "Forwarded calls the upstream answered with an error, by tool.",
		}, []string{"tool"}),

		duration: factory.histogramVec(prometheus.HistogramOpts{
			Name: "chokepoint_tool_call_duration_seconds",
			Help: "Upstream latency for forwarded tool calls.",
			// Tool calls span filesystem reads (sub-millisecond) to network
			// fetches and shell commands (tens of seconds), so the buckets
			// cover five orders of magnitude rather than the default range,
			// which tops out at 10s and would collapse the slow tail.
			Buckets: []float64{
				0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60,
			},
		}, []string{"tool"}),

		decompositionScore: factory.gauge(prometheus.GaugeOpts{
			Name: "chokepoint_decomposition_score",
			Help: "Most recent decomposition score for the session, 0-1. " +
				"NaN until the session is long enough to score.",
		}),

		sessionCalls: factory.gauge(prometheus.GaugeOpts{
			Name: "chokepoint_session_calls",
			Help: "Calls retained in the current behavioural window.",
		}),

		sessionTargets: factory.gauge(prometheus.GaugeOpts{
			Name: "chokepoint_session_targets",
			Help: "Distinct targets touched in the current behavioural window.",
		}),

		abandonedSpans: factory.counter(prometheus.CounterOpts{
			Name: "chokepoint_abandoned_spans_total",
			Help: "Tool calls the upstream never answered within the span TTL.",
		}),
	}
}

// New builds telemetry from opts. The returned Telemetry is always usable;
// disabled subsystems become no-ops rather than nil checks at every call site.
func New(ctx context.Context, opts Options) (*Telemetry, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.ServiceName == "" {
		opts.ServiceName = "chokepoint"
	}

	t := &Telemetry{
		logger: opts.Logger,
		spans:  make(map[string]*pendingSpan),
		// A no-op tracer until one is configured, so the recording path needs
		// no conditionals.
		tracer: noop.NewTracerProvider().Tracer("chokepoint"),
	}

	if opts.MetricsAddr != "" {
		t.registry = prometheus.NewRegistry()
		t.metrics = newMetrics(t.registry)
		// A registered gauge reports 0 from the moment it exists, and 0 is a
		// legitimate decomposition score meaning "nothing suspicious". Left
		// alone, a brand-new session would render on a dashboard as
		// definitively safe rather than as not yet measured. NaN is
		// Prometheus's way of saying "no value", and Grafana and friends
		// render it as a gap.
		t.metrics.decompositionScore.Set(math.NaN())
		if err := t.startMetricsServer(opts.MetricsAddr); err != nil {
			return nil, err
		}
	}

	if opts.OTLPEndpoint != "" {
		if err := t.startTracing(ctx, opts); err != nil {
			// Tearing down the metrics server keeps New's contract simple:
			// either everything the caller asked for is running, or nothing is
			// and they get an error.
			_ = t.Shutdown(context.Background())
			return nil, err
		}
	}

	sweepCtx, cancel := context.WithCancel(context.Background())
	t.stopSweeper = cancel
	t.sweeperDone = make(chan struct{})
	go t.sweepAbandonedSpans(sweepCtx)

	return t, nil
}

func (t *Telemetry) startMetricsServer(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(t.registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	t.server = &http.Server{
		Addr:    addr,
		Handler: mux,
		// A metrics scrape that stalls must not pin a connection open forever.
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Listen synchronously so a port conflict is reported to the caller rather
	// than logged from a goroutine after startup appears to have succeeded.
	listener, err := netListen(addr)
	if err != nil {
		return fmt.Errorf("metrics listener on %s: %w", addr, err)
	}

	t.boundAddr = listener.Addr().String()

	go func() {
		if err := t.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.logger.Error("metrics server stopped", "error", err)
		}
	}()
	t.logger.Info("metrics endpoint listening", "addr", t.boundAddr)
	return nil
}

// listenerAddr reports the address the metrics endpoint actually bound to,
// which differs from the configured one when port 0 was requested. Empty when
// metrics are disabled.
func (t *Telemetry) listenerAddr() string { return t.boundAddr }

func (t *Telemetry) startTracing(ctx context.Context, opts Options) error {
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(opts.OTLPEndpoint),
		// Plaintext by default: the expected deployment is a collector
		// sidecar or a DaemonSet peer on the same node, not the public
		// internet. TLS would need certificate configuration this flag set
		// does not expose, and a half-configured TLS story is worse than an
		// explicit plaintext one.
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return fmt.Errorf("otlp exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(opts.ServiceName),
		semconv.ServiceVersion(opts.Version),
	))
	if err != nil {
		return fmt.Errorf("otel resource: %w", err)
	}

	t.provider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	t.tracer = t.provider.Tracer("github.com/BipinRimal314/chokepoint")
	t.logger.Info("tracing enabled", "endpoint", opts.OTLPEndpoint)
	return nil
}

// ToolCallDecided implements gateway.Observer.
func (t *Telemetry) ToolCallDecided(ev gateway.DecisionEvent) {
	if t.metrics != nil {
		t.metrics.toolCalls.WithLabelValues(ev.Tool, string(ev.Effect)).Inc()
		for _, rule := range ev.Audited {
			t.metrics.audits.WithLabelValues(rule).Inc()
		}
		if ev.Effect == policy.EffectDeny {
			t.metrics.denials.WithLabelValues(ev.Tool, ev.Rule).Inc()
		}
		// NaN while the session is too short to score. 0.0 is a real score
		// meaning "nothing suspicious"; publishing it for a session that has
		// not been measured would read as "definitely safe" on a dashboard,
		// which is the opposite of "not yet known".
		if ev.ScoreUnavailable {
			t.metrics.decompositionScore.Set(math.NaN())
		} else {
			t.metrics.decompositionScore.Set(ev.Score)
		}
		t.metrics.sessionCalls.Set(float64(ev.SessionCalls))
		t.metrics.sessionTargets.Set(float64(ev.SessionTargets))
	}

	attrs := []attribute.KeyValue{
		attribute.String("mcp.tool.name", ev.Tool),
		attribute.String("mcp.method", ev.Method),
		attribute.String("chokepoint.policy.effect", string(ev.Effect)),
		attribute.Int("chokepoint.session.calls", ev.SessionCalls),
		attribute.Int("chokepoint.session.targets", ev.SessionTargets),
	}
	if ev.Rule != "" {
		attrs = append(attrs, attribute.String("chokepoint.policy.rule", ev.Rule))
	}
	if len(ev.Targets) > 0 {
		attrs = append(attrs, attribute.StringSlice("chokepoint.targets", ev.Targets))
	}
	if !ev.ScoreUnavailable {
		attrs = append(attrs, attribute.Float64("chokepoint.decomposition.score", ev.Score))
	}

	_, span := t.tracer.Start(context.Background(), "mcp.tool_call",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)

	if ev.Effect == policy.EffectDeny {
		// A denied call is answered locally and no upstream response will ever
		// arrive, so the span ends here. Holding it open waiting for a
		// completion that cannot come would leak one span per denial —
		// precisely the calls an operator most wants to see in a trace.
		span.SetStatus(codes.Error, "denied by policy: "+ev.Rule)
		span.End()
		return
	}

	if ev.ID == "" {
		// A notification: no response will correlate to it.
		span.End()
		return
	}

	t.mu.Lock()
	t.spans[ev.ID] = &pendingSpan{span: span, started: time.Now()}
	t.mu.Unlock()
}

// ToolCallCompleted implements gateway.Observer.
func (t *Telemetry) ToolCallCompleted(ev gateway.CompletionEvent) {
	if t.metrics != nil {
		t.metrics.duration.WithLabelValues(ev.Tool).Observe(ev.Latency.Seconds())
		if ev.Errored {
			t.metrics.upstreamErrors.WithLabelValues(ev.Tool).Inc()
		}
	}

	t.mu.Lock()
	pending, ok := t.spans[ev.ID]
	delete(t.spans, ev.ID)
	t.mu.Unlock()
	if !ok {
		return
	}

	pending.span.SetAttributes(
		attribute.Float64("chokepoint.upstream.latency_ms", float64(ev.Latency.Microseconds())/1000),
	)
	if ev.Errored {
		pending.span.SetStatus(codes.Error, "upstream returned an error")
	} else {
		pending.span.SetStatus(codes.Ok, "")
	}
	pending.span.End()
}

// sweepAbandonedSpans closes spans whose response never arrived.
func (t *Telemetry) sweepAbandonedSpans(ctx context.Context) {
	defer close(t.sweeperDone)

	ticker := time.NewTicker(SpanTTL / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.closeAllSpans("shutting down")
			return
		case <-ticker.C:
			t.expireSpans()
		}
	}
}

func (t *Telemetry) expireSpans() {
	cutoff := time.Now().Add(-SpanTTL)

	t.mu.Lock()
	var expired []*pendingSpan
	for id, pending := range t.spans {
		if pending.started.Before(cutoff) {
			expired = append(expired, pending)
			delete(t.spans, id)
		}
	}
	t.mu.Unlock()

	for _, pending := range expired {
		pending.span.SetStatus(codes.Error, "upstream never answered")
		pending.span.End()
		if t.metrics != nil {
			t.metrics.abandonedSpans.Inc()
		}
	}
}

func (t *Telemetry) closeAllSpans(reason string) {
	t.mu.Lock()
	pendings := make([]*pendingSpan, 0, len(t.spans))
	for id, pending := range t.spans {
		pendings = append(pendings, pending)
		delete(t.spans, id)
	}
	t.mu.Unlock()

	for _, pending := range pendings {
		pending.span.SetStatus(codes.Error, reason)
		pending.span.End()
	}
}

// Shutdown stops the metrics server and flushes pending spans.
func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t.stopSweeper != nil {
		t.stopSweeper()
		// Wait for the sweeper to close outstanding spans before the provider
		// is torn down, otherwise they are dropped instead of exported.
		select {
		case <-t.sweeperDone:
		case <-ctx.Done():
		}
	}

	var errs []error
	if t.server != nil {
		if err := t.server.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("metrics server: %w", err))
		}
	}
	if t.provider != nil {
		if err := t.provider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("tracer provider: %w", err))
		}
	}
	return errors.Join(errs...)
}

// Registry exposes the Prometheus registry, for tests.
func (t *Telemetry) Registry() *prometheus.Registry { return t.registry }

// PendingSpans reports how many spans await a response, for tests.
func (t *Telemetry) PendingSpans() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.spans)
}
