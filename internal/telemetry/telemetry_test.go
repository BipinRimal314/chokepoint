package telemetry

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/BipinRimal314/chokepoint/internal/gateway"
	"github.com/BipinRimal314/chokepoint/internal/policy"
)

// newForTest builds a Telemetry with metrics on an ephemeral port and no
// tracing, which is what most assertions here need.
func newForTest(t *testing.T) *Telemetry {
	t.Helper()
	tel, err := New(context.Background(), Options{
		ServiceName: "chokepoint-test",
		MetricsAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tel.Shutdown(ctx)
	})
	return tel
}

// metricValue returns the value of a counter/gauge matching name and labels.
func metricValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, m := range family.GetMetric() {
			if !labelsMatch(m, labels) {
				continue
			}
			switch {
			case m.GetCounter() != nil:
				return m.GetCounter().GetValue()
			case m.GetGauge() != nil:
				return m.GetGauge().GetValue()
			case m.GetHistogram() != nil:
				return float64(m.GetHistogram().GetSampleCount())
			}
		}
	}
	return -1 // not present, distinct from a legitimate zero
}

func labelsMatch(m *dto.Metric, want map[string]string) bool {
	got := map[string]string{}
	for _, lp := range m.GetLabel() {
		got[lp.GetName()] = lp.GetValue()
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

func decision(id, tool string, effect policy.Effect) gateway.DecisionEvent {
	return gateway.DecisionEvent{
		ID: id, Tool: tool, Method: "tools/call",
		Effect: effect, Score: 0.5, SessionCalls: 10, SessionTargets: 7,
	}
}

func TestAllowedCallCountsAndRecordsDuration(t *testing.T) {
	tel := newForTest(t)

	tel.ToolCallDecided(decision("1", "read_file", policy.EffectAllow))
	tel.ToolCallCompleted(gateway.CompletionEvent{
		ID: "1", Tool: "read_file", Latency: 25 * time.Millisecond,
	})

	if got := metricValue(t, tel.Registry(), "chokepoint_tool_calls_total",
		map[string]string{"tool": "read_file", "effect": "allow"}); got != 1 {
		t.Errorf("tool_calls_total = %v, want 1", got)
	}
	if got := metricValue(t, tel.Registry(), "chokepoint_tool_call_duration_seconds",
		map[string]string{"tool": "read_file"}); got != 1 {
		t.Errorf("duration sample count = %v, want 1", got)
	}
}

func TestDeniedCallIsCountedAgainstItsRule(t *testing.T) {
	tel := newForTest(t)

	ev := decision("2", "shell", policy.EffectDeny)
	ev.Rule = "no-shell"
	tel.ToolCallDecided(ev)

	if got := metricValue(t, tel.Registry(), "chokepoint_policy_denials_total",
		map[string]string{"tool": "shell", "rule": "no-shell"}); got != 1 {
		t.Errorf("denials_total = %v, want 1", got)
	}
	// A denied call never reaches the upstream, so it must not contribute a
	// latency observation — that would drag the upstream's own latency
	// distribution toward zero.
	if got := metricValue(t, tel.Registry(), "chokepoint_tool_call_duration_seconds",
		map[string]string{"tool": "shell"}); got != -1 {
		t.Errorf("denied call recorded a duration sample (%v); it never reached upstream", got)
	}
}

func TestDeniedCallDoesNotLeaveAPendingSpan(t *testing.T) {
	// A denial is answered locally, so no completion will ever arrive. Holding
	// the span open would leak one per denial — exactly the calls an operator
	// most wants to see.
	tel := newForTest(t)

	ev := decision("3", "shell", policy.EffectDeny)
	ev.Rule = "no-shell"
	tel.ToolCallDecided(ev)

	if got := tel.PendingSpans(); got != 0 {
		t.Errorf("pending spans = %d, want 0 after a denial", got)
	}
}

func TestForwardedCallHoldsASpanUntilCompletion(t *testing.T) {
	tel := newForTest(t)

	tel.ToolCallDecided(decision("4", "read_file", policy.EffectAllow))
	if got := tel.PendingSpans(); got != 1 {
		t.Fatalf("pending spans = %d, want 1 while awaiting the response", got)
	}

	tel.ToolCallCompleted(gateway.CompletionEvent{ID: "4", Tool: "read_file"})
	if got := tel.PendingSpans(); got != 0 {
		t.Errorf("pending spans = %d, want 0 after completion", got)
	}
}

func TestAbandonedSpansAreReaped(t *testing.T) {
	// An upstream that never answers must not pin spans open forever in a
	// process meant to run for weeks.
	tel := newForTest(t)

	tel.ToolCallDecided(decision("5", "slow_tool", policy.EffectAllow))
	if got := tel.PendingSpans(); got != 1 {
		t.Fatalf("pending spans = %d, want 1", got)
	}

	// Backdate the span past the TTL rather than waiting SpanTTL.
	tel.mu.Lock()
	tel.spans["5"].started = time.Now().Add(-2 * SpanTTL)
	tel.mu.Unlock()

	tel.expireSpans()

	if got := tel.PendingSpans(); got != 0 {
		t.Errorf("pending spans = %d, want 0 after expiry", got)
	}
	if got := metricValue(t, tel.Registry(), "chokepoint_abandoned_spans_total", nil); got != 1 {
		t.Errorf("abandoned_spans_total = %v, want 1", got)
	}
}

func TestUnscoreableSessionDoesNotPublishAZeroScore(t *testing.T) {
	// 0.0 and "not yet scoreable" are the same number and completely different
	// facts. Publishing the former would render as "definitely safe".
	tel := newForTest(t)

	ev := decision("6", "read_file", policy.EffectAllow)
	ev.Score = 0
	ev.ScoreUnavailable = true
	tel.ToolCallDecided(ev)

	// NaN, not 0: a registered gauge always reports something, and 0 is a real
	// score meaning "nothing suspicious". NaN is Prometheus's "no value" and
	// renders as a gap rather than a reassuring flat line.
	if got := metricValue(t, tel.Registry(), "chokepoint_decomposition_score", nil); !math.IsNaN(got) {
		t.Errorf("decomposition_score = %v, want NaN for an unscoreable session", got)
	}

	// Once scoreable, it publishes.
	scored := decision("7", "read_file", policy.EffectAllow)
	scored.Score = 0.62
	tel.ToolCallDecided(scored)

	if got := metricValue(t, tel.Registry(), "chokepoint_decomposition_score", nil); got != 0.62 {
		t.Errorf("decomposition_score = %v, want 0.62", got)
	}
}

func TestAuditedRulesAreCounted(t *testing.T) {
	tel := newForTest(t)

	ev := decision("8", "write_file", policy.EffectAllow)
	ev.Audited = []string{"watch-writes", "watch-everything"}
	tel.ToolCallDecided(ev)

	for _, rule := range ev.Audited {
		if got := metricValue(t, tel.Registry(), "chokepoint_policy_audits_total",
			map[string]string{"rule": rule}); got != 1 {
			t.Errorf("audits_total{rule=%q} = %v, want 1", rule, got)
		}
	}
}

func TestUpstreamErrorsAreCounted(t *testing.T) {
	tel := newForTest(t)

	tel.ToolCallDecided(decision("9", "read_file", policy.EffectAllow))
	tel.ToolCallCompleted(gateway.CompletionEvent{ID: "9", Tool: "read_file", Errored: true})

	if got := metricValue(t, tel.Registry(), "chokepoint_upstream_errors_total",
		map[string]string{"tool": "read_file"}); got != 1 {
		t.Errorf("upstream_errors_total = %v, want 1", got)
	}
}

func TestTargetsAreNeverMetricLabels(t *testing.T) {
	// Targets are attacker-influenced and unbounded. One series per distinct
	// path is a denial of service against your own monitoring.
	tel := newForTest(t)

	for i := 0; i < 50; i++ {
		ev := decision(fmt.Sprintf("t%d", i), "read_file", policy.EffectAllow)
		ev.Targets = []string{fmt.Sprintf("/srv/data/file-%d", i)}
		tel.ToolCallDecided(ev)
	}

	families, err := tel.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		for _, m := range family.GetMetric() {
			for _, lp := range m.GetLabel() {
				if strings.Contains(lp.GetValue(), "/srv/data/file-") {
					t.Fatalf("metric %s has a target as a label value: %s=%s",
						family.GetName(), lp.GetName(), lp.GetValue())
				}
			}
		}
	}

	// All 50 calls collapse into a single series keyed by tool name.
	if got := metricValue(t, tel.Registry(), "chokepoint_tool_calls_total",
		map[string]string{"tool": "read_file", "effect": "allow"}); got != 50 {
		t.Errorf("tool_calls_total = %v, want 50 in one series", got)
	}
}

func TestMetricsEndpointServes(t *testing.T) {
	tel, err := New(context.Background(), Options{MetricsAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tel.Shutdown(ctx)
	}()

	tel.ToolCallDecided(decision("10", "read_file", policy.EffectAllow))

	addr := tel.server.Addr
	if ln := tel.listenerAddr(); ln != "" {
		addr = ln
	}

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "chokepoint_tool_calls_total") {
		t.Errorf("/metrics body does not contain chokepoint metrics:\n%s", body)
	}
}

func TestPortConflictIsReportedAtStartup(t *testing.T) {
	// An operator who asked for metrics and silently got none believes they
	// have visibility they do not have.
	first, err := New(context.Background(), Options{MetricsAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Shutdown(context.Background()) }()

	addr := first.listenerAddr()
	if addr == "" {
		t.Skip("could not determine bound address")
	}

	if _, err := New(context.Background(), Options{MetricsAddr: addr}); err == nil {
		t.Fatal("expected an error binding an already-used port")
	}
}

func TestDisabledTelemetryIsSafeToUse(t *testing.T) {
	// With neither subsystem configured every method must still be callable:
	// the gateway holds an Observer, not an Option.
	tel, err := New(context.Background(), Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = tel.Shutdown(context.Background()) }()

	tel.ToolCallDecided(decision("11", "read_file", policy.EffectAllow))
	tel.ToolCallCompleted(gateway.CompletionEvent{ID: "11", Tool: "read_file"})

	if tel.Registry() != nil {
		t.Error("registry should be nil when metrics are disabled")
	}
}

func TestConcurrentObservationIsRaceFree(t *testing.T) {
	tel := newForTest(t)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				id := fmt.Sprintf("w%d-%d", worker, j)
				tel.ToolCallDecided(decision(id, "read_file", policy.EffectAllow))
				tel.ToolCallCompleted(gateway.CompletionEvent{
					ID: id, Tool: "read_file", Latency: time.Millisecond,
				})
			}
		}(i)
	}
	wg.Wait()

	if got := tel.PendingSpans(); got != 0 {
		t.Errorf("pending spans = %d, want 0", got)
	}
	if got := metricValue(t, tel.Registry(), "chokepoint_tool_calls_total",
		map[string]string{"tool": "read_file", "effect": "allow"}); got != 800 {
		t.Errorf("tool_calls_total = %v, want 800", got)
	}
}

// Compile-time proof that Telemetry satisfies the gateway's Observer.
var _ gateway.Observer = (*Telemetry)(nil)
