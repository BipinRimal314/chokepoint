package telemetry

import (
	"net"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"

	"github.com/BipinRimal314/chokepoint/internal/audit"
)

// factory registers each collector as it is built.
//
// The prometheus/promauto package does the same thing, but panics on a
// duplicate registration. That is fine for a package-level global registered
// once at init; it is not fine here, where a Telemetry can legitimately be
// constructed more than once in a test binary. This registers explicitly
// against the instance's own registry instead.
type factory struct {
	reg prometheus.Registerer
}

func promauto(reg prometheus.Registerer) factory {
	return factory{reg: reg}
}

func (f factory) counter(opts prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(opts)
	f.reg.MustRegister(c)
	return c
}

func (f factory) counterVec(opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(opts, labels)
	f.reg.MustRegister(c)
	return c
}

func (f factory) gauge(opts prometheus.GaugeOpts) prometheus.Gauge {
	g := prometheus.NewGauge(opts)
	f.reg.MustRegister(g)
	return g
}

func (f factory) histogramVec(opts prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
	h := prometheus.NewHistogramVec(opts, labels)
	f.reg.MustRegister(h)
	return h
}

// netListen opens the metrics listener.
//
// Wrapped so the bind happens synchronously in New: a port conflict is then
// returned to the caller, instead of being logged from a goroutine moments
// after startup has already reported success.
func netListen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// otelAttrs converts the canonical attribute set into OTel key-values.
//
// The definition lives in the audit package because both the trace exporter and
// the evidence log build from it; this is only the translation into the
// exporter's types.
func otelAttrs(attrs []audit.Attr) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(attrs))
	for _, a := range attrs {
		switch v := a.Value.(type) {
		case string:
			out = append(out, attribute.String(a.Key, v))
		case bool:
			out = append(out, attribute.Bool(a.Key, v))
		case int:
			out = append(out, attribute.Int(a.Key, v))
		case float64:
			out = append(out, attribute.Float64(a.Key, v))
		case []string:
			// Targets land here. They are unbounded and attacker-influenced,
			// which is exactly why they belong on a span and never on a metric
			// label — see TestTargetsAreNeverMetricLabels.
			out = append(out, attribute.StringSlice(a.Key, v))
		}
	}
	return out
}
