package telemetry

import (
	"net"

	"github.com/prometheus/client_golang/prometheus"
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
