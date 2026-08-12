package detect

import (
	"fmt"
	"testing"
	"time"
)

// The per-call cost of the report walks was measured once by hand and then
// written into prose, where nothing can check it and nothing notices when it
// stops being true. These benchmarks are that measurement, committed.
//
// The number that matters is not any one of them in isolation but the ratio:
// the gateway does one Vector, one ResourceSummary-shaped walk and one
// ScopeReport per gated call, so a report walk drifting far above Vector is the
// signal that a read path started doing work Observe should have done once.
//
// Run them with:
//
//	go test ./internal/detect -bench . -benchmem -run '^$'
//
// Nothing in CI asserts on these. A timing threshold on a shared runner fails
// for reasons that have nothing to do with this code, and a flaky gate teaches
// people to ignore it.

const benchCalls = 10000

// benchSession builds a session shaped like the case these walks are worst at:
// a broad sweep, every call landing on a distinct resource, spread over enough
// directories and roots that the grouping maps stay large.
func benchSession(tb testing.TB) *Session {
	tb.Helper()
	s := NewSession(Config{MaxCalls: benchCalls})
	at := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	tools := []string{"read_file", "list_dir", "grep", "stat"}
	for i := 0; i < benchCalls; i++ {
		s.Observe(Call{
			Tool:         tools[i%len(tools)],
			Target:       benchTarget(i),
			PayloadBytes: 128,
			IsToolCall:   true,
			At:           at.Add(time.Duration(i) * time.Millisecond),
		})
	}
	return s
}

// benchTarget mixes the target shapes ParseResource has separate paths for, so
// the cost measured is not the cost of the cheapest one.
func benchTarget(i int) string {
	switch i % 4 {
	case 0:
		return fmt.Sprintf("/srv/data/%02d/f%05d.json", i%50, i)
	case 1:
		return fmt.Sprintf("file:///srv/logs/%02d/l%05d.txt", i%50, i)
	case 2:
		return fmt.Sprintf("https://api.example.com/v1/items/%05d", i)
	default:
		// A traversal, because scope's Escaped check only runs on targets that
		// leave the boundary and it is the branch nobody measures.
		return fmt.Sprintf("/srv/data/../../etc/secrets/s%05d", i)
	}
}

// BenchmarkObserve is the other half of the trade: the parse the read paths no
// longer do has to happen somewhere, and this is where it went.
//
// The session is replaced every benchCalls iterations with the timer stopped.
// Letting it run to the cap instead would measure eviction's copy-down, which
// is O(n) per call once full and would swamp the parse being measured.
func BenchmarkObserve(b *testing.B) {
	at := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	s := NewSession(Config{MaxCalls: benchCalls})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%benchCalls == 0 {
			b.StopTimer()
			s = NewSession(Config{MaxCalls: benchCalls})
			b.StartTimer()
		}
		s.Observe(Call{
			Tool: "read_file", Target: benchTarget(i), IsToolCall: true,
			At: at.Add(time.Duration(i) * time.Millisecond),
		})
	}
}

func BenchmarkVector(b *testing.B) {
	s := benchSession(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Vector()
	}
}

func BenchmarkResourceSummary(b *testing.B) {
	s := benchSession(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.ResourceSummary()
	}
}

func BenchmarkScopeReport(b *testing.B) {
	s := benchSession(b)
	sc, err := NewScope([]string{"/srv/data", "/srv/logs"})
	if err != nil {
		b.Fatalf("NewScope: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.ScopeReport(sc)
	}
}

// BenchmarkDistinctTargets is the cheap read the gateway needs per gated call.
// Compare it against BenchmarkVector: reaching this one number through the full
// feature vector is what the gateway used to do, twice.
func BenchmarkDistinctTargets(b *testing.B) {
	s := benchSession(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.DistinctTargets()
	}
}

func BenchmarkAssess(b *testing.B) {
	s := benchSession(b)
	w := DefaultWeights()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Assess(w)
	}
}
