package detect

import (
	"fmt"
	"testing"
	"time"
)

func burst(t *testing.T, cfg Config, n int, spacing time.Duration, target func(int) string) (*Session, time.Time) {
	t.Helper()
	s := NewSession(cfg)
	at := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	var last time.Time
	for i := 0; i < n; i++ {
		last = at.Add(time.Duration(i) * spacing)
		s.Observe(Call{Tool: "read_file", Target: target(i), IsToolCall: true, At: last})
	}
	return s, last
}

func distinct(i int) string { return fmt.Sprintf("/srv/data/%d", i) }
func same(int) string       { return "/srv/data/one" }

func TestCountsInWindowCountsOnlyTheWindow(t *testing.T) {
	// 100 calls one second apart; the last is at t+99s.
	s, last := burst(t, Config{}, 100, time.Second, distinct)

	got := s.CountsInWindow(10*time.Second, last)
	// The window covers [t+89s, t+99s]: 11 calls.
	if got.Calls != 11 {
		t.Errorf("Calls = %d, want 11", got.Calls)
	}
	if got.Targets != 11 {
		t.Errorf("Targets = %d, want 11", got.Targets)
	}
	if got.Truncated {
		t.Error("Truncated = true, but nothing was evicted")
	}
}

// Calls and Targets answer different questions, and the difference is the
// whole reason both exist: a retry loop is fast and narrow, a sweep is fast
// and wide, and a rule that can only see the rate cannot separate them.
func TestRetryingOneFileIsNotASweep(t *testing.T) {
	s, last := burst(t, Config{}, 60, time.Second, same)

	got := s.CountsInWindow(time.Minute, last)
	if got.Calls != 60 {
		t.Errorf("Calls = %d, want 60", got.Calls)
	}
	if got.Targets != 1 {
		t.Errorf("Targets = %d, want 1 — 60 reads of one path is one place", got.Targets)
	}
}

func TestCountsInWindowIncludesTheCallBeingEvaluated(t *testing.T) {
	s, last := burst(t, Config{}, 1, time.Second, distinct)

	if got := s.CountsInWindow(time.Minute, last); got.Calls != 1 {
		t.Errorf("Calls = %d, want 1 — the call that completes a burst is the one worth refusing", got.Calls)
	}
}

// A count that silently under-reports is worse than no count, because a rate
// rule reading it fails open while looking like it is enforcing something.
func TestTruncatedMarksACountThatLostHistory(t *testing.T) {
	// Cap of 20, but 100 calls inside the window.
	s, last := burst(t, Config{MaxCalls: 20}, 100, time.Second, distinct)

	got := s.CountsInWindow(time.Hour, last)
	if got.Calls != 20 {
		t.Errorf("Calls = %d, want 20 (the cap)", got.Calls)
	}
	if !got.Truncated {
		t.Error("Truncated = false, but eviction dropped calls the window covers")
	}
}

// A young session has counted everything there is. Reporting it as truncated
// would make every new agent look like it was hiding history.
func TestAYoungSessionIsNotTruncated(t *testing.T) {
	s, last := burst(t, Config{}, 5, time.Second, distinct)

	got := s.CountsInWindow(time.Hour, last)
	if got.Calls != 5 {
		t.Errorf("Calls = %d, want 5", got.Calls)
	}
	if got.Truncated {
		t.Error("Truncated = true for a session that has never evicted")
	}
}

func TestCountsInWindowOnAnEmptyOrDisabledSession(t *testing.T) {
	empty := NewSession(Config{})
	if got := empty.CountsInWindow(time.Minute, time.Now()); got != (WindowCounts{}) {
		t.Errorf("empty session: %+v, want zero", got)
	}

	s, last := burst(t, Config{}, 10, time.Second, distinct)
	if got := s.CountsInWindow(0, last); got != (WindowCounts{}) {
		t.Errorf("zero window: %+v, want zero", got)
	}
}

// The counts have to survive the ring wrapping, which is the state a
// long-running session is permanently in.
func TestCountsInWindowAcrossTheRingWrap(t *testing.T) {
	s, last := burst(t, Config{MaxCalls: 64}, 500, time.Second, distinct)

	s.mu.Lock()
	front, back := s.calls.parts()
	wrapped := len(back) > 0
	s.mu.Unlock()
	if !wrapped {
		t.Fatalf("test needs a wrapped ring; front=%d back=%d", len(front), len(back))
	}

	// Window covers the last 10 seconds: 11 calls, all still retained.
	got := s.CountsInWindow(10*time.Second, last)
	if got.Calls != 11 || got.Targets != 11 {
		t.Errorf("Calls=%d Targets=%d, want 11 and 11", got.Calls, got.Targets)
	}
}

// The walk stops at the window edge rather than at the end of history, so its
// cost tracks the window and not the session.
func BenchmarkCountsInWindow(b *testing.B) {
	s := benchSession(b)
	// benchSession spaces calls 1ms apart, so a 1s window holds ~1000 of 10,000.
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC).
		Add(time.Duration(benchCalls-1) * time.Millisecond)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.CountsInWindow(time.Second, now)
	}
}
