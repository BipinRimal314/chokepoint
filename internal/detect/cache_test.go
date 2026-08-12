package detect

import (
	"testing"
	"time"
)

// The cached resource is only sound while every path that puts a Call into
// s.calls goes through Observe. Nothing in the type system enforces that — a
// future `func (s *Session) Restore([]Call)` or a direct push inside eviction
// would compile fine and produce a session whose reports silently skip calls,
// because an unparsed res is indistinguishable from "this target named no
// resource". These tests are the enforcement.

func TestEveryRetainedCallCarriesItsParsedResource(t *testing.T) {
	s := observe(t, []string{
		"/srv/data/a",
		"file:///srv/data/b",
		`C:\Users\agent\notes.txt`,
		"https://api.example.com/v1/items",
		"/srv/data/../../etc/shadow",
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.calls.all() {
		want := ParseResource(c.Target)
		if c.res != want {
			t.Errorf("call %d (target %q): cached resource %+v, want %+v",
				i, c.Target, c.res, want)
		}
	}
}

// Eviction advances the ring head over the calls it drops, and pushing at the
// cap overwrites a slot in place. Either one dropping the cache would leave the
// oldest surviving calls invisible to every report, which is precisely the
// window an operator investigating a long session is reading.
func TestEvictionPreservesTheParsedResource(t *testing.T) {
	s := NewSession(Config{MaxCalls: 3})
	at := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	for i, tg := range []string{"/a/1", "/a/2", "/b/3", "/b/4", "/c/5"} {
		s.Observe(Call{
			Tool: "read_file", Target: tg, IsToolCall: true,
			At: at.Add(time.Duration(i) * time.Second),
		})
	}

	if got := s.Len(); got != 3 {
		t.Fatalf("retained %d calls, want 3", got)
	}
	// All three survivors must still be countable, not just the ones appended
	// after the last eviction.
	if got := s.ResourceSummary(); got.Calls != 3 || got.Distinct != 3 {
		t.Errorf("after eviction: Calls=%d Distinct=%d, want 3 and 3", got.Calls, got.Distinct)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.calls.all() {
		if c.res.Empty() {
			t.Errorf("survivor %d (target %q) lost its parsed resource", i, c.Target)
		}
	}
}

// A target that names nothing must stay uncounted. Caching makes the two
// reasons a call is skipped — no target, and a target that parses to nothing —
// collapse into one check, so both are pinned here rather than trusted.
func TestTargetlessCallsAreNotResources(t *testing.T) {
	s := observe(t, []string{"/srv/data/a", "", "   ", ".", "/srv/data/b"})

	if got := s.ResourceSummary(); got.Calls != 2 || got.Distinct != 2 {
		t.Errorf("ResourceSummary: Calls=%d Distinct=%d, want 2 and 2", got.Calls, got.Distinct)
	}

	sc, err := NewScope([]string{"/srv/data"})
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	if got := s.ScopeReport(sc); got.Calls != 2 || got.OutOfScope != 0 {
		t.Errorf("ScopeReport: Calls=%d OutOfScope=%d, want 2 and 0", got.Calls, got.OutOfScope)
	}
}
