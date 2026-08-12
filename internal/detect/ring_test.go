package detect

import (
	"fmt"
	"testing"
	"time"
)

func ringOf(targets ...string) *ring {
	r := &ring{}
	at := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	for i, t := range targets {
		r.push(Call{Tool: "read_file", Target: t, At: at.Add(time.Duration(i) * time.Second)}, 4)
	}
	return r
}

func ringTargets(r *ring) []string {
	var out []string
	for _, c := range r.all() {
		out = append(out, c.Target)
	}
	return out
}

func TestRingKeepsTheNewestCallsInOrder(t *testing.T) {
	r := ringOf("a", "b", "c", "d", "e", "f")

	got := ringTargets(r)
	want := []string{"c", "d", "e", "f"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("retained %v, want %v", got, want)
	}
	if r.n != 4 {
		t.Errorf("n = %d, want 4", r.n)
	}
}

// The logical index is a position in retained history, not a slot in the
// buffer. Once the ring wraps those stop being the same number, and
// ScopeReport.FirstOutOfScope means the former — an off-by-head there would
// report the wrong call as the moment a session left its boundary.
func TestRingIndexIsAPositionInHistoryNotASlot(t *testing.T) {
	r := ringOf("a", "b", "c", "d", "e", "f")

	if r.head == 0 {
		t.Fatalf("test needs a wrapped ring; head = 0")
	}
	for i, c := range r.all() {
		if want := r.at(i); want != c {
			t.Errorf("index %d: all() and at() disagree", i)
		}
	}
	first := true
	for i, c := range r.all() {
		if first && (i != 0 || c.Target != "c") {
			t.Errorf("first yield was (%d, %q), want (0, \"c\")", i, c.Target)
		}
		first = false
	}
}

// Advancing an index does not release anything on its own. If eviction only
// moved head, every path the session had ever touched would stay reachable from
// the backing array for the life of the process — the leak the old copy-down
// eviction existed to avoid, reintroduced by the thing that replaced it.
func TestEvictedSlotsDoNotRetainTheirCall(t *testing.T) {
	r := &ring{}
	at := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 8; i++ {
		r.push(Call{
			Tool:   "read_file",
			Target: fmt.Sprintf("/srv/secret-%d", i),
			At:     at.Add(time.Duration(i) * time.Second),
		}, 8)
	}
	r.dropOldest(5)

	live := map[int]bool{}
	for i := 0; i < r.n; i++ {
		live[(r.head+i)%len(r.buf)] = true
	}
	for slot, c := range r.buf {
		if live[slot] {
			continue
		}
		if c != (Call{}) {
			t.Errorf("evicted slot %d still holds %+v", slot, c)
		}
	}
}

func TestRingGrowsToTheCapThenOverwrites(t *testing.T) {
	r := &ring{}
	const max = 100
	at := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 250; i++ {
		r.push(Call{Tool: "t", Target: fmt.Sprintf("/%d", i), At: at}, max)
		if r.n > max {
			t.Fatalf("after %d pushes: n = %d, over the cap of %d", i+1, r.n, max)
		}
		if len(r.buf) > max {
			t.Fatalf("after %d pushes: buffer grew to %d, over the cap of %d", i+1, len(r.buf), max)
		}
	}

	if r.n != max {
		t.Errorf("n = %d, want %d", r.n, max)
	}
	if got := r.at(0).Target; got != "/150" {
		t.Errorf("oldest retained is %s, want /150", got)
	}
	if got := r.at(r.n - 1).Target; got != "/249" {
		t.Errorf("newest retained is %s, want /249", got)
	}
}

// A short session is the common case, so it must not be charged for the cap.
func TestRingDoesNotAllocateTheCapUpFront(t *testing.T) {
	s := NewSession(Config{})
	s.Observe(Call{Tool: "read_file", Target: "/srv/a", IsToolCall: true})

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls.buf) > ringMinCap {
		t.Errorf("one call allocated a buffer of %d, want at most %d",
			len(s.calls.buf), ringMinCap)
	}
}

func TestWindowEvictionDropsOnlyExpiredCalls(t *testing.T) {
	s := NewSession(Config{Window: 10 * time.Second})
	at := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 20; i++ {
		s.Observe(Call{
			Tool:       "read_file",
			Target:     fmt.Sprintf("/srv/%d", i),
			IsToolCall: true,
			At:         at.Add(time.Duration(i) * time.Second),
		})
	}

	// Last call is at t+19s, so the window covers (t+9s, t+19s]: 11 calls.
	if got := s.Len(); got != 11 {
		t.Errorf("retained %d calls, want 11", got)
	}
	if got := s.calls.at(0).Target; got != "/srv/9" {
		t.Errorf("oldest retained is %s, want /srv/9", got)
	}
}

// Eviction by window and eviction by cap are separate passes over the same
// ring, and a session configured with both hits them on the same call.
func TestWindowAndCapEvictTogether(t *testing.T) {
	s := NewSession(Config{Window: 30 * time.Second, MaxCalls: 5})
	at := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 20; i++ {
		s.Observe(Call{
			Tool:       "read_file",
			Target:     fmt.Sprintf("/srv/%d", i),
			IsToolCall: true,
			At:         at.Add(time.Duration(i) * time.Second),
		})
	}

	if got := s.Len(); got != 5 {
		t.Fatalf("retained %d calls, want 5 (the cap, tighter than the window)", got)
	}
	if got := s.ResourceSummary(); got.Calls != 5 || got.Distinct != 5 {
		t.Errorf("ResourceSummary: Calls=%d Distinct=%d, want 5 and 5", got.Calls, got.Distinct)
	}
}

// BenchmarkObserveAtCapacity is the one BenchmarkObserve deliberately avoids.
//
// It is the reason the ring exists: this benchmark measures a session that has
// already reached MaxCalls and is still being called, which is what a
// long-running agent does for most of its life. Under the old copy-down
// eviction every call here paid an O(n) slide of 10,000 entries.
func BenchmarkObserveAtCapacity(b *testing.B) {
	at := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	s := benchSession(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Observe(Call{
			Tool: "read_file", Target: benchTarget(i), IsToolCall: true,
			At: at.Add(time.Duration(i) * time.Millisecond),
		})
	}
}
