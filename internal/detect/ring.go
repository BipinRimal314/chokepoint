package detect

import "iter"

// ring is a bounded circular buffer of calls, oldest first.
//
// It exists because eviction used to copy: dropping k calls slid the remaining
// ones down the slice, so a session parked at MaxCalls paid O(n) on every
// single call it observed for the rest of its life. A long-running agent is
// exactly the case that reaches the cap, and it is the case where the copy is
// most expensive, so the cost arrived precisely where it was least affordable.
// Advancing an index instead makes eviction O(k) in what actually leaves.
//
// Not safe for concurrent use. Session owns the lock; this type stays free of
// one so the three read paths can walk it inside the lock they already hold.
type ring struct {
	buf  []Call
	head int // index of the oldest retained call
	n    int // how many are retained
}

// ringMinCap is the first allocation, sized so that short sessions — the
// overwhelming majority — never grow at all.
//
// The cap is not allocated up front. DefaultMaxCalls is 10,000 and a Call is
// not small, so reserving the ceiling would charge every session that makes
// three calls for a sweep it is never going to attempt.
const ringMinCap = 16

// push appends a call, evicting the oldest once the buffer is at max.
func (r *ring) push(c Call, max int) {
	if max <= 0 {
		return
	}
	if r.n == len(r.buf) && len(r.buf) < max {
		r.grow(max)
	}

	if r.n == len(r.buf) {
		// At the cap. Overwriting the oldest slot both evicts it and drops the
		// evicted call's strings in one assignment, so nothing extra is needed
		// to keep them from being retained.
		r.buf[r.head] = c
		r.head = r.next(r.head)
		return
	}

	r.buf[(r.head+r.n)%len(r.buf)] = c
	r.n++
}

// grow doubles the buffer, up to max, and re-lays the contents from index 0.
func (r *ring) grow(max int) {
	size := len(r.buf) * 2
	if size < ringMinCap {
		size = ringMinCap
	}
	if size > max {
		size = max
	}

	buf := make([]Call, size)
	for i := 0; i < r.n; i++ {
		buf[i] = r.buf[(r.head+i)%len(r.buf)]
	}
	r.buf, r.head = buf, 0
}

// dropOldest evicts the k oldest calls.
func (r *ring) dropOldest(k int) {
	if k <= 0 {
		return
	}
	if k > r.n {
		k = r.n
	}

	for i := 0; i < k; i++ {
		// Zeroed, not merely skipped. A ring that only advanced its index would
		// leave every evicted call's Target and Resource reachable from the
		// backing array, so a session that evicted for a week would hold the
		// strings of every path it had ever touched — the same leak the old
		// copy-down eviction was written to avoid, reintroduced by the fix.
		r.buf[(r.head+i)%len(r.buf)] = Call{}
	}

	r.head = (r.head + k) % len(r.buf)
	r.n -= k
}

func (r *ring) next(i int) int {
	i++
	if i == len(r.buf) {
		return 0
	}
	return i
}

// at returns the i'th oldest call. Panics outside [0,n), like a slice index.
func (r *ring) at(i int) *Call {
	if i < 0 || i >= r.n {
		panic("detect: ring index out of range")
	}
	return &r.buf[(r.head+i)%len(r.buf)]
}

// parts returns the retained calls as at most two contiguous runs, oldest
// first: everything from head to the end of the buffer, then the wrapped
// remainder from the start.
//
// This is what keeps the read paths off the modulo. Indexing each element as
// buf[(head+i)%len(buf)] measured +5.5% on Vector and +2.5% on ScopeReport,
// which the gateway pays three Vectors and one ScopeReport of per gated call —
// far more than the 24.9µs the ring saves on Observe. Walking two plain slices
// gives the same order with the same arithmetic the old flat slice had.
func (r *ring) parts() (front, back []Call) {
	if r.n == 0 {
		return nil, nil
	}
	end := r.head + r.n
	if end <= len(r.buf) {
		return r.buf[r.head:end], nil
	}
	return r.buf[r.head:], r.buf[:end-len(r.buf)]
}

// all iterates oldest first, yielding the logical index alongside each call.
//
// The index is what the reports mean by "when did this start" — it is a
// position in retained history, not a slot in the buffer, and the two stopped
// being the same thing when this became a ring.
//
// Calls are yielded by pointer to avoid copying each one per walk. Callers must
// not retain the pointer past the iteration: the slot it addresses is reused
// once the call is evicted.
func (r *ring) all() iter.Seq2[int, *Call] {
	return func(yield func(int, *Call) bool) {
		front, back := r.parts()
		for i := range front {
			if !yield(i, &front[i]) {
				return
			}
		}
		for i := range back {
			if !yield(len(front)+i, &back[i]) {
				return
			}
		}
	}
}
