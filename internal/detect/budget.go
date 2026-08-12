package detect

import "time"

// DefaultRateWindow is the span the recent-activity counters cover when a
// policy does not set one.
//
// A minute is short enough that a burst is still a burst inside it and long
// enough that an agent doing ordinary work does not look like one. It is a
// default, not a finding: unlike the decomposition threshold there is no
// measured separation band behind this number, because what counts as too fast
// depends entirely on what the agent is for.
const DefaultRateWindow = time.Minute

// WindowCounts is recent activity, for rate rules.
//
// This is deliberately not a token bucket. A bucket decides; these are counts,
// and the policy decides — which keeps the limit in the operator's YAML next to
// every other rule instead of compiled into the binary, and lets a rule combine
// rate with everything else it already knows about the call.
type WindowCounts struct {
	// Calls is how many observed calls fall inside the window.
	Calls int
	// Targets is how many distinct targets they named.
	//
	// The more useful of the two for exfiltration: an agent legitimately
	// retrying one file is fast, and an agent reading two hundred different
	// ones in a minute is a sweep, and Calls alone cannot tell them apart.
	Targets int
	// Truncated is true when the counts are a floor rather than the number:
	// retained history ran out before the window did, so calls the window
	// covers have already been evicted. A rate rule reading a truncated count
	// under-fires, which is why this is reported rather than assumed away.
	Truncated bool
}

// CountsInWindow summarises the calls observed in the d before now.
//
// Walks newest-first and stops at the first call outside the window, so the
// cost is proportional to what the window holds and not to session length.
func (s *Session) CountsInWindow(d time.Duration, now time.Time) WindowCounts {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out WindowCounts
	if d <= 0 || s.calls.n == 0 {
		return out
	}

	cutoff := now.Add(-d)
	targets := make(map[string]struct{})
	reachedEdge := false

	front, back := s.calls.parts()
	// Newest first: the wrapped run holds the most recent calls, so it comes
	// first and each run is walked in reverse.
	for _, seg := range [2][]Call{back, front} {
		for i := len(seg) - 1; i >= 0; i-- {
			c := &seg[i]
			if c.At.Before(cutoff) {
				reachedEdge = true
				break
			}
			out.Calls++
			if c.Target != "" {
				targets[c.Target] = struct{}{}
			}
		}
		if reachedEdge {
			break
		}
	}

	out.Targets = len(targets)
	// Only truncated if history actually ran out *and* something was evicted.
	// A session younger than the window has counted everything there is.
	out.Truncated = !reachedEdge && s.calls.evicted
	return out
}
