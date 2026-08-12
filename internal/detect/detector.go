package detect

import (
	"sync"
	"time"
)

// Call is one observed MCP request.
type Call struct {
	// Tool is the tool name for tools/call, or the method for other requests.
	Tool string
	// Target identifies what the call acted on — a file path, a host, a
	// resource URI. Empty when the call names no target.
	//
	// This is the field that makes decomposition visible. Ten reads of one
	// file and ten reads of ten files are the same tool with the same
	// argument shape; only the target distinguishes them.
	Target string
	// PayloadBytes is the size of the arguments, plus the result when known.
	PayloadBytes int
	// IsToolCall separates tools/call from resource and prompt requests,
	// which the schema counts as secondary events.
	IsToolCall bool
	// Errored marks a call that failed or was retried, counted as peripheral.
	Errored bool
	// At is when the call was observed.
	At time.Time

	// res is Target normalised, parsed once by Observe.
	//
	// Unexported on purpose: it is a cache, not an input. A caller who could
	// set it could make it disagree with Target, and every containment and
	// grouping decision in this package would then be made against a resource
	// the tool was never called with — the exact failure normalisation exists
	// to prevent. Deriving it at the one point calls enter the session is what
	// makes "res always describes Target" a property rather than a convention.
	res Resource
}

// Config tunes session accounting.
type Config struct {
	// Window bounds how much history a session keeps. Zero means the whole
	// session. A window matters because a long-running agent should not be
	// judged forever on its first minute, and because unbounded history is a
	// memory leak in a process meant to run for weeks.
	Window time.Duration
	// MaxCalls caps retained calls regardless of Window, as a hard memory
	// bound. Zero means DefaultMaxCalls.
	MaxCalls int
	// BusinessHoursStart and End define "normal hours" in the local zone, for
	// the temporal features. Both zero means 9-17.
	BusinessHoursStart int
	BusinessHoursEnd   int
}

// DefaultMaxCalls bounds per-session memory.
const DefaultMaxCalls = 10000

func (c Config) withDefaults() Config {
	if c.MaxCalls <= 0 {
		c.MaxCalls = DefaultMaxCalls
	}
	if c.BusinessHoursStart == 0 && c.BusinessHoursEnd == 0 {
		c.BusinessHoursStart, c.BusinessHoursEnd = 9, 17
	}
	return c
}

// Session accumulates behaviour for one agent connection.
//
// Safe for concurrent use: the proxy's two pumps observe requests and
// responses from separate goroutines.
type Session struct {
	cfg Config

	mu        sync.Mutex
	calls     ring
	startedAt time.Time
}

// NewSession returns a Session ready to observe calls.
func NewSession(cfg Config) *Session {
	return &Session{cfg: cfg.withDefaults()}
}

// Observe records one call.
//
// The target is normalised here rather than at each read. Reports walk the
// retained history repeatedly — ResourceSummary and ScopeReport each parse
// every call they look at — so parsing per call instead of per walk moves the
// work from O(reports x calls) to O(calls), which is what keeps a 10,000-call
// session's report cost in the same place as the score's.
func (s *Session) Observe(c Call) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if c.At.IsZero() {
		c.At = time.Now()
	}
	c.res = ParseResource(c.Target)
	if s.startedAt.IsZero() {
		s.startedAt = c.At
	}

	// The cap is enforced by push, which overwrites the oldest slot rather than
	// letting the buffer exceed it. Only the window needs a separate pass.
	s.calls.push(c, s.cfg.MaxCalls)
	s.evictLocked(c.At)
}

// evictLocked drops history that has fallen outside the window.
func (s *Session) evictLocked(now time.Time) {
	if s.cfg.Window <= 0 {
		return
	}

	cutoff := now.Add(-s.cfg.Window)
	drop := 0
	for drop < s.calls.n && s.calls.at(drop).At.Before(cutoff) {
		drop++
	}
	s.calls.dropOldest(drop)
}

// Len returns the number of retained calls.
func (s *Session) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls.n
}

// Vector computes the UBFS observation for the current window.
//
// The walk happens under the lock rather than over a snapshot. Snapshotting
// used to buy a shorter critical section, but the copy was itself O(n) under
// the same lock and only saved the map work — and once Call carried its parsed
// resource, copying 10,000 of them cost more than the walk it was protecting.
// ResourceSummary and ScopeReport already walk locked; this makes the three
// read paths agree.
func (s *Session) Vector() *Vector {
	s.mu.Lock()
	defer s.mu.Unlock()

	started := s.startedAt

	v := NewVector()
	if s.calls.n == 0 {
		return v
	}

	var (
		toolCounts  = map[string]int{}
		targets     = map[string]struct{}{}
		transitions = map[string]int{}
		payloads    []float64

		toolCalls, secondary, peripheral int
		afterHours                       int
		totalBytes                       int
		prevTool                         string
	)

	// The ring holds its contents as at most two contiguous runs, so the walk is
	// nested rather than flat. That costs about 3% against the old single slice
	// and three shapes were measured trying to avoid it — a range-over-func
	// iterator (+4%, it does not inline across the method boundary), a closure
	// applied per run (+2.6%), and this (+3.3%). They are the same number. The
	// cost is the segmented walk itself, not the way it is spelled, so this is
	// the plainest of the three rather than the fastest.
	//
	// It buys eviction going from 25µs per call to 0.3µs once a session is at
	// MaxCalls, which is where a long-running agent spends its life.
	front, back := s.calls.parts()
	for _, seg := range [2][]Call{front, back} {
		for _, c := range seg {
			if c.IsToolCall {
				toolCalls++
			} else {
				secondary++
			}
			if c.Errored {
				peripheral++
			}

			toolCounts[c.Tool]++
			if c.Target != "" {
				targets[c.Target] = struct{}{}
			}
			if prevTool != "" {
				transitions[prevTool+"\x00"+c.Tool]++
			}
			prevTool = c.Tool

			totalBytes += c.PayloadBytes
			payloads = append(payloads, float64(c.PayloadBytes))

			hour := c.At.Hour()
			if hour < s.cfg.BusinessHoursStart || hour >= s.cfg.BusinessHoursEnd {
				afterHours++
			}
		}
	}

	n := s.calls.n
	last := s.calls.at(n - 1).At

	// TEMPORAL
	v.Set(FeatActivityHourMean, float64(started.Hour()))
	v.Set(FeatSessionDurationNorm, last.Sub(started).Seconds())
	v.Set(FeatAfterHoursRatio, float64(afterHours)/float64(n))
	if wd := started.Weekday(); wd == time.Saturday || wd == time.Sunday {
		v.Set(FeatWeekendActivityFlag, 1)
	}

	// FREQUENCY. event_rate_zscore needs a baseline and stays neutral.
	v.Set(FeatPrimaryEventCount, float64(toolCalls))
	v.Set(FeatSecondaryEventCount, float64(secondary))
	v.Set(FeatPeripheralEventCount, float64(peripheral))

	// VOLUME
	v.Set(FeatDataVolumeNorm, float64(totalBytes))
	v.Set(FeatOutputCountNorm, float64(n))
	v.Set(FeatVolumeVariability, stdDev(payloads))

	// SCOPE
	v.Set(FeatResourceBreadth, float64(len(toolCounts)))
	v.Set(FeatTargetBreadth, float64(len(targets)))
	v.Set(FeatBreadthRatio, float64(len(toolCounts))/float64(n))

	// SEQUENCE
	v.Set(FeatActionEntropy, shannonEntropy(toolCounts))
	v.Set(FeatTransitionNovelty, transitionNovelty(transitions))
	v.Set(FeatRepetitionScore, repetitionScore(toolCounts, n))

	// DEVIATION and PRIVILEGE stay neutral; see coverage.
	return v
}

// DistinctTargets is how many distinct targets the retained history names.
//
// The same number as Vector().Get(FeatTargetBreadth), and it exists because
// that is a very expensive way to ask. The gateway needs this count on every
// gated call, and reaching it through Vector built all twenty features —
// tallying tools, hashing every transition pair, accumulating a payload slice
// and computing a standard deviation — to read one of them. This walk keeps the
// one map it needs.
func (s *Session) DistinctTargets() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	targets := make(map[string]struct{})
	front, back := s.calls.parts()
	for _, seg := range [2][]Call{front, back} {
		for _, c := range seg {
			if c.Target != "" {
				targets[c.Target] = struct{}{}
			}
		}
	}
	return len(targets)
}

// ---------------------------------------------------------------------------
// Decomposition scoring
// ---------------------------------------------------------------------------

// Assessment is a decomposition verdict for a session.
type Assessment struct {
	// Score is in [0,1]; higher means more decomposition-like.
	Score float64
	// Contributions breaks the score down by signal, so an alert can say why.
	// An unexplainable score is not actionable, and a reviewer who cannot see
	// the reasoning cannot overrule it.
	Contributions map[string]float64
	// Calls is how many observations the score is based on.
	Calls int
	// BelowMinimum is true when there is not yet enough history to judge, in
	// which case Score is 0 and must not be read as "safe".
	BelowMinimum bool
}

// Weights tune the decomposition score.
//
// The default weighting follows the paper's characterisation of decomposed
// tasks: broad, shallow, non-repetitive traversal of the tool graph, where
// each individual call is structurally legitimate. Breadth carries the most
// weight because it is the signal hardest to produce accidentally.
type Weights struct {
	TargetBreadth     float64
	TransitionNovelty float64
	ActionEntropy     float64
	LowRepetition     float64
}

// DefaultWeights sum to 1.0.
func DefaultWeights() Weights {
	return Weights{
		TargetBreadth:     0.40,
		TransitionNovelty: 0.25,
		ActionEntropy:     0.20,
		LowRepetition:     0.15,
	}
}

// MinCallsForScore is the smallest history that produces a score.
//
// Below this, breadth and entropy are dominated by how few calls have been
// seen: the first three calls of any session are all novel and all distinct,
// which would score every new agent as maximally suspicious.
const MinCallsForScore = 8

// Assess scores the session for decomposition-like behaviour.
func (s *Session) Assess(w Weights) Assessment {
	v := s.Vector()
	n := s.Len()

	if n < MinCallsForScore {
		return Assessment{Calls: n, BelowMinimum: true, Contributions: map[string]float64{}}
	}

	// Target breadth is saturated rather than used raw: the difference
	// between touching 40 and 80 distinct targets is not twice as suspicious,
	// and an unbounded term would let one long session dominate the score.
	breadth := saturate(v.Get(FeatTargetBreadth), float64(n))
	novelty := clamp01(v.Get(FeatTransitionNovelty))
	entropy := clamp01(v.Get(FeatActionEntropy))
	lowRep := 1 - clamp01(v.Get(FeatRepetitionScore))

	contrib := map[string]float64{
		"target_breadth":     w.TargetBreadth * breadth,
		"transition_novelty": w.TransitionNovelty * novelty,
		"action_entropy":     w.ActionEntropy * entropy,
		"low_repetition":     w.LowRepetition * lowRep,
	}

	var score float64
	for _, c := range contrib {
		score += c
	}

	return Assessment{
		Score:         clamp01(score),
		Contributions: contrib,
		Calls:         n,
	}
}

// saturate maps a count to [0,1] against an expected scale, flattening as it
// grows so that large sessions do not run away with the score.
func saturate(value, scale float64) float64 {
	if scale <= 0 || value <= 0 {
		return 0
	}
	return clamp01(value / scale)
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
