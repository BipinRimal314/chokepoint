package detect

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"
)

var base = time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC) // a Saturday-safe weekday

func call(tool, target string, at time.Time) Call {
	return Call{Tool: tool, Target: target, IsToolCall: true, PayloadBytes: 100, At: at}
}

// feed builds a session from a sequence of (tool, target) pairs one second apart.
func feed(t *testing.T, cfg Config, pairs [][2]string) *Session {
	t.Helper()
	s := NewSession(cfg)
	for i, p := range pairs {
		s.Observe(call(p[0], p[1], base.Add(time.Duration(i)*time.Second)))
	}
	return s
}

func TestVectorIsEmptyWithNoCalls(t *testing.T) {
	v := NewSession(Config{}).Vector()
	for _, f := range FeatureOrder {
		if v.Get(f) != 0 {
			t.Errorf("%s = %v, want 0 for an empty session", f, v.Get(f))
		}
	}
}

func TestSliceMatchesSchemaLength(t *testing.T) {
	// The Python UBFS vector is 20-dimensional; a model trained there will
	// reject anything else.
	if got := len(NewVector().Slice()); got != 20 {
		t.Fatalf("vector length = %d, want 20", got)
	}
	if got := len(FeatureOrder); got != 20 {
		t.Fatalf("FeatureOrder length = %d, want 20", got)
	}
}

func TestEveryFeatureHasCategoryAndCoverage(t *testing.T) {
	for _, f := range FeatureOrder {
		if _, ok := CategoryOf[f]; !ok {
			t.Errorf("%s has no category", f)
		}
		if _, ok := coverage[f]; !ok {
			t.Errorf("%s has no coverage entry", f)
		}
	}
}

func TestUnobservableFeaturesStayNeutralAndSayWhy(t *testing.T) {
	s := feed(t, Config{}, [][2]string{
		{"read", "a"}, {"read", "b"}, {"write", "c"}, {"list", "d"},
		{"read", "e"}, {"grep", "f"}, {"read", "g"}, {"write", "h"},
	})
	v := s.Vector()

	// These cannot be computed from MCP traffic and must not be invented.
	for _, f := range []Feature{FeatEventRateZScore, FeatPeerDistance, FeatSelfDeviation, FeatPrivilegeDeviationIndex} {
		if v.Get(f) != 0 {
			t.Errorf("%s = %v, want neutral 0.0", f, v.Get(f))
		}
	}

	cov := v.Coverage()
	if got := cov[FeatPrivilegeDeviationIndex]; got == "" {
		t.Error("privilege_deviation_index has no coverage explanation")
	}
	for _, f := range []Feature{FeatPeerDistance, FeatSelfDeviation, FeatEventRateZScore} {
		if got := cov[f]; got == "" || got[:7] != "neutral" {
			t.Errorf("%s coverage = %q, want it flagged as neutral", f, got)
		}
	}
}

func TestScopeAndSequenceFeaturesOnRepetitiveWork(t *testing.T) {
	// One tool, one target, over and over: the shape of a legitimate loop.
	pairs := make([][2]string, 20)
	for i := range pairs {
		pairs[i] = [2]string{"read_file", "/app/config.yaml"}
	}
	v := feed(t, Config{}, pairs).Vector()

	if got := v.Get(FeatResourceBreadth); got != 1 {
		t.Errorf("resource_breadth = %v, want 1", got)
	}
	if got := v.Get(FeatTargetBreadth); got != 1 {
		t.Errorf("target_breadth = %v, want 1", got)
	}
	if got := v.Get(FeatActionEntropy); got != 0 {
		t.Errorf("action_entropy = %v, want 0 for a single action", got)
	}
	if got := v.Get(FeatRepetitionScore); got < 0.9 {
		t.Errorf("repetition_score = %v, want near 1", got)
	}
	if got := v.Get(FeatTransitionNovelty); got != 0 {
		t.Errorf("transition_novelty = %v, want 0 when one edge repeats", got)
	}
}

func TestScopeAndSequenceFeaturesOnDecomposedWork(t *testing.T) {
	// Many tools, each target touched once: the shape the paper describes as
	// decomposed — every call individually legitimate, the breadth is the tell.
	pairs := [][2]string{
		{"read_file", "/etc/passwd"}, {"list_dir", "/home"}, {"grep", "/var/log/auth"},
		{"read_file", "/home/a/.ssh/config"}, {"http_get", "api.internal"},
		{"list_dir", "/opt"}, {"read_file", "/srv/secrets.env"}, {"grep", "/var/log/sys"},
		{"http_get", "metadata.google"}, {"read_file", "/root/.bashrc"},
	}
	v := feed(t, Config{}, pairs).Vector()

	if got := v.Get(FeatTargetBreadth); got != 10 {
		t.Errorf("target_breadth = %v, want 10", got)
	}
	if got := v.Get(FeatActionEntropy); got < 0.8 {
		t.Errorf("action_entropy = %v, want high for varied actions", got)
	}
	if got := v.Get(FeatTransitionNovelty); got < 0.8 {
		t.Errorf("transition_novelty = %v, want high when edges are unique", got)
	}
	// repetition_score maps to the schema's `tool_repetition_rate`, so it is
	// measured over tool *names*, not targets. A decomposed sweep reuses a
	// small toolset across many distinct targets and therefore still shows
	// moderate tool repetition — it must simply be below the 1.0 of a truly
	// repetitive loop. target_breadth above is what actually separates them.
	if got := v.Get(FeatRepetitionScore); got >= 0.75 {
		t.Errorf("repetition_score = %v, want below a fully repetitive loop", got)
	}
}

func TestDecompositionScoreSeparatesTheTwoShapes(t *testing.T) {
	// This is the claim the project rests on: a sequence of individually
	// innocuous calls that together sweep a system must score higher than a
	// repetitive legitimate workload of the same length.
	repetitive := make([][2]string, 20)
	for i := range repetitive {
		repetitive[i] = [2]string{"read_file", "/app/config.yaml"}
	}

	decomposed := make([][2]string, 20)
	tools := []string{"read_file", "list_dir", "grep", "http_get", "stat"}
	for i := range decomposed {
		decomposed[i] = [2]string{tools[i%len(tools)], fmt.Sprintf("/target/%d", i)}
	}

	rep := feed(t, Config{}, repetitive).Assess(DefaultWeights())
	dec := feed(t, Config{}, decomposed).Assess(DefaultWeights())

	if rep.BelowMinimum || dec.BelowMinimum {
		t.Fatal("both sessions should exceed the minimum call count")
	}
	if dec.Score <= rep.Score {
		t.Fatalf("decomposed score %.3f should exceed repetitive %.3f", dec.Score, rep.Score)
	}
	if dec.Score < 0.5 {
		t.Errorf("decomposed score %.3f is too low to trip a useful threshold", dec.Score)
	}
	if rep.Score > 0.3 {
		t.Errorf("repetitive score %.3f is high enough to cause false alarms", rep.Score)
	}
}

func TestShortSessionsAreNotScored(t *testing.T) {
	// The first few calls of any session are all novel and all distinct;
	// scoring them would flag every new agent.
	s := feed(t, Config{}, [][2]string{
		{"read", "a"}, {"list", "b"}, {"grep", "c"},
	})
	a := s.Assess(DefaultWeights())

	if !a.BelowMinimum {
		t.Error("a 3-call session should be below the minimum")
	}
	if a.Score != 0 {
		t.Errorf("score = %v, want 0 when below minimum", a.Score)
	}
}

func TestScoreIsExplainable(t *testing.T) {
	pairs := make([][2]string, 12)
	for i := range pairs {
		pairs[i] = [2]string{fmt.Sprintf("tool%d", i%4), fmt.Sprintf("t%d", i)}
	}
	a := feed(t, Config{}, pairs).Assess(DefaultWeights())

	want := []string{"target_breadth", "transition_novelty", "action_entropy", "low_repetition"}
	for _, k := range want {
		if _, ok := a.Contributions[k]; !ok {
			t.Errorf("missing contribution %q; an unexplainable score is not actionable", k)
		}
	}

	var sum float64
	for _, v := range a.Contributions {
		sum += v
	}
	if math.Abs(sum-a.Score) > 1e-9 {
		t.Errorf("contributions sum to %v but score is %v", sum, a.Score)
	}
}

func TestScoreStaysInRange(t *testing.T) {
	// Adversarial shape: every call a unique tool and a unique target.
	pairs := make([][2]string, 200)
	for i := range pairs {
		pairs[i] = [2]string{fmt.Sprintf("tool%d", i), fmt.Sprintf("target%d", i)}
	}
	a := feed(t, Config{}, pairs).Assess(DefaultWeights())

	if a.Score < 0 || a.Score > 1 {
		t.Fatalf("score = %v, want within [0,1]", a.Score)
	}
}

func TestWindowEvictsOldCalls(t *testing.T) {
	s := NewSession(Config{Window: 10 * time.Second})
	for i := 0; i < 30; i++ {
		s.Observe(call("read", "x", base.Add(time.Duration(i)*time.Second)))
	}
	// Only calls within the trailing 10s of the last observation survive.
	if got := s.Len(); got > 11 {
		t.Errorf("retained %d calls, want at most 11 within the window", got)
	}
}

func TestMaxCallsBoundsMemory(t *testing.T) {
	s := NewSession(Config{MaxCalls: 50})
	for i := 0; i < 500; i++ {
		s.Observe(call("read", fmt.Sprintf("t%d", i), base.Add(time.Duration(i)*time.Second)))
	}
	if got := s.Len(); got != 50 {
		t.Errorf("retained %d calls, want 50", got)
	}
}

func TestAfterHoursRatio(t *testing.T) {
	s := NewSession(Config{BusinessHoursStart: 9, BusinessHoursEnd: 17})
	midnight := time.Date(2026, 7, 25, 2, 0, 0, 0, time.UTC)
	midday := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)

	s.Observe(call("read", "a", midnight))
	s.Observe(call("read", "b", midnight))
	s.Observe(call("read", "c", midday))
	s.Observe(call("read", "d", midday))

	if got := s.Vector().Get(FeatAfterHoursRatio); math.Abs(got-0.5) > 1e-9 {
		t.Errorf("after_hours_ratio = %v, want 0.5", got)
	}
}

func TestSecondaryAndPeripheralCounts(t *testing.T) {
	s := NewSession(Config{})
	s.Observe(Call{Tool: "tools/call", IsToolCall: true, At: base})
	s.Observe(Call{Tool: "resources/read", IsToolCall: false, At: base})
	s.Observe(Call{Tool: "tools/call", IsToolCall: true, Errored: true, At: base})

	v := s.Vector()
	if got := v.Get(FeatPrimaryEventCount); got != 2 {
		t.Errorf("primary = %v, want 2", got)
	}
	if got := v.Get(FeatSecondaryEventCount); got != 1 {
		t.Errorf("secondary = %v, want 1", got)
	}
	if got := v.Get(FeatPeripheralEventCount); got != 1 {
		t.Errorf("peripheral = %v, want 1", got)
	}
}

func TestVectorRejectsNaNAndInf(t *testing.T) {
	// A NaN would propagate into every downstream comparison and silently
	// make each one false.
	v := NewVector()
	v.Set(FeatActionEntropy, math.NaN())
	v.Set(FeatTargetBreadth, math.Inf(1))

	if math.IsNaN(v.Get(FeatActionEntropy)) {
		t.Error("NaN was stored")
	}
	if math.IsInf(v.Get(FeatTargetBreadth), 0) {
		t.Error("Inf was stored")
	}
}

func TestEntropyIsNormalisedAcrossVocabularySizes(t *testing.T) {
	// Three tools used evenly and thirty used evenly are both "maximally
	// varied"; an unnormalised entropy would rank the second far higher and
	// make any threshold workload-specific.
	small := map[string]int{"a": 10, "b": 10, "c": 10}
	large := map[string]int{}
	for i := 0; i < 30; i++ {
		large[fmt.Sprintf("t%d", i)] = 10
	}

	if got := shannonEntropy(small); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("small entropy = %v, want 1.0", got)
	}
	if got := shannonEntropy(large); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("large entropy = %v, want 1.0", got)
	}
	if got := shannonEntropy(map[string]int{"only": 5}); got != 0 {
		t.Errorf("single-action entropy = %v, want 0", got)
	}
}

func TestConcurrentObserveIsRaceFree(t *testing.T) {
	// The proxy's two pumps observe from separate goroutines.
	s := NewSession(Config{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.Observe(call("read", fmt.Sprintf("t%d-%d", id, j), base))
				_ = s.Vector()
			}
		}(i)
	}
	wg.Wait()

	if got := s.Len(); got != 800 {
		t.Errorf("observed %d calls, want 800", got)
	}
}
