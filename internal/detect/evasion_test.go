package detect

import (
	"fmt"
	"testing"
	"time"
)

// The threshold examples/policy.yaml ships with. Evasion means landing under
// it while still completing the attacker's objective.
const enforcementThreshold = 0.45

// exfilTargets is the attacker's goal: touch this many distinct targets.
//
// The goal is held fixed on purpose. An attacker who gives up targets has not
// evaded the detector, they have been stopped by it. Only a session that still
// reaches every target and scores below the threshold counts as an evasion.
const exfilTargets = 40

// buildSweep constructs a sweep that reaches exfilTargets distinct targets
// using a rotating vocabulary of vocab tools, interleaving padPer filler calls
// after each real one.
//
// Filler repeats one tool against one already-seen target, which is the
// cheapest padding available: it adds no new target, repeats an existing
// transition, and concentrates the tool distribution. That attacks three of
// the four scoring terms at once.
func buildSweep(vocab, padPer int) [][2]string {
	var out [][2]string
	for i := 0; i < exfilTargets; i++ {
		out = append(out, [2]string{
			fmt.Sprintf("tool%02d", i%vocab),
			fmt.Sprintf("/srv/data/f%03d", i),
		})
		for p := 0; p < padPer; p++ {
			out = append(out, [2]string{"tool00", "/srv/data/f000"})
		}
	}
	return out
}

func scoreOf(pairs [][2]string) Assessment {
	sess := NewSession(Config{})
	at := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	for i, p := range pairs {
		sess.Observe(Call{
			Tool: p[0], Target: p[1], IsToolCall: true,
			PayloadBytes: 128, At: at.Add(time.Duration(i) * time.Second),
		})
	}
	return sess.Assess(DefaultWeights())
}

// TestEvasionSurface maps the score across the two levers an attacker actually
// controls, and reports the contour where the score crosses the enforcement
// threshold.
//
//	go test ./internal/detect -run EvasionSurface -v
//
// The calibration table answers "where do we set the threshold". This answers
// the question after it: "what does it cost to get under the threshold we
// set". Both numbers belong in the README, because a detector's honest
// specification includes its price of evasion.
func TestEvasionSurface(t *testing.T) {
	vocabs := []int{1, 2, 4, 8, 20, 40}
	pads := []int{0, 1, 2, 3, 4, 6, 8}

	header := fmt.Sprintf("  %-8s", "vocab")
	for _, p := range pads {
		header += fmt.Sprintf(" %9s", fmt.Sprintf("pad=%d", p))
	}
	t.Log("score surface (marked * where the session evades)")
	t.Log(header)

	for _, v := range vocabs {
		row := fmt.Sprintf("  %-8d", v)
		for _, p := range pads {
			a := scoreOf(buildSweep(v, p))
			mark := " "
			if a.Score < enforcementThreshold {
				mark = "*"
			}
			row += fmt.Sprintf(" %8.3f%s", a.Score, mark)
		}
		t.Log(row)
	}

	// Inter-call delay is deliberately not an axis. Assess weights only
	// target_breadth, transition_novelty, action_entropy and low_repetition,
	// so the temporal features the vector computes (activity_hour_mean,
	// session_duration_norm, after_hours_ratio, weekend_activity_flag) do not
	// reach the decomposition score at all. Spreading a sweep over days moves
	// the vector and not the verdict.
	fast := scoreOf(buildSweep(4, 2))
	slow := NewSession(Config{})
	at := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	for i, p := range buildSweep(4, 2) {
		slow.Observe(Call{
			Tool: p[0], Target: p[1], IsToolCall: true,
			PayloadBytes: 128, At: at.Add(time.Duration(i) * 6 * time.Hour),
		})
	}
	if got := slow.Assess(DefaultWeights()).Score; got != fast.Score {
		t.Errorf("timing changed the score (%.6f vs %.6f); the score is "+
			"documented as timing-independent", got, fast.Score)
	}
	t.Logf("")
	t.Logf("timing is not a lever: same shape at 1s and 6h spacing both score %.3f",
		fast.Score)
}

// TestEvasionCost reports the cheapest evasion per vocabulary size, in the
// only unit an attacker cares about: how many extra calls it costs to reach
// the same targets undetected.
//
// It also pins that cost. A weight change that makes evasion cheaper without
// anyone noticing is exactly the regression this file exists to catch.
func TestEvasionCost(t *testing.T) {
	vocabs := []int{1, 2, 4, 8, 20, 40}

	t.Logf("attacker goal: reach %d distinct targets, score below %.2f",
		exfilTargets, enforcementThreshold)
	t.Logf("  %-8s %10s %10s %10s", "vocab", "min pad", "calls", "score")

	// vocab=1 is reported but excluded from the cost floor: it evades at zero
	// cost for structural reasons that padding has nothing to do with. See
	// TestSingleToolSweepIsUnderThreshold.
	cheapestMulti := -1
	for _, v := range vocabs {
		found := false
		for pad := 0; pad <= 32; pad++ {
			a := scoreOf(buildSweep(v, pad))
			if a.Score < enforcementThreshold {
				calls := exfilTargets * (1 + pad)
				t.Logf("  %-8d %10d %10d %10.3f", v, pad, calls, a.Score)
				if v > 1 && (cheapestMulti < 0 || calls < cheapestMulti) {
					cheapestMulti = calls
				}
				found = true
				break
			}
		}
		if !found {
			t.Logf("  %-8d %10s %10s %10s", v, "none", "-", "-")
		}
	}

	if cheapestMulti < 0 {
		t.Fatal("no multi-tool evasion found anywhere in the swept range; " +
			"either the sweep builder or the scorer has changed shape")
	}

	overhead := float64(cheapestMulti) / float64(exfilTargets)
	t.Logf("")
	t.Logf("cheapest multi-tool evasion: %d calls for %d targets (%.1fx overhead)",
		cheapestMulti, exfilTargets, overhead)

	// Pinned from the measured surface on 2026-07-29. This is a floor, not a
	// target: if a change makes evasion cheaper than this, the detector got
	// weaker and the README's stated cost is now a lie.
	const pinnedCheapestMulti = 80
	if cheapestMulti < pinnedCheapestMulti {
		t.Errorf("multi-tool evasion got cheaper: %d calls, was %d. Either "+
			"justify the regression and re-pin, or restore the lost signal.",
			cheapestMulti, pinnedCheapestMulti)
	}
}

// TestSingleToolSweepIsUnderThreshold pins a known defect.
//
// A session that calls ONE tool against any number of distinct targets scores
// exactly 0.400, forever. Three of the four terms are structurally zero for a
// single-tool sequence: there is one transition and it repeats (novelty 0),
// one symbol in the tool distribution (entropy 0), and maximal tool repetition
// (low_repetition 0). Only target_breadth fires, and it saturates at 1.0, so
// the total is pinned at exactly the breadth weight.
//
// With the shipped weights that ceiling is 0.400 and the shipped threshold is
// 0.45, which means `read_file` across every path on the disk is invisible to
// the detector. That is the most obvious exfiltration pattern there is, and it
// costs the attacker nothing — no padding, no timing, no knowledge of the
// rule.
//
// This test exists so the defect cannot be forgotten and cannot be silently
// fixed without updating the documentation that describes it. When the
// detector gains a signal that survives a single-tool sequence, this test
// fails and forces the README's limitations section to be rewritten with it.
func TestSingleToolSweepIsUnderThreshold(t *testing.T) {
	for _, targets := range []int{20, 40, 500, 5000} {
		sess := NewSession(Config{})
		at := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
		for i := 0; i < targets; i++ {
			sess.Observe(Call{
				Tool: "read_file", Target: fmt.Sprintf("/srv/%06d", i),
				IsToolCall: true, PayloadBytes: 128,
				At: at.Add(time.Duration(i) * time.Second),
			})
		}
		a := sess.Assess(DefaultWeights())

		const ceiling = 0.400
		if diff := a.Score - ceiling; diff > 1e-9 || diff < -1e-9 {
			t.Errorf("single-tool sweep over %d targets scored %.4f, expected "+
				"the %.3f ceiling. If a new signal now fires on single-tool "+
				"sequences, update the README limitations and re-pin.",
				targets, a.Score, ceiling)
		}
		if a.Score >= enforcementThreshold {
			t.Errorf("single-tool sweep over %d targets now scores %.4f, at or "+
				"above the %.2f threshold. The known defect is fixed — say so "+
				"in the README and delete this test.",
				targets, a.Score, enforcementThreshold)
		}
	}
	t.Logf("known defect held: a single-tool sweep scores 0.400 at any scale, "+
		"below the %.2f enforcement threshold", enforcementThreshold)
}
