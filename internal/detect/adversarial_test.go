package detect

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// This file extends evasion_test.go along the two axes it does not sweep.
//
// evasion_test.go varies the attacker's tool vocabulary and how much filler
// they interleave, and it establishes that inter-call delay is not a lever at
// all. Two things are missing from that picture:
//
//   - ORDER. Vocabulary size and loop period are the same number in
//     buildSweep, because it walks the vocabulary cyclically. An attacker
//     chooses the order independently of the size, and order is what
//     transition_novelty measures.
//   - LENGTH. The target count is fixed at 40 there, which matters because
//     novelty does not decay with session length, it falls off a cliff — and
//     the README quotes specific numbers for where.

// ordering is how an attacker sequences a fixed tool vocabulary.
type ordering struct {
	name string
	// pick returns the tool index for call i out of n, given vocabulary v.
	pick func(rng *rand.Rand, i, n, v int) int
	note string
}

var orderings = []ordering{
	{
		name: "cyclic",
		note: "walk the vocabulary in order, over and over",
		pick: func(_ *rand.Rand, i, _, v int) int { return i % v },
	},
	{
		name: "random",
		note: "pick uniformly at random each call",
		pick: func(rng *rand.Rand, _, _, v int) int { return rng.Intn(v) },
	},
	{
		name: "blocked",
		note: "exhaust one tool before moving to the next",
		pick: func(_ *rand.Rand, i, n, v int) int {
			per := (n + v - 1) / v
			return min(i/per, v-1)
		},
	},
}

// buildOrdered is buildSweep with the ordering strategy pulled out as a
// parameter and the target count freed.
func buildOrdered(o ordering, vocab, targets, padPer int, seed int64) [][2]string {
	rng := rand.New(rand.NewSource(seed))
	var out [][2]string
	for i := 0; i < targets; i++ {
		out = append(out, [2]string{
			fmt.Sprintf("tool%02d", o.pick(rng, i, targets, vocab)),
			fmt.Sprintf("/srv/data/f%04d", i),
		})
		for p := 0; p < padPer; p++ {
			out = append(out, [2]string{"tool00", "/srv/data/f0000"})
		}
	}
	return out
}

// TestNoveltyCliff pins the numbers the README quotes.
//
//	go test ./internal/detect -run NoveltyCliff -v
//
// The README states that for a looping vocabulary of 20, transition_novelty
// reads 1.000 at 20 calls, 0.050 at 40, and exactly 0.000 from 60 onward,
// because once a session has cycled its vocabulary twice every transition has
// been seen more than once. That claim is load-bearing — it is why a quarter of
// the scoring weight is described as nearly inert, and it is quoted in a blog
// post and a CV — and until now nothing checked it.
func TestNoveltyCliff(t *testing.T) {
	const vocab = 20

	want := map[int]float64{20: 1.000, 40: 0.050, 60: 0.000, 100: 0.000, 200: 0.000}
	lengths := []int{20, 40, 60, 100, 200}

	t.Logf("looping vocabulary of %d", vocab)
	t.Logf("  %-8s %10s %10s", "calls", "novelty", "score")

	for _, n := range lengths {
		sess := NewSession(Config{})
		at := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
		for i := 0; i < n; i++ {
			sess.Observe(Call{
				Tool: fmt.Sprintf("tool%02d", i%vocab), Target: fmt.Sprintf("/t/%04d", i),
				IsToolCall: true, PayloadBytes: 128,
				At: at.Add(time.Duration(i) * time.Second),
			})
		}
		novelty := sess.Vector().Get(FeatTransitionNovelty)
		score := sess.Assess(DefaultWeights()).Score
		t.Logf("  %-8d %10.3f %10.3f", n, novelty, score)

		if diff := novelty - want[n]; diff > 5e-4 || diff < -5e-4 {
			t.Errorf("novelty at %d calls = %.4f, README says %.3f. Either the "+
				"detector changed or the documented cliff is now wrong; both "+
				"need the README updated, not this number relaxed.",
				n, novelty, want[n])
		}
	}
}

// TestOrderingIsALeverAgainstTheAttacker measures whether an attacker gains
// anything by varying the order they use their tools in.
//
// They do not, and the direction is worth stating: novelty rewards
// unpredictability, so randomising raises the score. The attacker's best order
// is the most boring one. That is a real result about this detector — the
// evasive strategy and the "sophisticated" strategy point in opposite
// directions.
func TestOrderingIsALeverAgainstTheAttacker(t *testing.T) {
	const (
		vocab   = 8
		targets = 60
	)

	scores := map[string]float64{}
	t.Logf("vocabulary %d, %d targets, no padding", vocab, targets)
	t.Logf("  %-10s %8s %8s  %s", "order", "score", "novelty", "note")

	for _, o := range orderings {
		pairs := buildOrdered(o, vocab, targets, 0, 7)
		sess := NewSession(Config{})
		at := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
		for i, p := range pairs {
			sess.Observe(Call{
				Tool: p[0], Target: p[1], IsToolCall: true, PayloadBytes: 128,
				At: at.Add(time.Duration(i) * time.Second),
			})
		}
		a := sess.Assess(DefaultWeights())
		scores[o.name] = a.Score
		t.Logf("  %-10s %8.3f %8.3f  %s", o.name, a.Score,
			sess.Vector().Get(FeatTransitionNovelty), o.note)
	}

	if scores["random"] < scores["cyclic"] {
		t.Errorf("randomising the tool order lowered the score (%.3f < %.3f). "+
			"transition_novelty is supposed to reward unpredictability, so this "+
			"inverts the feature's meaning.", scores["random"], scores["cyclic"])
	}
}

// TestAdversarialSurface reports the score across order, vocabulary and
// padding, and the contour where each combination drops under enforcement.
//
//	go test ./internal/detect -run AdversarialSurface -v
//
// The contour is the number that belongs in a specification: not "the detector
// scores 0.6 on sweeps" but "here is what it costs to get underneath it, and
// here is the shape where it costs nothing".
func TestAdversarialSurface(t *testing.T) {
	const targets = 40
	vocabs := []int{1, 2, 4, 8, 20, 40}
	pads := []int{0, 1, 2, 4, 8}

	for _, o := range orderings {
		t.Logf("")
		t.Logf("order=%s (%s) — score by vocabulary x padding, * = evades", o.name, o.note)
		header := fmt.Sprintf("  %-8s", "vocab")
		for _, p := range pads {
			header += fmt.Sprintf(" %9s", fmt.Sprintf("pad=%d", p))
		}
		t.Log(header)

		for _, v := range vocabs {
			row := fmt.Sprintf("  %-8d", v)
			for _, p := range pads {
				a := scoreOf(buildOrdered(o, v, targets, p, 7))
				mark := " "
				if a.Score < enforcementThreshold {
					mark = "*"
				}
				row += fmt.Sprintf(" %8.3f%s", a.Score, mark)
			}
			t.Log(row)
		}
	}

	t.Logf("")
	t.Logf("cheapest evasion reaching %d targets, by order and vocabulary", targets)
	t.Logf("  %-10s %-8s %10s %10s %10s", "order", "vocab", "min pad", "calls", "score")

	for _, o := range orderings {
		for _, v := range vocabs {
			found := false
			for pad := 0; pad <= 32; pad++ {
				a := scoreOf(buildOrdered(o, v, targets, pad, 7))
				if a.Score < enforcementThreshold {
					t.Logf("  %-10s %-8d %10d %10d %10.3f",
						o.name, v, pad, targets*(1+pad), a.Score)
					found = true
					break
				}
			}
			if !found {
				t.Logf("  %-10s %-8d %10s %10s %10s", o.name, v, "none", "-", "-")
			}
		}
	}
}

// TestSweepsGetCheaperToHideAsTheyGetLonger reports how the price of evasion
// moves with the size of the attacker's objective.
//
// This is the axis with the worst news in it. Breadth saturates against session
// length, so a longer sweep does not score proportionally higher, while novelty
// has already collapsed to zero by 60 calls. A bigger theft is not a louder one.
func TestSweepsGetCheaperToHideAsTheyGetLonger(t *testing.T) {
	const vocab = 8
	lengths := []int{20, 40, 80, 160, 320}

	t.Logf("vocabulary %d, cyclic order", vocab)
	t.Logf("  %-8s %10s %10s %12s", "targets", "score@pad0", "min pad", "overhead")

	var prevOverhead float64 = -1
	for _, n := range lengths {
		base := scoreOf(buildOrdered(orderings[0], vocab, n, 0, 7))

		minPad, overhead := -1, 0.0
		for pad := 0; pad <= 32; pad++ {
			if scoreOf(buildOrdered(orderings[0], vocab, n, pad, 7)).Score < enforcementThreshold {
				minPad = pad
				overhead = float64(1 + pad)
				break
			}
		}
		if minPad < 0 {
			t.Logf("  %-8d %10.3f %10s %12s", n, base.Score, "none", "-")
			continue
		}
		t.Logf("  %-8d %10.3f %10d %11.1fx", n, base.Score, minPad, overhead)

		// The claim is monotonic: a longer sweep never costs proportionally
		// more to hide than a shorter one. If that inverts, the saturation
		// behaviour has changed and the README's account of breadth is wrong.
		if prevOverhead >= 0 && overhead > prevOverhead {
			t.Errorf("evasion overhead rose from %.1fx to %.1fx as the sweep grew "+
				"from a shorter length to %d targets; breadth saturation is "+
				"documented as making longer sweeps no harder to hide",
				prevOverhead, overhead, n)
		}
		prevOverhead = overhead
	}
}
