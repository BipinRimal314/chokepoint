package detect

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Paper data generation. Writes the tables behind the inline-detection
// result to CSV, so a figure is regenerated from the detector rather than
// transcribed from a README that has drifted.
//
//	CHOKEPOINT_PAPER_DATA=/path/to/dir go test ./internal/detect -run PaperData
//
// Off by default: it writes files, and a test that writes files on every CI
// run is a test people learn to distrust.

func paperDataDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("CHOKEPOINT_PAPER_DATA")
	if dir == "" {
		t.Skip("set CHOKEPOINT_PAPER_DATA to a directory to emit paper tables")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	return dir
}

func writeCSV(t *testing.T, dir, name string, rows [][]string) {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.WriteAll(rows); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	w.Flush()
	t.Logf("wrote %s (%d rows)", path, len(rows)-1)
}

// buildSweepN is buildSweep with the target count as a parameter, so the
// score can be measured as a function of attack scale rather than only at
// the fixed exfilTargets the evasion surface uses.
func buildSweepN(vocab, padPer, targets int) [][2]string {
	var out [][2]string
	for i := 0; i < targets; i++ {
		out = append(out, [2]string{
			fmt.Sprintf("tool%02d", i%vocab),
			fmt.Sprintf("/srv/data/f%06d", i),
		})
		for p := 0; p < padPer; p++ {
			out = append(out, [2]string{"tool00", "/srv/data/f000000"})
		}
	}
	return out
}

// TestPaperDataScaleCurve is the central claim, as a curve.
//
// A single-tool sweep scores a constant whatever its size. Three of the four
// weighted terms are structurally zero for a constant tool sequence — one
// transition that repeats, one symbol in the tool distribution, maximal
// repetition — so only target_breadth fires, it saturates, and the total
// pins at exactly the breadth weight.
//
// The consequence is that no threshold separates a 5-target sweep from a
// 20,000-target one. This is not a tuning failure that a better-chosen
// threshold recovers from; the quantity being thresholded does not move.
func TestPaperDataScaleCurve(t *testing.T) {
	dir := paperDataDir(t)

	// Below MinCallsForScore a session is not scoreable at all and reports
	// 0 with BelowMinimum set. That is a third state, not a low score, and
	// the curve records it as such rather than plotting a zero that would
	// read as "measured and unremarkable".
	scales := []int{4, 8, 10, 20, 50, 100, 200, 500, 1000, 5000, 20000}
	vocabs := []int{1, 2, 8, 40}

	rows := [][]string{{
		"targets", "vocab", "calls", "scoreable", "score",
		"target_breadth", "transition_novelty", "action_entropy",
		"low_repetition", "crosses_threshold",
	}}
	for _, n := range scales {
		for _, v := range vocabs {
			a := scoreOf(buildSweepN(v, 0, n))
			score := fmt.Sprintf("%.6f", a.Score)
			crosses := strconv.FormatBool(a.Score >= enforcementThreshold)
			if a.BelowMinimum {
				score, crosses = "", ""
			}
			rows = append(rows, []string{
				strconv.Itoa(n),
				strconv.Itoa(v),
				strconv.Itoa(a.Calls),
				strconv.FormatBool(!a.BelowMinimum),
				score,
				fmt.Sprintf("%.6f", a.Contributions["target_breadth"]),
				fmt.Sprintf("%.6f", a.Contributions["transition_novelty"]),
				fmt.Sprintf("%.6f", a.Contributions["action_entropy"]),
				fmt.Sprintf("%.6f", a.Contributions["low_repetition"]),
				crosses,
			})
		}
	}
	writeCSV(t, dir, "scale_curve.csv", rows)

	// The claim the curve is drawn to support, asserted rather than eyeballed.
	var first float64
	var firstN int
	for _, n := range scales {
		a := scoreOf(buildSweepN(1, 0, n))
		if a.BelowMinimum {
			continue
		}
		if firstN == 0 {
			first, firstN = a.Score, n
			continue
		}
		if diff := a.Score - first; diff > 1e-9 || diff < -1e-9 {
			t.Fatalf("single-tool sweep is no longer scale-invariant: "+
				"n=%d scores %.6f, n=%d scored %.6f",
				n, a.Score, firstN, first)
		}
	}
	if first < enforcementThreshold {
		t.Logf("single-tool sweep scores %.4f at every scale from %d to %d "+
			"targets, and never reaches the %.2f threshold",
			first, firstN, scales[len(scales)-1], enforcementThreshold)
	} else {
		t.Fatalf("premise broken: single-tool sweep now scores %.4f, which "+
			"the %.2f threshold catches", first, enforcementThreshold)
	}
}

// TestPaperDataEvasionSurface re-emits the evasion surface as data.
func TestPaperDataEvasionSurface(t *testing.T) {
	dir := paperDataDir(t)

	vocabs := []int{1, 2, 4, 8, 20, 40}
	pads := []int{0, 1, 2, 3, 4, 6, 8}

	rows := [][]string{{"vocab", "pad", "calls", "score", "evades"}}
	for _, v := range vocabs {
		for _, p := range pads {
			pairs := buildSweep(v, p)
			a := scoreOf(pairs)
			rows = append(rows, []string{
				strconv.Itoa(v),
				strconv.Itoa(p),
				strconv.Itoa(len(pairs)),
				fmt.Sprintf("%.6f", a.Score),
				strconv.FormatBool(a.Score < enforcementThreshold),
			})
		}
	}
	writeCSV(t, dir, "evasion_surface.csv", rows)
}

// TestPaperDataCalibration re-emits the benign/suspicious separation band.
func TestPaperDataCalibration(t *testing.T) {
	dir := paperDataDir(t)

	rows := [][]string{{
		"shape", "class", "score", "target_breadth",
		"transition_novelty", "action_entropy", "low_repetition",
	}}
	for _, s := range calibrationShapes() {
		a := scoreOf(s.build())
		class := "suspicious"
		if s.benign {
			class = "benign"
		}
		rows = append(rows, []string{
			s.name, class,
			fmt.Sprintf("%.6f", a.Score),
			fmt.Sprintf("%.6f", a.Contributions["target_breadth"]),
			fmt.Sprintf("%.6f", a.Contributions["transition_novelty"]),
			fmt.Sprintf("%.6f", a.Contributions["action_entropy"]),
			fmt.Sprintf("%.6f", a.Contributions["low_repetition"]),
		})
	}
	writeCSV(t, dir, "calibration.csv", rows)
}

// TestPaperDataTimingIsNotALever shows the temporal features never reach the
// score: the same sweep spread over seconds and over hours is one number.
func TestPaperDataTimingIsNotALever(t *testing.T) {
	dir := paperDataDir(t)

	spacings := []struct {
		label string
		gap   time.Duration
	}{
		{"1s", time.Second},
		{"1m", time.Minute},
		{"1h", time.Hour},
		{"6h", 6 * time.Hour},
		{"24h", 24 * time.Hour},
	}

	pairs := buildSweep(4, 2)
	rows := [][]string{{"spacing", "span", "score"}}
	var first float64
	for i, s := range spacings {
		sess := NewSession(Config{})
		at := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
		for j, p := range pairs {
			sess.Observe(Call{
				Tool: p[0], Target: p[1], IsToolCall: true,
				PayloadBytes: 128,
				At:           at.Add(time.Duration(j) * s.gap),
			})
		}
		score := sess.Assess(DefaultWeights()).Score
		if i == 0 {
			first = score
		} else if diff := score - first; diff > 1e-9 || diff < -1e-9 {
			t.Fatalf("timing now moves the score: %s gives %.6f, 1s gave %.6f",
				s.label, score, first)
		}
		rows = append(rows, []string{
			s.label,
			(time.Duration(len(pairs)) * s.gap).String(),
			fmt.Sprintf("%.6f", score),
		})
	}
	writeCSV(t, dir, "timing.csv", rows)
	t.Logf("same sweep scores %.4f whether spread over %s or %s",
		first,
		(time.Duration(len(pairs)) * spacings[0].gap),
		(time.Duration(len(pairs)) * spacings[len(spacings)-1].gap))
}
