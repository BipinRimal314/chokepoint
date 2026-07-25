package detect

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// TestCalibrationTable prints the decomposition score for a set of session
// shapes. Run it with -v to regenerate the table in the README.
//
//	go test ./internal/detect -run Calibration -v
//
// This exists because a threshold picked without measuring is a guess, and a
// guess in a deny rule is an outage waiting for the right Tuesday. The shapes
// below are the ones an operator has to tell apart, and the numbers are what
// the example policy's thresholds are set from.
func TestCalibrationTable(t *testing.T) {
	shapes := []struct {
		name    string
		build   func() [][2]string
		benign  bool
		comment string
	}{
		{
			name:    "poll-one-file",
			benign:  true,
			comment: "health check re-reading one path",
			build: func() [][2]string {
				return repeat(60, func(int) [2]string { return [2]string{"read_file", "/app/health.json"} })
			},
		},
		{
			name:    "build-pipeline",
			benign:  true,
			comment: "fixed tool sequence over a handful of paths",
			build: func() [][2]string {
				tools := []string{"read_file", "write_file", "exec_test"}
				paths := []string{"/src/a.go", "/src/b.go", "/src/c.go"}
				return repeat(60, func(i int) [2]string {
					return [2]string{tools[i%len(tools)], paths[i/3%len(paths)]}
				})
			},
		},
		{
			name:    "focused-debug",
			benign:  true,
			comment: "several tools, one small area of the tree",
			build: func() [][2]string {
				tools := []string{"read_file", "grep", "stat", "read_file"}
				paths := []string{"/svc/auth/handler.go", "/svc/auth/token.go", "/svc/auth/handler_test.go"}
				return repeat(60, func(i int) [2]string {
					return [2]string{tools[i%len(tools)], paths[i%len(paths)]}
				})
			},
		},
		{
			name:    "cyclic-sweep",
			benign:  false,
			comment: "wide target set, but a predictable tool cycle",
			build: func() [][2]string {
				tools := []string{"read_file", "list_dir", "grep", "stat"}
				return repeat(60, func(i int) [2]string {
					return [2]string{tools[i%len(tools)], fmt.Sprintf("/srv/data/f%03d", i)}
				})
			},
		},
		{
			name:    "randomised-sweep",
			benign:  false,
			comment: "wide target set, unpredictable tool order",
			build: func() [][2]string {
				rng := rand.New(rand.NewSource(42))
				tools := []string{"read_file", "list_dir", "grep", "stat", "http_get"}
				return repeat(60, func(i int) [2]string {
					return [2]string{tools[rng.Intn(len(tools))], fmt.Sprintf("/srv/data/f%03d", i)}
				})
			},
		},
		{
			name:    "exfil-crawl",
			benign:  false,
			comment: "every call a distinct tool and a distinct target",
			build: func() [][2]string {
				return repeat(60, func(i int) [2]string {
					return [2]string{fmt.Sprintf("tool%02d", i%20), fmt.Sprintf("/target/%03d", i)}
				})
			},
		},
	}

	t.Logf("%-18s %8s %8s %8s %8s %8s  %s",
		"shape", "score", "breadth", "novelty", "entropy", "lowRep", "note")

	var worstBenign, bestMalicious = 0.0, 1.0

	for _, s := range shapes {
		sess := NewSession(Config{})
		at := time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC)
		for i, p := range s.build() {
			sess.Observe(Call{
				Tool: p[0], Target: p[1], IsToolCall: true,
				PayloadBytes: 128, At: at.Add(time.Duration(i) * time.Second),
			})
		}
		a := sess.Assess(DefaultWeights())

		t.Logf("%-18s %8.3f %8.3f %8.3f %8.3f %8.3f  %s",
			s.name, a.Score,
			a.Contributions["target_breadth"],
			a.Contributions["transition_novelty"],
			a.Contributions["action_entropy"],
			a.Contributions["low_repetition"],
			s.comment)

		if s.benign && a.Score > worstBenign {
			worstBenign = a.Score
		}
		if !s.benign && a.Score < bestMalicious {
			bestMalicious = a.Score
		}
	}

	t.Logf("")
	t.Logf("highest benign score:     %.3f", worstBenign)
	t.Logf("lowest suspicious score:  %.3f", bestMalicious)
	t.Logf("usable threshold band:    %.3f .. %.3f", worstBenign, bestMalicious)

	// The separation is the whole claim. If the bands ever overlap, no single
	// threshold can serve both, and the example policy is unsafe to ship.
	if bestMalicious <= worstBenign {
		t.Fatalf("no separation: benign reaches %.3f but suspicious drops to %.3f",
			worstBenign, bestMalicious)
	}

	// The example policy's threshold must sit inside the measured band.
	const examplePolicyThreshold = 0.45
	if examplePolicyThreshold <= worstBenign || examplePolicyThreshold >= bestMalicious {
		t.Errorf("examples/policy.yaml threshold %.2f is outside the measured band %.3f..%.3f",
			examplePolicyThreshold, worstBenign, bestMalicious)
	}
}

func repeat(n int, f func(int) [2]string) [][2]string {
	out := make([][2]string, n)
	for i := range out {
		out[i] = f(i)
	}
	return out
}
