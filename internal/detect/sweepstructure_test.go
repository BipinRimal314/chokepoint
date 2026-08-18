package detect

import (
	"fmt"
	"math"
	"testing"
	"time"
)

// TestSweepStructureTable prints what the score and two candidate structural
// signals do across session shapes the calibration table does not contain.
// Run it with -v to regenerate the tables in docs/single-tool-sweep.md.
//
//	go test ./internal/detect -run SweepStructure -v
//
// It asserts nothing, deliberately. Every shape below is a hypothesis about
// what agents do, written by hand — and a detector evaluated only against
// fixtures its author invented will confirm whatever its author expected. The
// numbers are here to be argued with, not to gate CI.
//
// What the shapes are for: TestCalibrationTable's benign cases all touch three
// targets or fewer and its attack cases all touch sixty, so target count alone
// separates that corpus perfectly. Any signal correlated with breadth scores
// full marks there while proving nothing. These shapes break that correlation
// by holding breadth fixed at sixty and varying only structure.

// The example policy's sweep rule, so the tables can show the consequence
// rather than a number: decomposition_score > 0.45 && session_targets > 25.
const (
	sweepRuleScore   = 0.45
	sweepRuleTargets = 25
)

type sweepShape struct {
	name   string
	benign bool
	note   string
	pairs  [][2]string
}

// rootSpread describes how a session's calls distribute across unrelated
// roots. Nothing here reads the tool name, which is the point: a constant tool
// sequence cannot flatten it the way it flattens novelty, entropy and
// repetition, all three of which are structurally zero for a single-tool
// session.
type rootSpread struct {
	roots         int
	entropy       float64 // normalised Shannon over per-root call counts
	dominantShare float64 // calls in the largest root, over all targeted calls
}

func measureRootSpread(s *Session) rootSpread {
	sum := s.ResourceSummary()
	if len(sum.Roots) == 0 || sum.Calls == 0 {
		return rootSpread{}
	}

	counts := make(map[string]int, len(sum.Roots))
	total, largest := 0, 0
	for _, g := range sum.Roots {
		counts[g.Name] = g.Calls
		total += g.Calls
		if g.Calls > largest {
			largest = g.Calls
		}
	}

	out := rootSpread{roots: len(sum.Roots), dominantShare: float64(largest) / float64(total)}

	// Normalised by log2(roots) so that "spread evenly across however many
	// roots you touched" reads 1.0 regardless of how many that was. Raw
	// Shannon would grow with the root count and be another way of counting
	// roots, which target_breadth already does.
	if len(counts) > 1 {
		var h float64
		for _, c := range counts {
			p := float64(c) / float64(total)
			h -= p * math.Log2(p)
		}
		out.entropy = h / math.Log2(float64(len(counts)))
	}
	return out
}

func sweepSession(pairs [][2]string) *Session {
	s := NewSession(Config{})
	base := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	for i, p := range pairs {
		s.Observe(Call{
			Tool: p[0], Target: p[1], IsToolCall: true,
			At: base.Add(time.Duration(i) * time.Second),
		})
	}
	return s
}

func oneTool(n int, f func(int) string) [][2]string {
	return repeat(n, func(i int) [2]string { return [2]string{"read_file", f(i)} })
}

// sweepShapes holds breadth fixed at sixty distinct targets and varies only
// what the targets look like, so that anything which separates them is
// separating structure rather than counting.
func sweepShapes() []sweepShape {
	return []sweepShape{
		{
			name: "benign/one-project", benign: true,
			note: "read every file in one repo — an ordinary agent task",
			pairs: oneTool(60, func(i int) string {
				dirs := []string{"cmd", "internal", "docs", "test"}
				return fmt.Sprintf("/project/%s/f%02d.go", dirs[i%4], i)
			}),
		},
		{
			name: "benign/project+strays", benign: true,
			note: "one dominant place, two incidental reads elsewhere",
			pairs: oneTool(60, func(i int) string {
				switch i {
				case 17:
					return "/etc/hosts"
				case 41:
					return "/usr/share/ca-certificates/x.crt"
				default:
					return fmt.Sprintf("/project/src/f%02d.go", i)
				}
			}),
		},
		{
			name: "benign/multi-repo", benign: true,
			note: "three checkouts under one work directory",
			pairs: oneTool(60, func(i int) string {
				repos := []string{"/work/api", "/work/web", "/work/shared"}
				return fmt.Sprintf("%s/src/f%02d.go", repos[i%3], i)
			}),
		},
		{
			name: "benign/ci-build", benign: true,
			note: "genuinely spans unrelated roots, evenly",
			pairs: oneTool(60, func(i int) string {
				roots := []string{"/src", "/build", "/cache", "/tmp"}
				return fmt.Sprintf("%s/obj%02d", roots[i%4], i)
			}),
		},
		{
			name: "benign/sysadmin-audit", benign: true,
			note: "reading configuration across the machine, legitimately",
			pairs: oneTool(60, func(i int) string {
				roots := []string{"/etc", "/var", "/usr", "/opt"}
				return fmt.Sprintf("%s/conf%02d", roots[i%4], i)
			}),
		},
		{
			name: "benign/lint-repo", benign: true,
			note: "two tools over one repo — read and rewrite each file",
			pairs: repeat(60, func(i int) [2]string {
				tools := []string{"read_file", "write_file"}
				dirs := []string{"src/api", "src/db", "src/web", "test"}
				return [2]string{tools[i%2], fmt.Sprintf("/work/%s/mod%02d.ts", dirs[i%4], i/2)}
			}),
		},
		{
			name: "attack/one-root-sweep", benign: false,
			note: "the defect: one tool, one place, every target distinct",
			pairs: oneTool(60, func(i int) string {
				return fmt.Sprintf("/srv/data/f%03d", i)
			}),
		},
		{
			name: "attack/multiroot-even", benign: false,
			note: "theft spread across unrelated places",
			pairs: oneTool(60, func(i int) string {
				roots := []string{"/home", "/etc", "/var", "/srv", "/opt", "/root", "/mnt", "/boot"}
				return fmt.Sprintf("%s/item%02d", roots[i%8], i)
			}),
		},
		{
			name: "attack/multiroot-padded", benign: false,
			note: "the same theft, hidden behind reads in one place",
			pairs: oneTool(60, func(i int) string {
				if i%8 == 0 {
					roots := []string{"/home", "/etc", "/var", "/root", "/opt", "/mnt", "/boot", "/usr"}
					return fmt.Sprintf("%s/secret%02d", roots[i/8%8], i)
				}
				return fmt.Sprintf("/srv/data/f%03d", i)
			}),
		},
	}
}

func TestSweepStructureTable(t *testing.T) {
	w := DefaultWeights()

	t.Log("breadth held at 60 distinct targets; only structure varies")
	t.Logf("%-24s %-7s %6s %-8s %6s %8s %8s",
		"shape", "actual", "score", "rule", "roots", "rootEnt", "domShare")
	for _, sh := range sweepShapes() {
		s := sweepSession(sh.pairs)
		a := s.Assess(w)
		r := measureRootSpread(s)

		actual := "attack"
		if sh.benign {
			actual = "benign"
		}
		ruled := "allow"
		if a.Score > sweepRuleScore && s.DistinctTargets() > sweepRuleTargets {
			ruled = "DENY"
		}
		mark := ""
		if (ruled == "DENY") != !sh.benign {
			mark = "  <- wrong"
		}
		t.Logf("%-24s %-7s %6.3f %-8s %6d %8.3f %8.3f%s",
			sh.name, actual, a.Score, ruled, r.roots, r.entropy, r.dominantShare, mark)
	}

	t.Log("")
	t.Log("scale: the score saturates, root spread does not")
	t.Logf("  %6s %6s %8s", "calls", "score", "rootEnt")
	for _, n := range []int{20, 60, 200, 1000, 5000} {
		s := sweepSession(oneTool(n, func(i int) string {
			roots := []string{"/home", "/etc", "/var", "/srv", "/opt", "/root", "/mnt", "/boot"}
			return fmt.Sprintf("%s/item%05d", roots[i%8], i)
		}))
		t.Logf("  %6d %6.3f %8.3f", n, s.Assess(w).Score, measureRootSpread(s).entropy)
	}

	t.Log("")
	t.Log("what padding costs, to push root spread down from 1.000")
	t.Logf("  %6s %6s %8s %8s", "steal", "pad", "rootEnt", "overhead")
	for _, pad := range []int{0, 20, 60, 140, 300} {
		const steal = 20
		s := sweepSession(oneTool(steal+pad, func(i int) string {
			if i < steal {
				roots := []string{"/home", "/etc", "/var", "/root", "/opt"}
				return fmt.Sprintf("%s/secret%02d", roots[i%5], i)
			}
			return fmt.Sprintf("/srv/data/f%04d", i)
		}))
		t.Logf("  %6d %6d %8.3f %7.1fx",
			steal, pad, measureRootSpread(s).entropy, float64(steal+pad)/float64(steal))
	}
}
