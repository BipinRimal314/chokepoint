package gateway

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/BipinRimal314/chokepoint/internal/detect"
	"github.com/BipinRimal314/chokepoint/internal/inventory"
)

// SessionReport is everything the gateway knows about a finished session, in
// one structure.
//
// It exists because a score is not an answer. "0.677" tells a reviewer that
// something looked broad and tells them nothing about what to do, and the two
// sessions most worth telling apart — a repository scan and an exfiltration
// crawl — produce the same number by construction. What separates them is
// where the calls went, so that is what this reports.
//
// Judgement is left to the reader on purpose. The detector's own verdict is
// included, labelled, and bounded by its known limits; the resource and scope
// sections are facts the reader can overrule it with.
type SessionReport struct {
	// Assessment is the detector's verdict, or BelowMinimum when the session
	// was too short to have one.
	Assessment detect.Assessment
	// Resources is where the session went.
	Resources detect.ResourceSummary
	// Scope is where it went relative to where it was sent. Declared is false
	// when no workspace was configured, in which case the rest is empty and
	// means nothing.
	Scope detect.ScopeReport
	// Denials counts calls refused, by rule name.
	Denials map[string]int
	// ToolChanges are tool definitions that changed after the session's first
	// tools/list. Reported before anything else, because a mutated definition
	// re-frames every call made after it.
	ToolChanges []inventory.Change
}

// SessionReport gathers the current state of the session.
func (g *Gateway) SessionReport() SessionReport {
	rep := SessionReport{
		Assessment:  g.assess(),
		Scope:       g.scopeReport(),
		Denials:     g.denialCounts(),
		ToolChanges: g.opts.Inventory.Changes(),
	}
	if g.opts.Detector != nil {
		rep.Resources = g.opts.Detector.ResourceSummary()
	}
	return rep
}

func (g *Gateway) denialCounts() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.denials))
	for rule, n := range g.denials {
		out[rule] = n
	}
	return out
}

// Render writes the report as plain text.
//
// limit bounds how many groups each table shows; zero or less shows all. It is
// bounded because a sweep is exactly the session most worth reporting on and
// exactly the one with thousands of groups, and a report that scrolls past the
// terminal buffer is one nobody reads.
//
// Groups arrive sorted by call count then name, so the output is stable
// between runs and two sessions can be diffed against each other.
func (r SessionReport) Render(w io.Writer, limit int) error {
	var b strings.Builder

	b.WriteString("chokepoint session report\n\n")

	// First, because it changes how everything below should be read.
	if len(r.ToolChanges) > 0 {
		fmt.Fprintf(&b, "  !! %d tool definition(s) changed after the first listing\n",
			len(r.ToolChanges))
		for _, c := range r.ToolChanges {
			fmt.Fprintf(&b, "     %s\n", c)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "  %d calls carried a resource, %d distinct\n",
		r.Resources.Calls, r.Resources.Distinct)

	switch {
	case r.Assessment.BelowMinimum:
		fmt.Fprintf(&b, "  decomposition score: not scoreable (%d of %d calls needed)\n",
			r.Assessment.Calls, detect.MinCallsForScore)
	default:
		fmt.Fprintf(&b, "  decomposition score: %.3f  (%s)\n",
			r.Assessment.Score, contributionLine(r.Assessment.Contributions))
	}

	if len(r.Denials) > 0 {
		fmt.Fprintf(&b, "  %d calls denied:\n", totalOf(r.Denials))
		for _, rule := range sortedByCount(r.Denials) {
			fmt.Fprintf(&b, "    %-32s %d\n", rule, r.Denials[rule])
		}
	}

	// The scope section is omitted rather than shown empty when no workspace
	// was declared. Printing "0 outside" would read as a clean bill of health
	// for a session nobody ever set a boundary for.
	if r.Scope.Declared {
		b.WriteString("\n")
		fmt.Fprintf(&b, "  workspace: %d of %d calls inside\n",
			r.Scope.InScope, r.Scope.Calls)
		if r.Scope.OutOfScope > 0 {
			fmt.Fprintf(&b, "    %d outside, in %d distinct place(s)\n",
				r.Scope.OutOfScope, r.Scope.Distinct)
			if r.Scope.Escaped > 0 {
				fmt.Fprintf(&b, "    %d reached by a path that read as inside the workspace\n",
					r.Scope.Escaped)
			}
			fmt.Fprintf(&b, "    first left the workspace at call %d\n", r.Scope.FirstOutOfScope)
			writeGroups(&b, "outside the workspace", r.Scope.Outside, limit)
		}
	}

	writeGroups(&b, "where it went, by root", r.Resources.Roots, limit)
	writeGroups(&b, "where it went, by directory", r.Resources.Dirs, limit)

	_, err := io.WriteString(w, b.String())
	return err
}

// writeGroups renders one table, or nothing at all when there is nothing to
// say. An empty table is noise that makes the populated ones harder to find.
func writeGroups(b *strings.Builder, title string, groups []detect.Group, limit int) {
	if len(groups) == 0 {
		return
	}
	shown := groups
	if limit > 0 && len(shown) > limit {
		shown = shown[:limit]
	}

	fmt.Fprintf(b, "\n  %s\n", title)
	fmt.Fprintf(b, "    %-44s %7s %9s %6s\n", "", "calls", "distinct", "first")
	for _, g := range shown {
		fmt.Fprintf(b, "    %-44s %7d %9d %6d\n",
			truncate(g.Name, 44), g.Calls, g.Distinct, g.FirstCall)
	}
	if len(groups) > len(shown) {
		fmt.Fprintf(b, "    ... and %d more\n", len(groups)-len(shown))
	}
}

// truncate keeps the tail of an over-long path rather than the head, because
// the distinguishing part of "/srv/data/very/deep/tree/f01" is at the end.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return "..." + s[len(s)-(max-3):]
}

func contributionLine(contrib map[string]float64) string {
	if len(contrib) == 0 {
		return "no contributions"
	}
	keys := make([]string, 0, len(contrib))
	for k := range contrib {
		keys = append(keys, k)
	}
	// By contribution descending, so the term carrying the score reads first.
	sort.Slice(keys, func(i, j int) bool {
		if contrib[keys[i]] != contrib[keys[j]] {
			return contrib[keys[i]] > contrib[keys[j]]
		}
		return keys[i] < keys[j]
	})

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %.3f", k, contrib[k]))
	}
	return strings.Join(parts, ", ")
}

func sortedByCount(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

func totalOf(m map[string]int) int {
	var n int
	for _, v := range m {
		n += v
	}
	return n
}
