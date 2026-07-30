package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/BipinRimal314/chokepoint/internal/detect"
	"github.com/BipinRimal314/chokepoint/internal/proxy"
)

// render is the report as a string, which is what a human actually reads.
func render(t *testing.T, g *Gateway, limit int) string {
	t.Helper()
	var b strings.Builder
	if err := g.SessionReport().Render(&b, limit); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return b.String()
}

// sweep drives n single-tool calls at the given path prefix through the gateway.
func sweep(t *testing.T, g *Gateway, prefix string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		intercept(t, g, toolCall(t, i, "read_file", map[string]any{
			"path": fmt.Sprintf("%s/f%03d", prefix, i),
		}))
	}
}

// TestReportSeparatesTwoSessionsThatScoreIdentically is the whole point of the
// arc that started with resource normalisation. The scorer returns the same
// number for a repository scan and an exfiltration crawl; a person reading the
// report is not confused for a moment.
func TestReportSeparatesTwoSessionsThatScoreIdentically(t *testing.T) {
	pol := mustPolicy(t, "default_effect: allow\nworkspace:\n  - /src\nrules: []\n")

	scan := New(Options{Policy: pol, Scope: mustScope(t, pol),
		Detector: detect.NewSession(detect.Config{})})
	sweep(t, scan, "/src/pkg", 40)

	crawl := New(Options{Policy: pol, Scope: mustScope(t, pol),
		Detector: detect.NewSession(detect.Config{})})
	for i := 0; i < 40; i++ {
		root := []string{"/home/u/.ssh", "/etc", "/var/secrets", "/root/.aws"}[i%4]
		intercept(t, crawl, toolCall(t, i, "read_file", map[string]any{
			"path": fmt.Sprintf("%s/f%03d", root, i),
		}))
	}

	if a, b := scan.assess().Score, crawl.assess().Score; a != b {
		t.Fatalf("premise broken: the two sessions no longer score identically (%.4f vs %.4f)", a, b)
	}

	scanOut, crawlOut := render(t, scan, 10), render(t, crawl, 10)

	if !strings.Contains(scanOut, "workspace: 40 of 40 calls inside") {
		t.Errorf("scan report does not say the session stayed in bounds:\n%s", scanOut)
	}
	// The scan's report has no "outside the workspace" table at all, because
	// there is nothing to put in it.
	if strings.Contains(scanOut, "outside the workspace") {
		t.Errorf("scan report has an out-of-scope section it should not:\n%s", scanOut)
	}

	if !strings.Contains(crawlOut, "workspace: 0 of 40 calls inside") {
		t.Errorf("crawl report does not say the session was out of bounds:\n%s", crawlOut)
	}
	for _, want := range []string{"/home", "/etc", "/var", "/root"} {
		if !strings.Contains(crawlOut, want) {
			t.Errorf("crawl report does not name %s:\n%s", want, crawlOut)
		}
	}
	if !strings.Contains(crawlOut, "first left the workspace at call 0") {
		t.Errorf("crawl report does not say when it left:\n%s", crawlOut)
	}

	t.Logf("both scored %.3f\n\nSCAN:\n%s\nCRAWL:\n%s",
		scan.assess().Score, scanOut, crawlOut)
}

func TestReportCountsDenialsByRule(t *testing.T) {
	pol := mustPolicy(t, scopedPolicy)
	g := New(Options{Policy: pol, Scope: mustScope(t, pol),
		Detector: detect.NewSession(detect.Config{})})

	sweep(t, g, "/srv/data/ok", 5)
	for i := 0; i < 3; i++ {
		got := intercept(t, g, toolCall(t, 100+i, "read_file",
			map[string]any{"path": fmt.Sprintf("/etc/secret%d", i)}))
		if got.Decision != proxy.Reject {
			t.Fatalf("out-of-scope call %d was not denied", i)
		}
	}

	rep := g.SessionReport()
	if rep.Denials["outside-workspace"] != 3 {
		t.Errorf("denials = %v, want 3 for outside-workspace", rep.Denials)
	}

	out := render(t, g, 10)
	if !strings.Contains(out, "3 calls denied") {
		t.Errorf("report does not count denials:\n%s", out)
	}
	if !strings.Contains(out, "outside-workspace") {
		t.Errorf("report does not name the rule that denied:\n%s", out)
	}
}

// TestReportDoesNotShowAScoreItDoesNotHave is the same distinction the metrics
// layer makes with NaN. A session below the minimum has no score, and printing
// 0.000 would read as "nothing suspicious" rather than "not yet measured".
func TestReportDoesNotShowAScoreItDoesNotHave(t *testing.T) {
	g := New(Options{Detector: detect.NewSession(detect.Config{})})
	sweep(t, g, "/srv/data", 3)

	out := render(t, g, 10)
	if !strings.Contains(out, "not scoreable") {
		t.Errorf("short session should report no score, got:\n%s", out)
	}
	if strings.Contains(out, "0.000") {
		t.Errorf("short session rendered a score of 0.000, which reads as safe:\n%s", out)
	}
}

// TestReportOmitsScopeWhenNoneWasDeclared pins the counterpart. "0 calls
// outside" would be a clean bill of health for a session nobody set a boundary
// for.
func TestReportOmitsScopeWhenNoneWasDeclared(t *testing.T) {
	g := New(Options{
		Policy:   mustPolicy(t, "default_effect: allow\nrules: []\n"),
		Detector: detect.NewSession(detect.Config{}),
	})
	sweep(t, g, "/home/u/.ssh", 20)

	out := render(t, g, 10)
	if strings.Contains(out, "workspace") {
		t.Errorf("report mentions a workspace that was never declared:\n%s", out)
	}
	// It still says where the session went, which is the part that does not
	// depend on a boundary.
	if !strings.Contains(out, "/home") {
		t.Errorf("report does not say where the session went:\n%s", out)
	}
}

func TestReportBoundsItsTables(t *testing.T) {
	g := New(Options{Detector: detect.NewSession(detect.Config{})})
	for i := 0; i < 60; i++ {
		intercept(t, g, toolCall(t, i, "read_file", map[string]any{
			"path": fmt.Sprintf("/root%02d/f%03d", i, i),
		}))
	}

	out := render(t, g, 10)
	if !strings.Contains(out, "and 50 more") {
		t.Errorf("report did not bound its tables at 10 groups:\n%s", out)
	}

	// A limit of zero means everything, for a caller that wants the full list.
	full := render(t, g, 0)
	if strings.Contains(full, "more") {
		t.Errorf("limit 0 should show every group:\n%s", full)
	}
}

// TestReportIsStableBetweenRuns guards the report against Go's randomised map
// iteration. Two runs of the same session must render byte-identically, or the
// report cannot be diffed — which is most of what makes it useful.
func TestReportIsStableBetweenRuns(t *testing.T) {
	build := func() string {
		pol := mustPolicy(t, scopedPolicy)
		g := New(Options{Policy: pol, Scope: mustScope(t, pol),
			Detector: detect.NewSession(detect.Config{})})
		for i := 0; i < 40; i++ {
			intercept(t, g, toolCall(t, i, "read_file", map[string]any{
				"path": fmt.Sprintf("/root%d/dir%d/f%02d", i%5, i%7, i),
			}))
		}
		return render(t, g, 10)
	}

	first := build()
	for n := 0; n < 20; n++ {
		if got := build(); got != first {
			t.Fatalf("report is not stable between runs:\n--- first ---\n%s\n--- run %d ---\n%s",
				first, n, got)
		}
	}
}

func TestReportTruncatesLongPathsFromTheLeft(t *testing.T) {
	// The distinguishing part of a deep path is its tail, so that is the part
	// worth keeping when a name does not fit the column.
	long := "/very/deeply/nested/directory/structure/that/goes/on/for/a/long/while/final"
	got := truncate(long, 44)
	if len(got) != 44 {
		t.Errorf("truncate produced %d chars, want 44: %q", len(got), got)
	}
	if !strings.HasPrefix(got, "...") {
		t.Errorf("truncate should elide the head, got %q", got)
	}
	if !strings.HasSuffix(got, "final") {
		t.Errorf("truncate dropped the distinguishing tail, got %q", got)
	}
	if short := truncate("/srv/data", 44); short != "/srv/data" {
		t.Errorf("truncate altered a short name: %q", short)
	}
}
