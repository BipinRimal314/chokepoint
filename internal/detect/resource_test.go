package detect

import (
	"fmt"
	"testing"
	"time"
)

func TestParseResourceNormalises(t *testing.T) {
	cases := []struct {
		raw    string
		scheme string
		host   string
		path   string
		dir    string
		root   string
	}{
		// Bare paths.
		{"/srv/data/f01", "file", "", "/srv/data/f01", "/srv/data", "/srv"},
		{"/srv/data/", "file", "", "/srv/data", "/srv", "/srv"},
		{"/srv//data///f01", "file", "", "/srv/data/f01", "/srv/data", "/srv"},
		{"/srv/./data/f01", "file", "", "/srv/data/f01", "/srv/data", "/srv"},
		{"  /srv/data/f01  ", "file", "", "/srv/data/f01", "/srv/data", "/srv"},
		{"/", "file", "", "/", "/", "/"},

		// Relative paths stay relative: there is no working directory here to
		// resolve them against, and guessing one would be confidently wrong.
		{"src/main.go", "file", "", "src/main.go", "src", "src"},

		// URIs.
		{"file:///etc/passwd", "file", "", "/etc/passwd", "/etc", "file:///etc"},
		{"https://api.example.com/v1/users", "https", "api.example.com",
			"/v1/users", "/v1", "https://api.example.com"},
		{"HTTPS://API.Example.COM/v1", "https", "api.example.com",
			"/v1", "/", "https://api.example.com"},

		// Windows paths fold to forward slashes, drive kept as the root so
		// C: and D: do not merge.
		{`C:\Users\bipin\.ssh\id_rsa`, "file", "", "/Users/bipin/.ssh/id_rsa",
			"/Users/bipin/.ssh", "C:"},
	}

	for _, c := range cases {
		got := ParseResource(c.raw)
		if got.Scheme != c.scheme || got.Host != c.host || got.Path != c.path ||
			got.Dir != c.dir || got.Root != c.root {
			t.Errorf("ParseResource(%q)\n  got  scheme=%q host=%q path=%q dir=%q root=%q\n  want scheme=%q host=%q path=%q dir=%q root=%q",
				c.raw, got.Scheme, got.Host, got.Path, got.Dir, got.Root,
				c.scheme, c.host, c.path, c.dir, c.root)
		}
		if got.Raw != c.raw {
			t.Errorf("ParseResource(%q) did not preserve Raw, got %q", c.raw, got.Raw)
		}
	}
}

// TestTraversalIsResolved is the security-relevant case.
//
// Step 2 of this work compares observed resources against a declared working
// set. If "/src/../home/u/.ssh/id_rsa" is still recorded as living under
// /src, every scope rule is one "../" away from useless. Normalisation has to
// happen before anything compares targets, which is why it lives here rather
// than in the policy layer.
func TestTraversalIsResolved(t *testing.T) {
	cases := []struct{ raw, wantPath, wantRoot string }{
		{"/src/../home/u/.ssh/id_rsa", "/home/u/.ssh/id_rsa", "/home"},
		{"/src/lib/../../etc/shadow", "/etc/shadow", "/etc"},
		{"/src/./../../../../etc/passwd", "/etc/passwd", "/etc"},
		{"/../etc/passwd", "/etc/passwd", "/etc"},
		{`/src\..\home\u\.aws`, "/home/u/.aws", "/home"},
	}
	for _, c := range cases {
		got := ParseResource(c.raw)
		if got.Path != c.wantPath || got.Root != c.wantRoot {
			t.Errorf("traversal not resolved for %q: got path=%q root=%q, want path=%q root=%q",
				c.raw, got.Path, got.Root, c.wantPath, c.wantRoot)
		}
	}
}

func TestParseResourceEmpty(t *testing.T) {
	for _, raw := range []string{"", "   ", "."} {
		if got := ParseResource(raw); got.Path != "" || got.Root != "" {
			t.Errorf("ParseResource(%q) should yield no resource, got %+v", raw, got)
		}
	}
}

func observe(t *testing.T, targets []string) *Session {
	t.Helper()
	s := NewSession(Config{})
	at := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	for i, tg := range targets {
		s.Observe(Call{
			Tool: "read_file", Target: tg, IsToolCall: true,
			PayloadBytes: 128, At: at.Add(time.Duration(i) * time.Second),
		})
	}
	return s
}

func TestResourceSummaryCountsAndGroups(t *testing.T) {
	s := observe(t, []string{
		"/srv/data/a", "/srv/data/b", "/srv/data/a", // 3 calls, 2 distinct
		"/srv/logs/x",
		"/etc/passwd",
	})
	got := s.ResourceSummary()

	if got.Calls != 5 {
		t.Errorf("Calls = %d, want 5", got.Calls)
	}
	if got.Distinct != 4 {
		t.Errorf("Distinct = %d, want 4", got.Distinct)
	}

	wantDirs := []Group{
		{Name: "/srv/data", Calls: 3, Distinct: 2, FirstCall: 0},
		{Name: "/etc", Calls: 1, Distinct: 1, FirstCall: 4},
		{Name: "/srv/logs", Calls: 1, Distinct: 1, FirstCall: 3},
	}
	if len(got.Dirs) != len(wantDirs) {
		t.Fatalf("Dirs = %+v, want %d entries", got.Dirs, len(wantDirs))
	}
	for i, w := range wantDirs {
		if got.Dirs[i] != w {
			t.Errorf("Dirs[%d] = %+v, want %+v", i, got.Dirs[i], w)
		}
	}

	wantRoots := []Group{
		{Name: "/srv", Calls: 4, Distinct: 3, FirstCall: 0},
		{Name: "/etc", Calls: 1, Distinct: 1, FirstCall: 4},
	}
	for i, w := range wantRoots {
		if got.Roots[i] != w {
			t.Errorf("Roots[%d] = %+v, want %+v", i, got.Roots[i], w)
		}
	}
}

// TestResourceSummaryDedupesAcrossSpellings is the payoff for normalising:
// four spellings of one file must count as one resource, not four.
func TestResourceSummaryDedupesAcrossSpellings(t *testing.T) {
	s := observe(t, []string{
		"/srv/data/f01",
		"/srv/data/./f01",
		"/srv//data/f01",
		"/srv/other/../data/f01",
	})
	got := s.ResourceSummary()
	if got.Calls != 4 {
		t.Errorf("Calls = %d, want 4", got.Calls)
	}
	if got.Distinct != 1 {
		t.Errorf("Distinct = %d, want 1 — four spellings of one file", got.Distinct)
	}
}

// TestResourceSummaryIsStable guards the report against Go's randomised map
// iteration. An unstable report cannot be diffed between sessions, which is
// most of what makes it useful.
func TestResourceSummaryIsStable(t *testing.T) {
	targets := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		targets = append(targets, fmt.Sprintf("/root%d/dir%d/f%02d", i%4, i%7, i))
	}
	first := observe(t, targets).ResourceSummary()
	for n := 0; n < 20; n++ {
		got := observe(t, targets).ResourceSummary()
		if len(got.Dirs) != len(first.Dirs) || len(got.Roots) != len(first.Roots) {
			t.Fatalf("summary shape changed between runs")
		}
		for i := range got.Dirs {
			if got.Dirs[i] != first.Dirs[i] {
				t.Fatalf("Dirs[%d] unstable: %+v vs %+v", i, got.Dirs[i], first.Dirs[i])
			}
		}
		for i := range got.Roots {
			if got.Roots[i] != first.Roots[i] {
				t.Fatalf("Roots[%d] unstable: %+v vs %+v", i, got.Roots[i], first.Roots[i])
			}
		}
	}
}

// TestResourceSummarySeparatesWhatScoringCannot is the point of the whole
// step. A repository scan and an exfiltration crawl score identically — both
// 0.400, every scoring term equal. They are not remotely alike once you look
// at where they went, which is the information a human needs and the scorer
// throws away.
func TestResourceSummarySeparatesWhatScoringCannot(t *testing.T) {
	var linter, exfil []string
	for i := 0; i < 60; i++ {
		linter = append(linter, fmt.Sprintf("/src/pkg%d/file%02d.go", i/20, i))
	}
	roots := []string{"/home/u/.ssh", "/etc", "/var/secrets", "/root/.aws",
		"/opt/app/.env.d", "/home/u/.config/gcloud"}
	for i := 0; i < 60; i++ {
		exfil = append(exfil, fmt.Sprintf("%s/f%02d", roots[i%len(roots)], i))
	}

	ls, es := observe(t, linter), observe(t, exfil)

	if a, b := ls.Assess(DefaultWeights()).Score, es.Assess(DefaultWeights()).Score; a != b {
		t.Fatalf("premise broken: the two shapes no longer score identically (%.4f vs %.4f). "+
			"If the scorer can now tell them apart, this test and the README should say so.", a, b)
	}

	lsum, esum := ls.ResourceSummary(), es.ResourceSummary()
	if len(lsum.Roots) != 1 {
		t.Errorf("repo scan touched %d roots, want 1: %+v", len(lsum.Roots), lsum.Roots)
	}
	if len(esum.Roots) < 4 {
		t.Errorf("exfil crawl touched %d roots, want at least 4: %+v", len(esum.Roots), esum.Roots)
	}
	t.Logf("identical scores (%.3f), different stories: repo scan spans %d root(s) %v; "+
		"crawl spans %d roots", ls.Assess(DefaultWeights()).Score,
		len(lsum.Roots), rootNames(lsum.Roots), len(esum.Roots))
}

func rootNames(gs []Group) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.Name
	}
	return out
}
