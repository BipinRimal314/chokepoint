package detect

import (
	"fmt"
	"strings"
	"testing"
)

func mustScope(t *testing.T, decls ...string) Scope {
	t.Helper()
	s, err := NewScope(decls)
	if err != nil {
		t.Fatalf("NewScope(%v): %v", decls, err)
	}
	return s
}

func TestScopeContains(t *testing.T) {
	sc := mustScope(t, "/srv/data", "/var/log/app", "https://api.example.com/v1")

	in := []string{
		"/srv/data",
		"/srv/data/f01",
		"/srv/data/nested/deep/f01",
		"/srv/data/",           // trailing separator
		"/srv/data/./f01",      // dot segment
		"/srv//data///f01",     // repeated separators
		"/srv/data/sub/../f01", // traversal that stays inside
		"/var/log/app/today.log",
		"https://api.example.com/v1/users",
		"HTTPS://API.Example.COM/v1/users", // case-folded host and scheme
	}
	for _, raw := range in {
		if !sc.Contains(ParseResource(raw)) {
			t.Errorf("Contains(%q) = false, want true", raw)
		}
	}

	out := []string{
		"/srv",                 // the parent is not inside the child
		"/srv/database/f01",    // segment boundary, not string prefix
		"/srv/data-backup/f01", // same
		"/etc/passwd",
		"/var/log/other/app.log",
		"https://api.example.com/v2/users",  // different path
		"https://evil.example.com/v1/users", // different host
		"http://api.example.com/v1/users",   // different scheme
		"api.example.com/v1/users",          // bare, unresolvable relative
	}
	for _, raw := range out {
		if sc.Contains(ParseResource(raw)) {
			t.Errorf("Contains(%q) = true, want false", raw)
		}
	}
}

// TestScopeIsNotDefeatedByTraversal is why normalisation lives below the policy
// layer. Every one of these reads as being under /srv to a string comparison,
// and not one of them is.
func TestScopeIsNotDefeatedByTraversal(t *testing.T) {
	sc := mustScope(t, "/srv/data")

	escapes := []string{
		"/srv/data/../../home/u/.ssh/id_rsa",
		"/srv/data/../../../etc/shadow",
		"/srv/data/./../../root/.aws/credentials",
		`/srv/data\..\..\home\u\.ssh\id_rsa`,
		"/srv/data/x/../../../etc/passwd",
	}
	for _, raw := range escapes {
		r := ParseResource(raw)
		if sc.Contains(r) {
			t.Errorf("Contains(%q) = true — traversal escaped the working set", raw)
		}
		if !sc.Escaped(r) {
			t.Errorf("Escaped(%q) = false, want true — its raw text reads as contained", raw)
		}
	}

	// A plainly external target is out of scope but is not an escape: nobody
	// dressed it up as being inside.
	if r := ParseResource("/etc/passwd"); sc.Escaped(r) {
		t.Error("Escaped(/etc/passwd) = true; a plain external target is not a traversal")
	}
}

func TestScopeVolumesStayDistinct(t *testing.T) {
	sc := mustScope(t, `C:\Users\agent\work`)

	if !sc.Contains(ParseResource(`C:\Users\agent\work\notes.txt`)) {
		t.Error("C: drive resource should be inside the C: working set")
	}
	if sc.Contains(ParseResource(`D:\Users\agent\work\notes.txt`)) {
		t.Error("D: resource matched a C: working set — identical paths, different volumes")
	}
}

func TestScopeRootEntryContainsEverythingLocal(t *testing.T) {
	sc := mustScope(t, "/")
	for _, raw := range []string{"/etc/passwd", "/srv/data/f01", "/"} {
		if !sc.Contains(ParseResource(raw)) {
			t.Errorf("Contains(%q) = false under a %q working set", raw, "/")
		}
	}
	if sc.Contains(ParseResource("https://api.example.com/v1")) {
		t.Error("a local root working set should not contain a network resource")
	}
}

// TestUndeclaredScopeContainsNothingAndAccusesNobody pins the safety property.
// An undeclared working set must not read as "everything is out of scope",
// which would turn any scope rule into a deny-all on a deployment that never
// opted in.
func TestUndeclaredScopeContainsNothingAndAccusesNobody(t *testing.T) {
	var sc Scope
	if sc.Declared() {
		t.Fatal("zero Scope reports itself as declared")
	}
	if sc.Contains(ParseResource("/etc/passwd")) {
		t.Error("undeclared scope claimed to contain something")
	}
	if sc.Escaped(ParseResource("/etc/passwd")) {
		t.Error("undeclared scope reported an escape")
	}

	rep := observe(t, []string{"/etc/passwd", "/home/u/.ssh/id_rsa"}).ScopeReport(sc)
	if rep.Declared || rep.OutOfScope != 0 || rep.Distinct != 0 || rep.Calls != 0 {
		t.Errorf("undeclared ScopeReport should be empty and marked undeclared, got %+v", rep)
	}
	if rep.FirstOutOfScope != -1 {
		t.Errorf("FirstOutOfScope = %d, want -1", rep.FirstOutOfScope)
	}
}

func TestNewScopeRejectsUnusableDeclarations(t *testing.T) {
	cases := []struct{ decl, wants string }{
		{"", "empty"},
		{"   ", "empty"},
		{"src/data", "relative"}, // silently matches nothing against absolute targets
		{"./data", "relative"},
		{".", "no resource"},
	}
	for _, c := range cases {
		_, err := NewScope([]string{c.decl})
		if err == nil {
			t.Errorf("NewScope(%q) accepted an unusable declaration", c.decl)
			continue
		}
		if !strings.Contains(err.Error(), c.wants) {
			t.Errorf("NewScope(%q) error = %q, want it to mention %q", c.decl, err, c.wants)
		}
	}
}

func TestScopeReportCounts(t *testing.T) {
	sc := mustScope(t, "/srv/data")
	s := observe(t, []string{
		"/srv/data/a",
		"/srv/data/b",
		"/srv/data/a",                // repeat, in scope
		"/etc/passwd",                // out
		"/srv/data/../../etc/shadow", // out, and an escape
		"/etc/passwd",                // repeat, out but not a new place
		"/home/u/.ssh/id_rsa",        // out
	})
	rep := s.ScopeReport(sc)

	if !rep.Declared {
		t.Fatal("Declared = false")
	}
	if rep.Calls != 7 {
		t.Errorf("Calls = %d, want 7", rep.Calls)
	}
	if rep.InScope != 3 {
		t.Errorf("InScope = %d, want 3", rep.InScope)
	}
	if rep.OutOfScope != 4 {
		t.Errorf("OutOfScope = %d, want 4", rep.OutOfScope)
	}
	// /etc/passwd twice is one place, not two.
	if rep.Distinct != 3 {
		t.Errorf("Distinct = %d, want 3 — one path retried is not two places", rep.Distinct)
	}
	if rep.Escaped != 1 {
		t.Errorf("Escaped = %d, want 1", rep.Escaped)
	}
	if rep.FirstOutOfScope != 3 {
		t.Errorf("FirstOutOfScope = %d, want 3", rep.FirstOutOfScope)
	}

	wantOutside := []Group{
		{Name: "/etc", Calls: 3, Distinct: 2, FirstCall: 3},
		{Name: "/home", Calls: 1, Distinct: 1, FirstCall: 6},
	}
	if len(rep.Outside) != len(wantOutside) {
		t.Fatalf("Outside = %+v, want %d groups", rep.Outside, len(wantOutside))
	}
	for i, w := range wantOutside {
		if rep.Outside[i] != w {
			t.Errorf("Outside[%d] = %+v, want %+v", i, rep.Outside[i], w)
		}
	}
}

// TestScopeSeparatesTheSweepScoringCannot is the point of Step 2, and the
// answer to the defect the evasion harness found.
//
// A repository scan and an exfiltration crawl score identically — 0.400 each,
// every behavioural term equal, permanently, at any scale. The score cannot
// separate them because the information that does is not in the call stream. A
// declared working set has it: one session stayed where it was sent and the
// other did not, and that verdict does not move with session length, tool
// vocabulary, padding, or timing.
func TestScopeSeparatesTheSweepScoringCannot(t *testing.T) {
	var repo, exfil []string
	for i := 0; i < 60; i++ {
		repo = append(repo, fmt.Sprintf("/src/pkg%d/file%02d.go", i/20, i))
	}
	roots := []string{"/home/u/.ssh", "/etc", "/var/secrets", "/root/.aws",
		"/opt/app/.env.d", "/home/u/.config/gcloud"}
	for i := 0; i < 60; i++ {
		exfil = append(exfil, fmt.Sprintf("%s/f%02d", roots[i%len(roots)], i))
	}

	rs, es := observe(t, repo), observe(t, exfil)

	repoScore := rs.Assess(DefaultWeights()).Score
	exfilScore := es.Assess(DefaultWeights()).Score
	if repoScore != exfilScore {
		t.Fatalf("premise broken: the two shapes no longer score identically (%.4f vs %.4f). "+
			"If the scorer can now tell them apart, this test and the README should say so.",
			repoScore, exfilScore)
	}

	sc := mustScope(t, "/src")
	repoRep, exfilRep := rs.ScopeReport(sc), es.ScopeReport(sc)

	if repoRep.OutOfScope != 0 {
		t.Errorf("repo scan left its working set %d times, want 0: %+v",
			repoRep.OutOfScope, repoRep.Outside)
	}
	if exfilRep.OutOfScope != 60 {
		t.Errorf("exfil crawl OutOfScope = %d, want all 60", exfilRep.OutOfScope)
	}
	if exfilRep.FirstOutOfScope != 0 {
		t.Errorf("FirstOutOfScope = %d, want 0 — the crawl was out of bounds immediately",
			exfilRep.FirstOutOfScope)
	}

	t.Logf("identical scores (%.3f); scope separates them at the first call: "+
		"repo scan 0/%d out of bounds, crawl %d/%d across %d roots",
		repoScore, repoRep.Calls, exfilRep.OutOfScope, exfilRep.Calls, len(exfilRep.Outside))
}

// TestScopeVerdictIsScaleInvariant is the property the score does not have.
// A single-tool sweep scores a constant 0.400 whether it reads 20 files or
// 5,000, so no threshold catches it. Scope catches the first call and every
// call after it, at every scale.
func TestScopeVerdictIsScaleInvariant(t *testing.T) {
	sc := mustScope(t, "/srv/data")

	for _, n := range []int{8, 20, 200, 5000} {
		targets := make([]string, 0, n)
		for i := 0; i < n; i++ {
			targets = append(targets, fmt.Sprintf("/home/u/secrets/f%05d", i))
		}
		s := observe(t, targets)

		if score := s.Assess(DefaultWeights()).Score; score >= 0.45 {
			t.Fatalf("premise broken at n=%d: single-tool sweep now scores %.4f, "+
				"which the shipped 0.45 threshold would catch", n, score)
		}
		rep := s.ScopeReport(sc)
		if rep.OutOfScope != n {
			t.Errorf("n=%d: OutOfScope = %d, want %d", n, rep.OutOfScope, n)
		}
		if rep.InScope != 0 {
			t.Errorf("n=%d: InScope = %d, want 0", n, rep.InScope)
		}
	}
}
