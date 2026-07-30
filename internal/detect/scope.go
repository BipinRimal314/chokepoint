package detect

import (
	"fmt"
	"strings"
)

// Scope is a declared working set: the places an agent is supposed to reach.
//
// It exists because the scorer cannot tell a repository scan from an
// exfiltration crawl. Both are one tool over sixty targets, both score exactly
// 0.400, and every behavioural term is equal — the information that separates
// them is not in the call stream at all. It is in whether the calls went where
// the agent was sent.
//
// That makes scope categorically different from the score, and better where it
// applies. A score asks how unusual the behaviour looks and can be argued with;
// a working set asks whether the call is inside the boundary its operator
// declared, and a single read of /home/u/.ssh/id_rsa answers it. The attacker
// who declines to vary their tool vocabulary pays nothing against the score and
// everything against this.
//
// The catch is that it only works on deployments whose operator can say where
// the agent belongs. That is why nothing here is on by default: an undeclared
// Scope contains nothing and reports nothing, and rules written against it stay
// inert rather than denying every call on a deployment that never declared one.
type Scope struct {
	entries []Resource
}

// NewScope declares a working set from a list of paths or URI prefixes.
//
// Entries are normalised the same way targets are, so "/srv/data/" and
// "/srv/./data" declare the same boundary. A relative entry is rejected: it
// would silently match nothing on a server that reports absolute paths, and a
// scope rule that never fires while appearing to protect something is the
// failure this package exists to prevent.
func NewScope(decls []string) (Scope, error) {
	var s Scope
	for _, d := range decls {
		if strings.TrimSpace(d) == "" {
			return Scope{}, fmt.Errorf("workspace entry is empty")
		}
		r := ParseResource(d)
		if r.Empty() {
			return Scope{}, fmt.Errorf("workspace entry %q names no resource", d)
		}
		if r.Host == "" && !strings.HasPrefix(r.Path, "/") {
			return Scope{}, fmt.Errorf(
				"workspace entry %q is relative; declare an absolute path or a URI prefix", d)
		}
		s.entries = append(s.entries, r)
	}
	return s, nil
}

// Declared reports whether any working set was declared. A Scope that was never
// declared must not be read as "everything is out of scope".
func (s Scope) Declared() bool { return len(s.entries) > 0 }

// Entries returns the declared boundaries, for reporting.
func (s Scope) Entries() []Resource {
	out := make([]Resource, len(s.entries))
	copy(out, s.entries)
	return out
}

// Contains reports whether r sits inside the working set.
//
// Comparison is on the normalised resource, never the raw string, which is the
// whole reason normalisation happens a layer below policy: "/srv/../etc/shadow"
// is not in /srv, and a containment check written against raw text is one "../"
// from useless.
//
// Boundaries are segment-aligned. "/srv/data" contains "/srv/data/f01" and does
// not contain "/srv/database", which a plain string prefix would get wrong in
// the direction that matters.
func (s Scope) Contains(r Resource) bool {
	if r.Empty() {
		return false
	}
	rk := scopeKey(r)
	for _, e := range s.entries {
		ek := scopeKey(e)
		if rk == ek {
			return true
		}
		// A trailing separator is trimmed before the boundary is re-added, so
		// an entry of "/" or a bare "https://host" still contains its children
		// without producing a doubled separator that matches nothing.
		if strings.HasPrefix(rk, strings.TrimSuffix(ek, "/")+"/") {
			return true
		}
	}
	return false
}

// Escaped reports whether r's raw text reads as being inside the working set
// while the resource it actually names is outside it.
//
// This separates "the agent was pointed somewhere else" from "the agent was
// handed a path that resolves out of bounds" — an ordinary out-of-scope call
// from a traversal. Both are denied identically; they are worth different
// levels of alarm in a report, because only one of them had to be constructed.
//
// It is a reporting heuristic over the raw string and must never be used to
// decide whether a call is permitted. Contains is the authority for that.
func (s Scope) Escaped(r Resource) bool {
	if r.Empty() || s.Contains(r) {
		return false
	}
	naive := strings.ReplaceAll(strings.TrimSpace(r.Raw), `\`, "/")
	for _, e := range s.entries {
		if e.Path == "" {
			continue
		}
		if naive == e.Path || strings.HasPrefix(naive, strings.TrimSuffix(e.Path, "/")+"/") {
			return true
		}
	}
	return false
}

// scopeKey is the string containment is tested on.
//
// The drive letter is folded in because ParseResource carries it in Root rather
// than Path, so "C:/Users/x" and "D:/Users/x" have identical paths and must not
// contain one another.
func scopeKey(r Resource) string {
	return r.Scheme + "://" + r.Host + volumeOf(r) + r.Path
}

func volumeOf(r Resource) string {
	if len(r.Root) == 2 && r.Root[1] == ':' && isLetter(r.Root[0]) {
		return r.Root
	}
	return ""
}

// ScopeReport is where a session went relative to where it was told to go.
//
// Like ResourceSummary it reports rather than judges — but unlike the score, an
// operator reading it does not have to interpret a number. Calls landed inside
// the declared boundary or they did not.
type ScopeReport struct {
	// Declared is false when no working set was declared, in which case every
	// other field is zero and none of them mean "clean".
	Declared bool
	// Calls is how many observed calls carried a resource.
	Calls int
	// InScope and OutOfScope split those calls by the boundary.
	InScope    int
	OutOfScope int
	// Distinct is how many distinct out-of-scope resources were touched. This
	// is the number a rule should threshold on: one call retried thirty times
	// is not thirty places.
	Distinct int
	// Escaped counts out-of-scope calls whose raw text read as contained —
	// traversals rather than plainly external targets.
	Escaped int
	// Outside groups out-of-scope activity by root, sorted by call count
	// descending then name, so the report is stable and diffable.
	Outside []Group
	// FirstOutOfScope is the index of the first call that left the working set,
	// or -1 if none did. It answers "when did this start", which is the first
	// question anyone reading an alert asks.
	//
	// The index is into retained history, not the session's whole life; eviction
	// trims the window. Same caveat as Group.FirstCall.
	FirstOutOfScope int
}

// ScopeReport describes this session's activity relative to a declared working
// set.
func (s *Session) ScopeReport(sc Scope) ScopeReport {
	out := ScopeReport{Declared: sc.Declared(), FirstOutOfScope: -1}
	if !out.Declared {
		return out
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	roots := make(map[string]*Group)
	rootSeen := make(map[string]map[string]struct{})
	seen := make(map[string]struct{})

	for i, c := range s.calls {
		if c.Target == "" {
			continue
		}
		r := ParseResource(c.Target)
		if r.Empty() {
			continue
		}

		out.Calls++
		if sc.Contains(r) {
			out.InScope++
			continue
		}

		out.OutOfScope++
		if sc.Escaped(r) {
			out.Escaped++
		}
		if out.FirstOutOfScope < 0 {
			out.FirstOutOfScope = i
		}

		key := scopeKey(r)
		if _, dup := seen[key]; !dup {
			seen[key] = struct{}{}
			out.Distinct++
		}
		track(roots, rootSeen, r.Root, key, i)
	}

	out.Outside = sortGroups(roots)
	return out
}
