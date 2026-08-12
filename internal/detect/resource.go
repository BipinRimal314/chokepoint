package detect

import (
	"net/url"
	"path"
	"sort"
	"strings"
)

// Resource is a normalised view of one target string.
//
// Targets arrive as whatever the tool's arguments happened to contain: a bare
// path, a file:// URI, an HTTPS endpoint, a Windows path with backslashes.
// Comparing those raw strings is unsound — "/srv/data", "/srv/data/" and
// "/srv/./data" are the same place, and "/src/../home/.ssh/id_rsa" is not in
// /src at all.
//
// The last of those is the security-relevant one. Any scope rule written
// against raw strings is defeated by a traversal, so normalisation has to
// happen here, once, before anything compares or counts targets.
type Resource struct {
	// Raw is the target exactly as observed, kept so a report can show what
	// the tool was actually called with rather than our tidied version.
	Raw string
	// Scheme is the URI scheme, or "file" for a bare path.
	Scheme string
	// Host is the authority for network resources, empty for local paths.
	Host string
	// Path is the cleaned path: traversal resolved, separators collapsed, no
	// trailing slash.
	Path string
	// Dir is the container Path sits in — the parent directory, or the parent
	// of the URI path.
	Dir string
	// Root is the coarsest grouping: scheme://host for network resources, or
	// the first path segment for local ones. This is what answers "how many
	// unrelated places did this session reach into".
	Root string
}

// Empty reports whether this Resource names nothing — the result of parsing an
// empty or unusable target. Callers must treat it as "no target" rather than as
// a resource named "", which would otherwise group every targetless call
// together as if it were a place.
func (r Resource) Empty() bool {
	return r.Path == "" && r.Host == ""
}

// ParseResource normalises a raw target string.
//
// An empty or unparseable target yields the zero Resource, which callers must
// treat as "no target" rather than as a resource named "".
func ParseResource(raw string) Resource {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Resource{}
	}

	r := Resource{Raw: raw}

	// A URI scheme is only recognised when the target really looks like a
	// URI. Bare Windows paths ("C:\Users\...") would otherwise parse as
	// scheme "c", which would file every drive letter as its own protocol.
	if u, err := url.Parse(trimmed); err == nil && u.Scheme != "" && len(u.Scheme) > 1 {
		r.Scheme = strings.ToLower(u.Scheme)
		r.Host = strings.ToLower(u.Host)
		r.Path = cleanPath(u.Path)
		if r.Host != "" {
			r.Root = r.Scheme + "://" + r.Host
		} else {
			r.Root = r.Scheme + "://" + firstSegment(r.Path)
		}
		r.Dir = dirOf(r.Path)
		return r
	}

	// Everything else is a filesystem path. Backslashes are folded to forward
	// slashes so a Windows server and a POSIX one group the same way.
	p := strings.ReplaceAll(trimmed, `\`, "/")

	// A drive letter is carried as the root so C: and D: stay distinct.
	var drive string
	if len(p) >= 2 && p[1] == ':' && isLetter(p[0]) {
		drive = strings.ToUpper(p[:2])
		p = p[2:]
	}

	r.Scheme = "file"
	r.Path = cleanPath(p)
	r.Dir = dirOf(r.Path)
	switch {
	case drive != "":
		r.Root = drive
	default:
		r.Root = firstSegment(r.Path)
	}
	return r
}

// cleanPath resolves "." and "..", collapses repeated separators, and strips
// any trailing separator.
//
// path.Clean already clamps ".." at the root, so "/../../etc" becomes "/etc"
// rather than escaping upward. Relative inputs stay relative — this package
// has no working directory to resolve them against, and inventing one would
// produce a confident wrong answer.
func cleanPath(p string) string {
	if p == "" {
		return ""
	}
	c := path.Clean(p)
	if c == "." {
		return ""
	}
	if len(c) > 1 {
		c = strings.TrimSuffix(c, "/")
	}
	return c
}

// dirOf returns the container of a cleaned path.
func dirOf(p string) string {
	if p == "" || p == "/" {
		return p
	}
	d := path.Dir(p)
	if d == "." {
		return ""
	}
	return d
}

// firstSegment returns the top-level component of a cleaned path, which is the
// coarsest useful grouping for a local target.
func firstSegment(p string) string {
	t := strings.TrimPrefix(p, "/")
	if t == "" {
		if p == "/" {
			return "/"
		}
		return ""
	}
	if i := strings.IndexByte(t, '/'); i >= 0 {
		t = t[:i]
	}
	if strings.HasPrefix(p, "/") {
		return "/" + t
	}
	return t
}

func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// Group is one bucket of resource activity — a directory or a root — with
// enough context for a report to be read without further lookups.
type Group struct {
	// Name is the directory or root this bucket covers.
	Name string
	// Calls is how many calls touched it.
	Calls int
	// Distinct is how many distinct resources inside it were touched.
	Distinct int
	// FirstCall is the 0-based index of the call that first reached it.
	// A crawl keeps discovering new groups as the session runs; a scoped
	// agent reaches its groups early and stays there.
	//
	// This is an index into the calls the session still retains, not into the
	// session's whole life. Config.Window and Config.MaxCalls evict old calls,
	// so in a long session a FirstCall of 0 means "first call still in the
	// window", not "first call ever". Persisting true first-contact across
	// eviction is part of the cross-session history work, not this layer.
	FirstCall int
}

// ResourceSummary is what a session touched, in a shape a human can read.
//
// This deliberately reports rather than judges. Whether reading four thousand
// files is a repository scan or an exfiltration crawl is not answerable from
// the call stream — the two are identical in every behavioural feature this
// package computes. It is answerable by whoever knows what the agent was
// supposed to be doing, so the job here is to put that person in a position
// to answer it.
type ResourceSummary struct {
	// Calls is how many observed calls carried a target.
	Calls int
	// Distinct is how many distinct resources were touched.
	Distinct int
	// Dirs and Roots are sorted by call count descending, then name, so the
	// output is stable across runs and diffable between sessions.
	Dirs  []Group
	Roots []Group
}

// ResourceSummary describes the resources this session has touched so far.
func (s *Session) ResourceSummary() ResourceSummary {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out ResourceSummary
	seen := make(map[string]struct{})
	dirs := make(map[string]*Group)
	roots := make(map[string]*Group)
	dirSeen := make(map[string]map[string]struct{})
	rootSeen := make(map[string]map[string]struct{})

	// Two contiguous runs rather than the ring's iterator; see Vector. base
	// carries the logical index across the wrap, for Group.FirstCall.
	front, back := s.calls.parts()
	base := 0
	for _, seg := range [2][]Call{front, back} {
		for j := range seg {
			c, i := &seg[j], base+j

			// Normalised once at Observe; see Call.res.
			r := c.res
			if r.Empty() {
				continue
			}
			key := r.Scheme + "://" + r.Host + r.Path

			out.Calls++
			if _, dup := seen[key]; !dup {
				seen[key] = struct{}{}
				out.Distinct++
			}

			track(dirs, dirSeen, r.Dir, key, i)
			track(roots, rootSeen, r.Root, key, i)
		}
		base += len(seg)
	}

	out.Dirs = sortGroups(dirs)
	out.Roots = sortGroups(roots)
	return out
}

func track(groups map[string]*Group, seen map[string]map[string]struct{}, name, key string, idx int) {
	if name == "" {
		return
	}
	g, ok := groups[name]
	if !ok {
		g = &Group{Name: name, FirstCall: idx}
		groups[name] = g
		seen[name] = make(map[string]struct{})
	}
	g.Calls++
	if _, dup := seen[name][key]; !dup {
		seen[name][key] = struct{}{}
		g.Distinct++
	}
}

// sortGroups orders by call count descending, then by name, so that equal
// counts do not reorder between runs. Map iteration order in Go is randomised,
// and an unstable report is one nobody can diff.
func sortGroups(m map[string]*Group) []Group {
	out := make([]Group, 0, len(m))
	for _, g := range m {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Calls != out[j].Calls {
			return out[i].Calls > out[j].Calls
		}
		return out[i].Name < out[j].Name
	})
	return out
}
