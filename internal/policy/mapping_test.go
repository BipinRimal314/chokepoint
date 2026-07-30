package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// asiCategories is the OWASP Top 10 for Agentic Applications, release of
// 9 December 2025.
//
// Hard-coded here rather than parsed out of the document, so that the document
// is checked against something rather than against itself. Editing the mapping
// alone cannot make this test pass.
//
// The identifiers matter more than they look. OWASP's earlier "Agentic AI —
// Threats and Mitigations" taxonomy used names that no longer sit where people
// remember them: "Excessive Agency" is not in this list at all, "Memory &
// Context Poisoning" is ASI06 rather than ASI05, and "Agentic Supply Chain
// Vulnerabilities" is ASI04 rather than ASI06. A mapping that inherits the old
// names while citing the new release looks authoritative and is wrong.
var asiCategories = map[string]string{
	"ASI01": "Agent Goal Hijack",
	"ASI02": "Tool Misuse",
	"ASI03": "Identity & Privilege Abuse",
	"ASI04": "Agentic Supply Chain Vulnerabilities",
	"ASI05": "Unexpected Code Execution",
	"ASI06": "Memory & Context Poisoning",
	"ASI07": "Insecure Inter-Agent Communication",
	"ASI08": "Cascading Failures",
	"ASI09": "Human-Agent Trust Exploitation",
	"ASI10": "Rogue Agents",
}

func mappingDoc(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "owasp-asi-mapping.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// TestASIMappingMatchesTheStandard pins the document's claims about a public
// standard. Those are exactly the claims that rot quietly: nothing in the build
// breaks when a category is renamed upstream, and a control mapping carrying a
// wrong identifier is worse than none, because it will be checked.
func TestASIMappingMatchesTheStandard(t *testing.T) {
	doc := mappingDoc(t)

	// Identifier and title must be bound to each other, in both places the
	// document states the pairing: the summary table row and the section
	// heading. Merely checking that the right title appears *somewhere* is not
	// enough — swap two rows of the table and every title is still present,
	// which is precisely how a mapping ends up authoritative and wrong.
	tableRow := regexp.MustCompile(`(?m)^\| (ASI\d{2}) \| ([^|]+?) \|`)
	heading := regexp.MustCompile(`(?m)^## (ASI\d{2}) — (.+)$`)

	for _, form := range []struct {
		what string
		re   *regexp.Regexp
	}{
		{"table row", tableRow},
		{"section heading", heading},
	} {
		seen := map[string]bool{}
		for _, m := range form.re.FindAllStringSubmatch(doc, -1) {
			id, title := m[1], strings.TrimSpace(m[2])
			seen[id] = true

			want, known := asiCategories[id]
			if !known {
				t.Errorf("%s names %s, which is not in the Top 10", form.what, id)
				continue
			}
			if title != want {
				t.Errorf("%s for %s is titled %q, want %q", form.what, id, title, want)
			}
		}
		for id, title := range asiCategories {
			if !seen[id] {
				t.Errorf("no %s for %s (%s)", form.what, id, title)
			}
		}
	}

	// Every ASI identifier in the document must be one that exists. A typo'd
	// ASI11, or an identifier carried over from the older taxonomy, is caught
	// here rather than by a reader.
	found := regexp.MustCompile(`ASI\d{2}`).FindAllString(doc, -1)
	if len(found) == 0 {
		t.Fatal("the mapping names no ASI categories at all")
	}
	for _, id := range found {
		if _, ok := asiCategories[id]; !ok {
			t.Errorf("mapping references %s, which is not in the Top 10", id)
		}
	}

	// Names from the superseded taxonomy are the specific mistake worth
	// guarding: they are plausible, familiar, and wrong.
	for _, stale := range []string{
		"Excessive Agency",
		"Cascading Hallucinations",
		"Inadequate Sandboxing",
		"Unsafe Code Generation",
		"Supply Chain Compromise",
	} {
		// Allowed only where the document explicitly discusses them as
		// superseded names.
		idx := strings.Index(doc, stale)
		if idx < 0 {
			continue
		}
		window := doc[max(0, idx-400):idx]
		if !strings.Contains(window, "superseded") && !strings.Contains(window, "Threats and Mitigations") {
			t.Errorf("mapping uses the superseded name %q without saying so", stale)
		}
	}
}

// TestASIMappingNamesRealPolicyRules keeps the document's examples honest. A
// mapping that points at a rule the shipped policy does not contain is
// describing a deployment nobody has.
func TestASIMappingNamesRealPolicyRules(t *testing.T) {
	doc := mappingDoc(t)

	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "policy.yaml"))
	if err != nil {
		t.Fatalf("read example policy: %v", err)
	}
	p, err := Parse(data)
	if err != nil {
		t.Fatalf("parse example policy: %v", err)
	}

	shipped := make(map[string]bool, len(p.Rules))
	for _, r := range p.Rules {
		shipped[r.Name] = true
	}

	// Backticked identifiers that look like rule names: lowercase words joined
	// by hyphens. Anything else in backticks is a path, a flag, or a method.
	ruleLike := regexp.MustCompile("`([a-z]+(?:-[a-z]+){1,})`")
	for _, m := range ruleLike.FindAllStringSubmatch(doc, -1) {
		name := m[1]
		// Only names the example policy would plausibly define; skip prose
		// hyphenations and known non-rules.
		switch name {
		case "tools-list", "resources-read", "prompts-get":
			continue
		}
		if strings.Contains(name, "/") {
			continue
		}
		// A hyphenated backticked token that is not a shipped rule is only an
		// error if the policy defines rules with that shape at all — which it
		// does, so an unknown one is a stale reference.
		if !shipped[name] && looksLikeARuleReference(doc, name) {
			t.Errorf("mapping references rule %q, which examples/policy.yaml does not define", name)
		}
	}
}

// looksLikeARuleReference is true when the document uses the token in a
// sentence about policy rules rather than as incidental prose.
func looksLikeARuleReference(doc, name string) bool {
	idx := strings.Index(doc, "`"+name+"`")
	if idx < 0 {
		return false
	}
	window := doc[max(0, idx-120):min(len(doc), idx+120)]
	return strings.Contains(window, "rule") || strings.Contains(window, "policy")
}
