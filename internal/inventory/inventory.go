// Package inventory fingerprints the tool definitions a server advertises and
// reports when they change.
//
// The attack this exists for is the rug pull: a server advertises benign tools,
// is reviewed and approved, and then mutates a definition afterwards. The agent
// re-reads the tool list, sees new instructions inside a description or a
// widened schema, and acts on them. Nothing in the tool-call stream looks
// unusual, because the call genuinely matches what the server now advertises —
// which is exactly why behavioural scoring cannot see it and why the check has
// to be on the definitions rather than on the calls.
//
// It is cheap because a proxy is already in the right position: tools/list
// responses cross the wire here. No new transport, no new protocol support.
package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ChangeKind is what happened to a tool definition between listings.
type ChangeKind string

const (
	// Added is a tool that was not in any earlier listing. Suspicious for the
	// same reason a modification is: capability that appeared after whatever
	// review the first listing got.
	Added ChangeKind = "added"
	// Modified is the rug pull — same name, different definition.
	Modified ChangeKind = "modified"
	// Removed is a tool that has disappeared. Recorded for completeness; on its
	// own it withdraws capability rather than adding any.
	Removed ChangeKind = "removed"
)

// Change is one difference from the first listing.
type Change struct {
	Tool string
	Kind ChangeKind
	// Was and Now are fingerprints, empty for Added and Removed respectively.
	// They are hashes rather than the definitions themselves: a definition can
	// be large and attacker-controlled, and this ends up in logs.
	Was string
	Now string
	// Listing is the 1-based index of the tools/list response that differed.
	Listing int
}

func (c Change) String() string {
	switch c.Kind {
	case Modified:
		return fmt.Sprintf("%s modified (%s -> %s) at listing %d",
			c.Tool, short(c.Was), short(c.Now), c.Listing)
	case Added:
		return fmt.Sprintf("%s added (%s) at listing %d", c.Tool, short(c.Now), c.Listing)
	default:
		return fmt.Sprintf("%s removed at listing %d", c.Tool, c.Listing)
	}
}

func short(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12]
}

// Registry remembers the first definition seen for each tool.
//
// First sight is the baseline, deliberately: the proxy has no way to know what
// an operator approved, only what the server said first. That makes the check
// "has this changed under us", not "is this what was reviewed" — weaker, but
// honest about what the position affords, and it is the mutation that the rug
// pull depends on.
//
// Safe for concurrent use; responses are observed from a proxy pump goroutine.
type Registry struct {
	mu      sync.Mutex
	first   map[string]string // tool name -> fingerprint at first sight
	changed map[string]bool   // tools modified or added after the first listing
	// schemas holds the compiled inputSchema from the listing that established
	// each tool's baseline. Absent means the tool declared none or advertised
	// one that would not compile; see Validate, which will not guess.
	schemas  map[string]*jsonschema.Schema
	changes  []Change
	listings int
	// schemaErrs records tools whose declared schema failed to compile, so the
	// gateway can say so once rather than the operator wondering why a tool is
	// never validated.
	schemaErrs map[string]error
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		first:      make(map[string]string),
		changed:    make(map[string]bool),
		schemas:    make(map[string]*jsonschema.Schema),
		schemaErrs: make(map[string]error),
	}
}

// Observe records one tools/list result and returns what changed.
//
// The first listing establishes the baseline and reports nothing. Later
// listings are compared against it — against the *first* definition, not the
// previous one, so a server cannot launder a mutation by changing a definition
// and changing it back.
func (r *Registry) Observe(tools []json.RawMessage) []Change {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.listings++
	seen := make(map[string]string, len(tools))
	raws := make(map[string]json.RawMessage, len(tools))

	for _, raw := range tools {
		name, fp, ok := fingerprint(raw)
		if !ok {
			// A tool with no usable name cannot be tracked across listings.
			// Skipped rather than counted under "": grouping every malformed
			// entry together would invent a tool that changes constantly.
			continue
		}
		seen[name] = fp
		raws[name] = raw
	}

	// The first listing is the baseline.
	if r.listings == 1 {
		for name, fp := range seen {
			r.first[name] = fp
			r.compileLocked(name, raws[name])
		}
		return nil
	}

	var out []Change
	for name, fp := range seen {
		was, known := r.first[name]
		switch {
		case !known:
			r.first[name] = fp
			r.changed[name] = true
			// A tool that appears late still gets its schema captured from the
			// listing that introduced it — that listing is its baseline, the
			// same rule the fingerprint follows. It is flagged as added
			// regardless, so a policy can refuse to trust it at all.
			r.compileLocked(name, raws[name])
			out = append(out, Change{Tool: name, Kind: Added, Now: fp, Listing: r.listings})
		case was != fp:
			r.changed[name] = true
			out = append(out, Change{Tool: name, Kind: Modified, Was: was, Now: fp, Listing: r.listings})
		}
	}
	for name := range r.first {
		if _, still := seen[name]; !still {
			// Only report a removal once, on the listing it vanished from.
			if !r.removedAlreadyLocked(name) {
				out = append(out, Change{Tool: name, Kind: Removed, Was: r.first[name], Listing: r.listings})
			}
		}
	}

	// Deterministic order so logs and reports are diffable.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Tool < out[j].Tool
	})

	r.changes = append(r.changes, out...)
	return out
}

// compileLocked captures a tool's declared schema at the moment it becomes the
// baseline. Never called for a later listing of a tool already known: the whole
// point is that the schema a call is checked against is the one the tool was
// first advertised with.
func (r *Registry) compileLocked(name string, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	sch, err := compileSchema(name, raw)
	if err != nil {
		// Recorded, not fatal, and deliberately not treated as "invalid". A
		// schema this build cannot compile is a gap in what can be checked, not
		// evidence about the call — failing closed here would deny every use of
		// a tool because of a dialect the library does not know.
		r.schemaErrs[name] = err
		return
	}
	if sch != nil {
		r.schemas[name] = sch
	}
}

// SchemaErrors returns the tools whose declared inputSchema did not compile.
func (r *Registry) SchemaErrors() map[string]error {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]error, len(r.schemaErrs))
	for k, v := range r.schemaErrs {
		out[k] = v
	}
	return out
}

// Schemas is how many tools are validatable.
func (r *Registry) Schemas() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.schemas)
}

func (r *Registry) removedAlreadyLocked(name string) bool {
	for _, c := range r.changes {
		if c.Tool == name && c.Kind == Removed {
			return true
		}
	}
	return false
}

// Changed reports whether this tool's definition has changed since first sight.
func (r *Registry) Changed(tool string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.changed[tool]
}

// ChangedCount is how many distinct tools have been modified or added.
func (r *Registry) ChangedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.changed)
}

// Changes returns every change recorded so far, in observation order.
func (r *Registry) Changes() []Change {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Change, len(r.changes))
	copy(out, r.changes)
	return out
}

// Listings is how many tools/list results have been observed.
func (r *Registry) Listings() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listings
}

// Tracked is how many distinct tools have been seen.
func (r *Registry) Tracked() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.first)
}

// fingerprint hashes one tool definition, returning its name and digest.
//
// The whole definition is hashed, not a chosen subset: a rug pull can hide in
// the description, the input schema, an annotation, or a field this build has
// never heard of. Picking fields to hash would be picking which mutations to
// miss.
func fingerprint(raw json.RawMessage) (name, digest string, ok bool) {
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Numbers stay as their literal text. Decoding into float64 and
	// re-encoding would make 1 and 1.0 hash alike, and could round a large
	// integer into a different one.
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return "", "", false
	}
	n, _ := obj["name"].(string)
	if n == "" {
		return "", "", false
	}

	var b bytes.Buffer
	canonical(&b, obj)
	sum := sha256.Sum256(b.Bytes())
	return n, hex.EncodeToString(sum[:]), true
}

// canonical writes a deterministic encoding of a decoded JSON value.
//
// Object keys are sorted; array order is preserved because it is meaningful.
// Go's encoding/json already sorts map keys, but relying on that would make the
// wire format of a security check an implementation detail of the standard
// library.
func canonical(b *bytes.Buffer, v any) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strconv.Quote(k))
			b.WriteByte(':')
			canonical(b, t[k])
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			canonical(b, item)
		}
		b.WriteByte(']')
	case json.Number:
		b.WriteString(t.String())
	case string:
		b.WriteString(strconv.Quote(t))
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case nil:
		b.WriteString("null")
	default:
		fmt.Fprintf(b, "%v", t)
	}
}
