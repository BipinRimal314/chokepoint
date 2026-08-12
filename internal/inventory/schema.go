package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// printer renders the library's error kinds into English. Package-level because
// it is stateless and building one per violation would allocate on a path that
// only runs when something is already wrong.
var printer = message.NewPrinter(language.English)

// MaxViolations bounds how many schema failures are reported for one call.
//
// The violation strings are derived from arguments the agent chose, so their
// number and content are attacker-influenced. An object with a thousand bad
// properties would otherwise put a thousand attacker-written strings into the
// evidence log and the policy environment for every call.
const MaxViolations = 10

// compileSchema builds a validator from a tool's declared inputSchema.
//
// Returns nil when the tool declares no schema, which is not an error: MCP does
// not require one, and a tool without a schema has to stay unvalidated rather
// than be treated as accepting nothing.
func compileSchema(name string, raw json.RawMessage) (*jsonschema.Schema, error) {
	var def struct {
		InputSchema json.RawMessage `json:"inputSchema"`
	}
	if err := json.Unmarshal(raw, &def); err != nil {
		return nil, err
	}
	if len(def.InputSchema) == 0 {
		return nil, nil
	}

	// Decoded through the library's own unmarshaller rather than
	// encoding/json, because it is particular about how numbers arrive and a
	// json.Number where it wants a float is a compile error at the wrong layer.
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(def.InputSchema)))
	if err != nil {
		return nil, fmt.Errorf("decode inputSchema: %w", err)
	}

	c := jsonschema.NewCompiler()
	// A fixed, non-resolvable base URL. Schemas that reference the network are
	// not fetched — a proxy that dialled out to whatever URL a tool definition
	// named while deciding whether to allow a call would be a far better
	// vulnerability than the one this check closes.
	const res = "mcp:///tool-input-schema"
	if err := c.AddResource(res, doc); err != nil {
		return nil, fmt.Errorf("add schema resource: %w", err)
	}
	sch, err := c.Compile(res)
	if err != nil {
		return nil, fmt.Errorf("compile inputSchema for %q: %w", name, err)
	}
	return sch, nil
}

// Validate checks a call's arguments against the tool's first-seen schema.
//
// known is false when the tool declares no schema, was never listed, or
// advertised one that did not compile. Callers must branch on it rather than
// reading violations: "no schema to check against" and "checked and clean" are
// both an empty violation list and completely different facts, and a policy
// that conflated them would deny every call to an unschema'd tool the moment it
// was written to trust this.
//
// Validation is against the schema seen in the *first* tools/list, for the same
// reason the fingerprint is: a server that widens a schema mid-session to admit
// an argument it previously refused has performed the rug pull, and checking
// against the widened version would ratify it.
func (r *Registry) Validate(tool string, args map[string]any) (known bool, violations []string) {
	r.mu.Lock()
	sch, ok := r.schemas[tool]
	r.mu.Unlock()
	if !ok || sch == nil {
		return false, nil
	}

	// A nil map and an absent arguments object are the same thing to MCP, and
	// the library wants a value rather than a nil map to apply "required" to.
	var instance any = args
	if args == nil {
		instance = map[string]any{}
	}

	err := sch.Validate(instance)
	if err == nil {
		return true, nil
	}

	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return true, []string{err.Error()}
	}
	return true, flatten(ve)
}

// MaxViolationLen bounds one violation string.
//
// Bounding the *count* is not enough on its own, which a test caught: the
// library reports every offending property inside a single message, so one
// violation carrying two hundred attacker-chosen names is a two-hundred-name
// string in the evidence log no matter how few violations there are.
const MaxViolationLen = 160

// maxNames bounds how many offending property names one violation lists.
const maxNames = 5

// describe renders one leaf error deterministically and within bounds.
//
// The two kinds that carry attacker-chosen names are handled structurally
// rather than through the library's prose, because that prose renders them in
// map order — the same bad call produced a different string on almost every
// run, which a test caught. An evidence log whose lines reorder between runs
// cannot be diffed, and a non-deterministic policy input is worse than none.
func describe(e *jsonschema.ValidationError) string {
	loc := "/" + strings.Join(e.InstanceLocation, "/")
	if loc == "/" {
		loc = "(root)"
	}

	var detail string
	switch k := e.ErrorKind.(type) {
	case *kind.AdditionalProperties:
		detail = "properties not in the tool's declared schema: " + nameList(k.Properties)
	case *kind.Required:
		detail = "missing required properties: " + nameList(k.Missing)
	default:
		detail = e.ErrorKind.LocalizedString(printer)
	}

	out := loc + ": " + detail
	if len(out) > MaxViolationLen {
		out = out[:MaxViolationLen] + "…"
	}
	return out
}

// nameList sorts and truncates attacker-chosen property names.
func nameList(names []string) string {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	if len(sorted) > maxNames {
		extra := len(sorted) - maxNames
		sorted = append(sorted[:maxNames:maxNames], fmt.Sprintf("(and %d more)", extra))
	}
	return strings.Join(sorted, ", ")
}

// flatten turns a validation error tree into sorted, bounded, human strings.
func flatten(ve *jsonschema.ValidationError) []string {
	seen := map[string]struct{}{}
	var walk func(*jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			seen[describe(e)] = struct{}{}
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)

	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)

	if len(out) > MaxViolations {
		extra := len(out) - MaxViolations
		out = out[:MaxViolations]
		out = append(out, fmt.Sprintf("(and %d more)", extra))
	}
	return out
}
