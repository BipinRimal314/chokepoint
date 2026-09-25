package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"
)

// Entry is one decision read back from an audit log.
type Entry struct {
	// Session groups the records of one chokepoint process, which is one
	// agent session with one server.
	Session string
	At      time.Time
	Tool    string
	Method  string
	Effect  string
	Rule    string
	// Enforced is meaningful only when Effect is "deny": true for a call that
	// was refused, false for one monitor mode let through.
	Enforced bool
	Targets  []string
	// OutOfScope is how many of this call's targets fell outside the
	// workspace.
	OutOfScope int
	// Audited lists audit rules that matched.
	Audited []string
}

// Breach reports whether the entry is a policy violation, refused or not.
func (e Entry) Breach() bool { return e.Effect == "deny" }

// Read parses an audit log. A line that does not parse is reported through
// onBad with its line number and skipped, so one torn write at the end of a
// log that was cut off by a crash does not hide everything before it.
func Read(r io.Reader, onBad func(line int, err error)) ([]Entry, error) {
	var out []Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	line := 0
	for sc.Scan() {
		line++
		if len(sc.Bytes()) == 0 {
			continue
		}
		var rec spanRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			if onBad != nil {
				onBad(line, err)
			}
			continue
		}
		out = append(out, entryOf(rec))
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("read audit log: %w", err)
	}
	return out, nil
}

func entryOf(rec spanRecord) Entry {
	e := Entry{Session: rec.TraceID}
	if ns, err := strconv.ParseInt(rec.StartTimeUnixNano, 10, 64); err == nil {
		e.At = time.Unix(0, ns)
	}
	for _, a := range rec.Attributes {
		v := a.Value
		switch a.Key {
		case KeyMCPTool:
			e.Tool = str(v)
		case KeyMCPMethod:
			e.Method = str(v)
		case KeyEffect:
			e.Effect = str(v)
		case KeyRule:
			e.Rule = str(v)
		case KeyEnforced:
			e.Enforced = v.BoolValue != nil && *v.BoolValue
		case KeyTargets:
			e.Targets = strs(v)
		case KeyOutOfScope:
			if v.IntValue != nil {
				e.OutOfScope, _ = strconv.Atoi(*v.IntValue)
			}
		case KeyAudited:
			e.Audited = strs(v)
		}
	}
	// Logs written before chokepoint.policy.enforced existed had no monitor
	// mode, so every deny in them was enforced.
	if e.Effect == "deny" && !hasKey(rec, KeyEnforced) {
		e.Enforced = true
	}
	return e
}

func hasKey(rec spanRecord, key string) bool {
	for _, a := range rec.Attributes {
		if a.Key == key {
			return true
		}
	}
	return false
}

func str(v jsonValue) string {
	if v.StringValue != nil {
		return *v.StringValue
	}
	return ""
}

func strs(v jsonValue) []string {
	if v.ArrayValue == nil {
		if s := str(v); s != "" {
			return []string{s}
		}
		return nil
	}
	out := make([]string, 0, len(v.ArrayValue.Values))
	for _, item := range v.ArrayValue.Values {
		out = append(out, str(item))
	}
	return out
}
