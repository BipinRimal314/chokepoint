# chokepoint

[![CI](https://github.com/BipinRimal314/chokepoint/actions/workflows/ci.yml/badge.svg)](https://github.com/BipinRimal314/chokepoint/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/BipinRimal314/chokepoint.svg)](https://pkg.go.dev/github.com/BipinRimal314/chokepoint)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A policy-enforcing proxy for Model Context Protocol tool servers.

It runs an MCP server as a child process and sits between it and the agent,
evaluating every tool call before forwarding it — and scoring the *sequence* of
calls for behaviour no single call reveals.

```bash
chokepoint --policy policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /srv
```

## See it work

```bash
./demo.sh
```

Drives the real binary against a real MCP server subprocess. The server answers
every call successfully, so every block you see comes from policy rather than
from something failing. It shows two calls refused for *what they are* (an SSH
key, cloud instance metadata) and then a 40-call sweep stopped for *what it adds
up to* — with the score and its breakdown printed, and the same run repeated
with metrics scraped live.

## Why this exists

My published research on cross-domain agent-misuse detection
([SSRN 6355658](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6355658),
[Zenodo](https://doi.org/10.5281/zenodo.18797847)) found that detection models
transfer between insider-threat logs and AI-agent traces — and so do their
blind spots. Structurally legitimate misuse (tool misuse, decomposed tasks,
distributed distillation) evades behavioural monitoring in both domains, and
the failure is **architectural, not a tuning problem**.

A monitor that reads traces after the fact can only describe what already
happened. chokepoint computes the same feature space *in the request path*,
where a decision can still change the outcome.

The rule that motivates the whole project looks like this:

```yaml
- name: halt-decomposed-sweep
  match: decomposition_score > 0.45 && session_targets > 25
  effect: deny
```

Every call it blocks is, on its own, an ordinary read of an ordinary path.

## What it does

- **Transparent by default.** With no `--policy`, every message is forwarded as
  the exact bytes that arrived. Put it in the path first, watch what your agent
  actually does, write rules against observed behaviour second.
- **CEL policies.** Per-tool allow/deny/audit rules over tool name, arguments,
  extracted targets, and live session state.
- **Live UBFS scoring.** The 20-feature Unified Behavioural Feature Schema from
  the paper, computed online over the tool-call stream.
- **Denials are protocol-correct.** A blocked call returns a well-formed
  JSON-RPC error with a matching id and an explanation. The connection stays
  up; a policy decision is not an outage.

## Policy

```yaml
default_effect: allow          # safe to install before it is configured

rules:
  # Deploy as `audit` first, watch the logs, then arm it as `deny`.
  - name: watch-writes
    match: tool.startsWith("write") || tool.startsWith("delete")
    effect: audit

  - name: no-credential-paths
    match: targets.exists(t, t.contains("/.ssh/") || t.endsWith(".pem"))
    effect: deny
    message: Credential material is out of scope; use the secret store.
```

Variables available to `match`:

| variable | type | meaning |
|---|---|---|
| `tool` | string | tool name, e.g. `read_file` |
| `method` | string | JSON-RPC method, e.g. `tools/call` |
| `args` | map | decoded tool arguments |
| `targets` | list\<string\> | target-like strings extracted from `args` |
| `session_calls` | int | calls made this session |
| `session_targets` | int | distinct targets touched this session |
| `decomposition_score` | double | UBFS decomposition score, 0.0–1.0 |

Rules are evaluated top to bottom; the first non-`audit` match wins. An
undeclared variable or a non-boolean `match` is a **load-time** error, not a
silent never-match — a policy engine that fails open on a typo reports
protection it is not providing.

## Calibration

A threshold picked without measuring is a guess, and a guess in a deny rule is
an outage waiting for the right Tuesday. Scores for 60-call sessions
(`go test ./internal/detect -run Calibration -v`):

| shape | score | breadth | novelty | entropy | lowRep |
|---|---|---|---|---|---|
| poll-one-file | 0.007 | 0.007 | 0.000 | 0.000 | 0.000 |
| focused-debug | 0.214 | 0.020 | 0.000 | 0.189 | 0.005 |
| build-pipeline | 0.225 | 0.020 | 0.000 | 0.200 | 0.005 |
| cyclic-sweep | **0.608** | 0.400 | 0.000 | 0.200 | 0.008 |
| exfil-crawl | **0.648** | 0.400 | 0.000 | 0.200 | 0.048 |
| randomised-sweep | **0.666** | 0.400 | 0.062 | 0.193 | 0.010 |

Highest benign 0.225, lowest suspicious 0.608, so any threshold in
**0.225–0.608** separates them. The example policy uses 0.45, and a test fails
if that value ever drifts outside the measured band.

My first draft of the example policy used 0.7 — above the whole band. It would
have shipped looking authoritative and never fired once. That is exactly the
failure this table exists to catch.

## Cost of evasion

Calibration answers *where do we set the threshold*. The question after it is
*what does it cost to get under the threshold we set* — and a detector's
honest specification includes its price of evasion
(`go test ./internal/detect -run Evasion -v`).

Attacker goal held fixed: reach 40 distinct targets. Levers: how many distinct
tools they cycle through, and how many filler calls they pad with. `*` marks a
session that reaches every target and still scores below 0.45.

| tools \ pad | 0 | 1 | 2 | 3 | 4 | 6 | 8 |
|---|---|---|---|---|---|---|---|
| 1 | **0.400\*** | 0.200\* | 0.133\* | 0.100\* | 0.080\* | 0.057\* | 0.044\* |
| 2 | 0.604 | 0.364\* | 0.265\* | 0.210\* | 0.175\* | 0.132\* | 0.107\* |
| 4 | 0.612 | 0.361\* | 0.258\* | 0.202\* | 0.167\* | 0.125\* | 0.100\* |
| 8 | 0.627 | 0.361\* | 0.255\* | 0.198\* | 0.163\* | 0.121\* | 0.096\* |
| 20 | 0.686 | 0.376\* | 0.261\* | 0.201\* | 0.164\* | 0.121\* | 0.096\* |
| 40 | 1.000 | 0.658 | 0.528 | 0.462 | 0.422\* | 0.374\* | 0.348\* |

**A multi-tool sweep evades at 2× overhead** — one filler call per real one,
80 calls to reach 40 targets. That cost is pinned by a test, so a weight change
that makes evasion cheaper fails the build.

**Timing is not a lever.** `Assess` weights only breadth, novelty, entropy and
repetition, so the temporal features the vector computes never reach the
decomposition score. The same sweep spaced one second apart and six hours
apart scores identically. Spreading an attack over days moves the vector and
not the verdict.

### Known defect: a single-tool sweep is invisible

The top-left cell is not an evasion, it is a hole. **A session that calls one
tool against any number of distinct targets scores exactly 0.400 — at 20
targets, at 5,000 targets, always.** Three of the four terms are structurally
zero for a single-tool sequence: one transition that repeats (novelty 0), one
symbol in the tool distribution (entropy 0), and maximal tool repetition
(low_repetition 0). Only `target_breadth` fires, it saturates at 1.0, and the
total pins at exactly the breadth weight.

Since the shipped threshold is 0.45, **`read_file` across every path on the
disk never crosses it.** That is the most obvious exfiltration pattern there
is, and it costs the attacker nothing — no padding, no timing, no knowledge of
this rule. Raising the breadth weight does not fix it either; it moves the
ceiling but leaves a single-tool sweep scoring a constant, which any threshold
either always catches or never does.

Fixing this needs a signal that survives a constant tool sequence — the
dependency-graph structure of the calls rather than their vocabulary
statistics. Until then the honest statement is that chokepoint scores *how
varied* an attack is, and an attacker who declines to vary pays nothing.
`TestSingleToolSweepIsUnderThreshold` pins the defect so it cannot be silently
fixed without rewriting this section.

## Telemetry

Both subsystems are off by default and independently switchable.

```bash
chokepoint --policy policy.yaml \
  --metrics-addr :9090 \
  --otlp-endpoint localhost:4317 \
  -- npx -y @modelcontextprotocol/server-filesystem /srv
```

Scraped mid-session during a 40-call sweep against the example policy:

```
chokepoint_tool_calls_total{effect="allow",tool="read_file"} 7
chokepoint_tool_calls_total{effect="deny",tool="read_file"}  3
chokepoint_policy_denials_total{rule="halt-decomposed-sweep",tool="grep"} 4
chokepoint_decomposition_score 0.6115384615384616
chokepoint_session_calls   40
chokepoint_session_targets 40
chokepoint_abandoned_spans_total 0
```

Plus `chokepoint_tool_call_duration_seconds` (upstream latency),
`chokepoint_policy_audits_total`, and `chokepoint_upstream_errors_total`.
`/healthz` sits alongside `/metrics`.

Traces emit one `mcp.tool_call` span per call, carrying the tool, the policy
effect and rule, the decomposition score, and the extracted targets.

Three decisions in here are load-bearing:

- **Targets are never metric labels.** They are attacker-influenced and
  unbounded; one series per distinct file path is a denial of service against
  your own monitoring. They go on spans, where high cardinality is fine. A test
  asserts no metric label ever contains a target.
- **An unscoreable session reports `NaN`, not `0`.** A registered gauge reports
  something from the moment it exists, and `0` is a real score meaning "nothing
  suspicious" — so a brand-new session would render as definitively safe rather
  than as not yet measured. `NaN` is Prometheus's "no value" and draws a gap.
- **Denied calls end their span immediately and record no latency.** No upstream
  response is coming, so holding the span open would leak one per denial — the
  calls an operator most wants to see — and recording a latency for a call that
  never left the process would drag the upstream's own distribution toward zero.

Spans for calls the upstream never answers are closed after `SpanTTL`
(5 minutes) and counted in `chokepoint_abandoned_spans_total`, so a hung server
shows up as a number rather than as unbounded memory growth.

Asking for telemetry that cannot start is a startup failure, not a warning: an
operator who believes they have visibility and does not is worse off than one
who gets an error.

## Known limitations

Stated plainly, because a detector whose limits are undocumented invites
exactly the over-trust the research warns about.

- **A single-tool sweep scores a constant 0.400 and never crosses the
  threshold.** See [Known defect](#known-defect-a-single-tool-sweep-is-invisible)
  above. This is the most serious limit here.
- **Breadth carries the score.** At 60 calls, `target_breadth` contributes
  0.007–0.400 while `transition_novelty` contributes 0.000–0.062. A quarter of
  the weight is doing almost nothing. Novelty does not decay gradually with
  session length — it falls off a cliff: measured over a looping vocabulary of
  20 it reads 1.000 at 20 calls, 0.050 at 40, and **exactly 0.000 from 60
  onward**, because once a session cycles its vocabulary twice every transition
  has been seen more than once. A sweep written as an ordinary loop therefore
  forfeits a quarter of the weight without attempting evasion, capping a
  looping attacker at 0.75. The weights are not yet re-derived from labelled
  data.
- **4 of 20 UBFS features are not computed here.** Three need a peer or
  historical baseline this process does not have on a cold start
  (`event_rate_zscore`, `peer_distance`, `self_deviation`); one is not derivable
  from MCP traffic at all (`privilege_deviation_index`, since the protocol
  carries no permission level). Those report 0.0, the schema's neutral value,
  and `Vector.Coverage()` says so per feature rather than letting a zero read as
  "normal". The count is asserted by a test, so this sentence cannot drift out
  of step with the code.
- **Target extraction is heuristic.** MCP does not standardise argument
  schemas, so targets are pulled from conventional key names (`path`, `uri`,
  `host`, …). A server using an unusual key will under-report breadth.
- **Evasion is straightforward if you know the rule, and now it is priced.**
  Padding a sweep with repeated calls lowers breadth ratio and entropy. A
  multi-tool sweep gets under 0.45 at **2× call overhead**; a single-tool sweep
  pays nothing. See [Cost of evasion](#cost-of-evasion). This raises the cost of
  a decomposed attack; it does not close the class.
- **stdio transport only.** Streamable-HTTP and SSE are not implemented yet.

## Design

```
cmd/chokepoint      CLI, process supervision, signal handling
internal/jsonrpc    JSON-RPC 2.0 codec — preserves original bytes exactly
internal/proxy      bidirectional pump, interceptor interface
internal/policy     CEL evaluation, target extraction
internal/detect     UBFS feature computation and decomposition scoring
internal/gateway    joins the three; the only package that knows MCP shapes
```

Two decisions worth calling out:

**Messages keep their original bytes.** Decoding and re-encoding would reorder
object keys, drop fields this build has never heard of, and renumber floats —
all invisible until an upstream server rejects a request nobody can reproduce.
Fields are decoded lazily; anything forwarded unmodified is forwarded verbatim.

**The two directions are not symmetric.** A client closing its end means "no
more requests", not "discard the answers to the ones already sent" — so that
side signals end-of-input upstream and waits, bounded by a drain timeout. A
server closing its end ends the session, because nothing more can arrive and a
waiting agent would hang forever. Getting this wrong dropped 40 of 41 replies,
and only an end-to-end run against a real subprocess caught it.

## Development

```bash
go test ./...                 # unit tests
go test -race -count=3 ./...  # what CI runs
go build -o chokepoint ./cmd/chokepoint

# end-to-end against a mock MCP server
./chokepoint --policy examples/policy.yaml -- python3 testdata/mock_mcp_server.py
```

## Status

Working and tested; not yet deployed anywhere real. Next: OpenTelemetry spans
and Prometheus metrics, then streamable-HTTP transport, then a k3s DaemonSet
manifest.

## License

Apache-2.0
