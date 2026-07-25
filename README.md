# chokepoint

A policy-enforcing proxy for Model Context Protocol tool servers.

It runs an MCP server as a child process and sits between it and the agent,
evaluating every tool call before forwarding it — and scoring the *sequence* of
calls for behaviour no single call reveals.

```bash
chokepoint --policy policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /srv
```

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

## Known limitations

Stated plainly, because a detector whose limits are undocumented invites
exactly the over-trust the research warns about.

- **Breadth carries the score.** At 60 calls, `target_breadth` contributes
  0.007–0.400 while `transition_novelty` contributes 0.000–0.062. A quarter of
  the weight is doing almost nothing: with a small tool vocabulary and a long
  session, nearly every transition repeats. Novelty is informative for short
  sessions and large tool vocabularies, and close to inert otherwise. The
  weights are not yet re-derived from labelled data.
- **8 of 20 UBFS features are unobservable here.** Token counts and model
  identities are not in MCP tool traffic; peer- and self-baseline features need
  history this process does not have on a cold start. Those report 0.0, the
  schema's neutral value, and `Vector.Coverage()` says so per feature rather
  than letting a zero read as "normal".
- **Target extraction is heuristic.** MCP does not standardise argument
  schemas, so targets are pulled from conventional key names (`path`, `uri`,
  `host`, …). A server using an unusual key will under-report breadth.
- **Evasion is straightforward if you know the rule.** Padding a sweep with
  repeated calls lowers breadth ratio and entropy. This raises the cost of a
  decomposed attack; it does not close the class.
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
