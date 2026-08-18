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

## Install

Tagged releases carry static binaries for Linux, macOS and Windows on amd64 and
arm64, a `checksums.txt`, and a build provenance attestation.

```bash
# from a release
tar xzf chokepoint_<version>_linux_amd64.tar.gz
sha256sum -c checksums.txt --ignore-missing
gh attestation verify chokepoint_<version>_linux_amd64.tar.gz --repo BipinRimal314/chokepoint

# or from source
go install github.com/BipinRimal314/chokepoint/cmd/chokepoint@latest
```

Verifying the attestation is worth the extra command here specifically: this is
a binary you are installing in order to *deny* tool calls, which makes it worth
substituting. Pin a tag — chokepoint is pre-1.0 and both the policy format and
the score's weights can still move between minor versions.

## See it work

```bash
./demo.sh
```

Drives the real binary against a real MCP server subprocess. The server answers
every call successfully, so every block you see comes from policy rather than
from something failing. It shows three kinds of refusal — two calls refused for
*what they are* (an SSH key, cloud instance metadata), one for *where it goes*
(a path that reads as inside the workspace and resolves outside it), and a
40-call sweep stopped for *what it adds up to* — with the score and its
breakdown printed, then the same run repeated three times more: as a session
report, as an evidence log, and with metrics scraped live.

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
- name: watch-decomposed-sweep
  match: decomposition_score > 0.45 && session_targets > 25
  effect: audit

- name: halt-decomposed-sweep
  match: decomposition_score > 0.45 && session_targets > 25 && session_out_of_scope > 0
  effect: deny
```

Every call it blocks is, on its own, an ordinary read of an ordinary path.

The score is recorded whenever it trips and acted on only with corroboration,
because a wide, varied, low-repetition session is what thorough work looks like
as well as what theft looks like — a linter rewriting a repository scores
`0.603` while a single-tool sweep of identical breadth scores `0.400`, and no
threshold sits between those. [docs/single-tool-sweep.md](docs/single-tool-sweep.md)
has the measurements. Leaving the declared workspace is the corroboration, and
`session_out_of_scope` is zero where no workspace is declared, so the deny is
inert there rather than guessing.

## What it does

- **Transparent by default.** With no `--policy`, every message is forwarded as
  the exact bytes that arrived. Put it in the path first, watch what your agent
  actually does, write rules against observed behaviour second.
- **CEL policies.** Per-tool allow/deny/audit rules over tool name, arguments,
  extracted targets, and live session state.
- **Live UBFS scoring.** The 20-feature Unified Behavioural Feature Schema from
  the paper, computed online over the tool-call stream.
- **A declared workspace.** Optionally say where the agent belongs, and every
  call is checked against it on the resolved path rather than the raw string —
  so a boundary is not one `../` from useless. Unlike the score, this verdict
  does not move with session length, tool vocabulary, padding, or timing.
- **Denials are protocol-correct.** A blocked call returns a well-formed
  JSON-RPC error with a matching id and an explanation. The connection stays
  up; a policy decision is not an outage.
- **A session report, not just a score.** `--report` prints where the session
  went, what it was denied for, and how it sat relative to its workspace — the
  part a reviewer can act on. See [The session report](#the-session-report).
- **An evidence log.** `--audit-log` appends every decision as OTLP/JSON with
  the OTel GenAI semantic conventions, ingestible by compliance tooling as-is.
  See [Compliance evidence](#compliance-evidence).
- **Tool definitions are fingerprinted.** Every `tools/list` is compared against
  the session's first, so a server that is approved benign and then mutates a
  description — the rug pull — is caught on the next call. See
  [Tool-definition fingerprinting](#tool-definition-fingerprinting).
- **Arguments are checked against the schema the tool published.** Validated
  against the *first* `inputSchema` seen, so a server that widens one
  mid-session to admit an argument it previously refused does not get to ratify
  it. See [Schema validation](#schema-validation).
- **Recent activity is counted, not throttled.** `calls_in_window` and
  `targets_in_window` are handed to rules over a configurable `rate_window`, so
  the limit stays in your policy rather than compiled in. See
  [Rate](#rate).

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
| `calls_in_window` | int | calls inside `rate_window` |
| `targets_in_window` | int | distinct targets inside `rate_window` |
| `decomposition_score` | double | UBFS decomposition score, 0.0–1.0 |
| `tool_definition_changed` | bool | this tool changed since the first `tools/list` |
| `session_tools_changed` | int | distinct tools changed since the first listing |
| `schema_known` | bool | this tool declared an `inputSchema` that compiled |
| `args_valid` | bool | arguments satisfied it; **true when `schema_known` is false** |
| `schema_violations` | list\<string\> | what failed, bounded and sorted |
| `scope_declared` | bool | whether a `workspace` was declared |
| `out_of_scope` | list\<string\> | this call's targets outside the workspace |
| `session_out_of_scope` | int | distinct out-of-scope resources this session |

Rules are evaluated top to bottom; the first non-`audit` match wins. An
undeclared variable or a non-boolean `match` is a **load-time** error, not a
silent never-match — a policy engine that fails open on a typo reports
protection it is not providing.

### Declaring a workspace

A `workspace` says where the agent is supposed to reach. Calls landing outside
it are reported to rules through `out_of_scope` and `session_out_of_scope`:

```yaml
workspace:
  - /srv/data
  - https://api.example.com/v1

rules:
  - name: outside-declared-workspace
    match: scope_declared && out_of_scope.size() > 0
    effect: deny
```

This is a different kind of check from the score, and better where it applies.
A score asks how unusual the behaviour looks and can be argued with; a
workspace asks whether the call landed inside the boundary its operator
declared. **It is the answer to the [single-tool sweep](#known-defect-a-single-tool-sweep-is-invisible)
below** — that sweep scores a constant whatever it reads, so no threshold
catches it, but it is out of bounds on its first call and every call after.

Containment is tested on the **normalised** resource, never the raw string, so
`/srv/data/../../etc/shadow` is out of scope while `/srv/data/sub/../f01` is
not. Boundaries are segment-aligned: `/srv/data` does not contain
`/srv/database`. Scheme, host and Windows volume must all match. A traversal
that leaves the workspace is counted separately from a plainly external target
— both are denied, but only one had to be constructed.

Declaring a workspace is **opt-in, and the default is none**. Without it
`scope_declared` is false, nothing is ever out of scope, and rules guarding on
it stay inert — so a policy copied from a scoped deployment fails open rather
than denying every call on a deployment whose operator never said where the
agent belongs. That limit is the honest one: this only works where somebody can
answer that question.

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

**Order is not a lever either, and it points the wrong way.** Randomising which
tool is used next *raises* the score — 0.757 against 0.618 for the same
vocabulary walked cyclically — because `transition_novelty` rewards
unpredictability. An attacker's best sequence is the most boring one available,
so the evasive strategy and the sophisticated-looking strategy run in opposite
directions (`go test ./internal/detect -run Ordering -v`).

**Size is not a lever, which is the worst of the three.** The price of evasion
is 2× overhead at 20 targets and still 2× at 320. Breadth saturates against
session length and novelty has already collapsed to zero by 60 calls, so a
larger theft is not a louder one — the attacker pays the same multiple
regardless of how much they take. A test asserts the overhead never rises with
length, since that is breadth saturation stated as a check.

### Novelty falls off a cliff

`transition_novelty` does not decay gradually with session length. Measured
over a looping vocabulary of 20 it reads **1.000 at 20 calls, 0.050 at 40, and
exactly 0.000 from 60 onward** — once a session cycles its vocabulary twice,
every transition has been seen more than once and the feature is dead.

A sweep written as an ordinary loop therefore forfeits a quarter of the scoring
weight without attempting evasion, which caps a looping attacker at 0.75 rather
than 1.0. The shipped 0.45 threshold sits at roughly 60% of the range actually
achievable against such an attacker, not 45%.

Those three figures are quoted elsewhere, so `TestNoveltyCliff` reproduces them
and fails if either the detector or the claim moves.

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

Fixing this *in the score* needs a signal that survives a constant tool
sequence — the dependency-graph structure of the calls rather than their
vocabulary statistics. That is not done — one candidate was tried and refuted,
and [docs/single-tool-sweep.md](docs/single-tool-sweep.md) records why, along
with a false positive it turned up: a benign wide session that varies its tools
is denied, while a single-tool sweep of identical breadth is allowed. The
honest statement about the score is unchanged: chokepoint scores *how varied* an
attack is, and an attacker who declines to vary pays nothing. `TestSingleToolSweepIsUnderThreshold` pins the
defect so it cannot be silently fixed without rewriting this section.

**What does stop it is a [declared workspace](#declaring-a-workspace)**, and
only because it asks a different question. Scope does not care how varied the
behaviour is; it asks whether the call landed where the agent was sent. The
sweep is out of bounds on its first call and stays out of bounds at 20 targets
and at 5,000 — `TestScopeVerdictIsScaleInvariant` asserts both halves, failing
if the sweep ever starts scoring above the threshold *or* if scope stops
catching it. `TestSingleToolSweepIsStoppedByScope` runs the same sweep through
the real gateway.

Read the mitigation for exactly what it is. It requires an operator who can
declare where the agent belongs, it says nothing about a sweep confined to the
workspace, and it does not repair the score — the defect above is still there,
underneath it.

## Tool-definition fingerprinting

A server advertises benign tools, gets approved, and then changes one. The agent
re-reads the list, finds new instructions inside a description or a widened
schema, and acts on them. The call that follows is unremarkable — it matches
what the server now advertises — which is exactly why scoring the call stream
cannot see it, and why the check has to be on the definitions.

Every `tools/list` reply is fingerprinted and compared against the session's
first. A tool that has changed is reported to policy:

```yaml
- name: tool-definition-changed
  match: tool_definition_changed
  effect: deny
```

```
allowed #1  tools/list  (benign definitions)
allowed #2  read_file   before the mutation
allowed #3  tools/list  (server rug-pulls here)
BLOCKED #4  read_file   after the mutation
        rule: tool-definition-changed
```

The blocked call is identical in shape to the allowed one. What changed was the
definition it was made against. `./demo.sh` runs this against the real binary.

- **Compared against the first listing, not the previous one** — a server cannot
  launder a mutation by changing a definition and changing it back.
- **The whole definition is hashed.** Description, schema, annotations, and
  fields this build has never heard of. Choosing which fields to hash would be
  choosing which mutations to miss.
- **Key order is not a change; array order is.** A server that re-serialises its
  tool list has not mutated anything.
- **Listings are never gated.** The mutation has already happened by the time it
  is visible, and refusing discovery would break an agent that has done nothing
  wrong. The useful moment is the next call to the tool that changed.

Limits, stated plainly: first sight is the baseline, so this is "has this changed
under us" rather than "is this what was reviewed" — a server malicious from its
first listing is not a rug pull and is not caught. And the flag is set when the
listing *reply* is processed, so a client that pipelines a call ahead of that
reply is judged against what has been seen so far; a conforming MCP client
cannot, but a batch harness can.

## Rate

The score measures how *varied* a session is, so a sweep run quickly is not more
suspicious to it than the same sweep run slowly. That leaves volume — OWASP
ASI-02, tool misuse by sheer quantity — invisible. Two counters close it:

```yaml
rate_window: 1m

rules:
  - name: high-fan-out-rate
    match: targets_in_window > 100
    effect: audit
```

`rate_window` is configuration; the limit is a rule. There is deliberately no
`max_calls` setting to go with it. A token bucket would move the decision into
the binary, where it cannot be read next to the other rules and cannot be
combined with the tool, the scope or the score — and a rate limit that cannot
say *which* tool it is limiting is not much of a control.

**Use `targets_in_window` before `calls_in_window`.** An agent retrying one file
is fast and narrow; a sweep is fast and wide. Only the second is evidence of
anything, and the call counter alone cannot tell them apart.

Both counters include the call being evaluated, so a rule refuses the request
that completes a burst rather than the one after it.

The counters never enforce on their own. Write no rate rule and two hundred
calls in a row are all forwarded — `TestRateCountersDoNotEnforceOnTheirOwn`
pins that.

**Limit worth knowing:** the counts are bounded by retained history. If
`rate_window` reaches further back than `MaxCalls` allows, the count is a floor
rather than the number, and a rule reading it under-fires. That case is flagged
internally as `Truncated`; with the default 10,000-call retention it needs a
window holding more than ten thousand calls to occur.

## Schema validation

MCP servers are lax about enforcing their own `inputSchema`, so an argument a
tool never declared can still reach it. The proxy already holds the tool
definitions, so it can hold the server to the contract it published:

```yaml
- name: args-violate-declared-schema
  match: schema_known && !args_valid
  effect: audit
```

Validation is against the schema from the **first** `tools/list`, the same
baseline rule the fingerprint uses. That is what makes this more than a second
copy of the server's own validation: a server that widens a schema mid-session
to admit an exfiltration argument does not get to ratify it. The fingerprint
tells you the definition moved; this refuses the individual call that exploits
the move.

**`schema_known` is the guard and is not optional.** Most tools in the wild ship
no schema at all. "Nothing to check against" and "checked and clean" are both an
empty violation list and opposite facts, so a rule written as bare `!args_valid`
would deny every unschema'd tool. `args_valid` is `true` when nothing was
checked, so that mistake fails open rather than closed — but write the guard
anyway.

Three deliberate refusals to be clever:

- **A schema that will not compile disables the check for that tool** and is
  recorded, rather than failing closed. An unsupported dialect is a gap in
  coverage, not evidence about the call.
- **Remote `$ref`s are never fetched.** A proxy that dialled out to a URL named
  in a tool definition while deciding whether to allow a call would be a better
  vulnerability than the one this closes.
- **Violation strings are bounded and sorted.** They are attacker-influenced in
  both content and number, and they land in the evidence log and the policy
  environment on every call.

## The session report

A score is not an answer. `0.677` tells a reviewer that something looked broad
and nothing about what to do, and the two sessions most worth telling apart
produce the same number by construction. `--report` prints where the session
actually went:

```bash
chokepoint --policy policy.yaml --report -- python3 testdata/mock_mcp_server.py
```

```
chokepoint session report

  44 calls carried a resource, 44 distinct
  decomposition score: 0.666  (target_breadth 0.400, action_entropy 0.181, ...)
  22 calls denied:
    halt-decomposed-sweep            19
    no-cloud-metadata                1
    no-credential-paths              1
    outside-declared-workspace       1

  workspace: 41 of 44 calls inside
    3 outside, in 3 distinct place(s)
    1 reached by a path that read as inside the workspace
    first left the workspace at call 1

  outside the workspace
                                       calls  distinct  first
    /etc                                   1         1      3
    /home                                  1         1      1
    http://169.254.169.254                 1         1      2

  where it went, by root
                                       calls  distinct  first
    /srv                                  41        41      0
    ...
```

It reports rather than judges. The detector's verdict is included and labelled;
the resource and scope sections are the facts a reviewer can overrule it with.
Three things it deliberately will not do:

- **Show a score it does not have.** A session below `MinCallsForScore` reads
  "not scoreable", not `0.000` — the same distinction the metrics layer makes
  by reporting `NaN`.
- **Show an empty workspace section.** With no workspace declared the section
  is omitted, because "0 calls outside" would be a clean bill of health for a
  session nobody set a boundary for.
- **Reorder between runs.** Groups sort by call count then name, so two
  sessions can be diffed against each other. A test renders the same session
  twenty times and fails on any difference.

Tables are bounded (10 groups each from the CLI), because the session most
worth reporting on is exactly the one with thousands of groups.

## Compliance evidence

A [control mapping against the OWASP Top 10 for Agentic
Applications](docs/owasp-asi-mapping.md) states which of the ten risks
chokepoint addresses and which it cannot — four of ten to any real degree, one
of the absences being merely unbuilt rather than architectural. Its identifiers
and titles are pinned to the standard by a test.


`--audit-log` appends every tool-call decision to a file as OTLP/JSON spans,
one per line:

```bash
chokepoint --policy policy.yaml --audit-log decisions.jsonl \
  -- npx -y @modelcontextprotocol/server-filesystem /srv
```

The format is deliberate. Records carry the **OTel GenAI semantic conventions**
(`gen_ai.operation.name`, `gen_ai.tool.name`, `gen_ai.tool.call.id`) alongside
chokepoint's own attributes, so the log is readable by tooling that never heard
of this project rather than a bespoke format needing its own parser. The
attribute set has one definition shared with the trace exporter, so a span and
an evidence record cannot describe the same decision differently.

Verified against [ai-trace-auditor](https://github.com/BipinRimal314/ai-trace-auditor):
a 30-call demo session ingests as **one trace, 30 spans, all classified as tool
calls**, and produces a clause-level gap report against the EU AI Act, ISO
42001, NIST AI RMF and SOC 2. chokepoint produces the runtime evidence; the
auditor turns it into the artefact.

What that does and does not mean: the auditor scores *trace field coverage* —
which required fields are present in the log — not legal compliance, which needs
organisational measures and review that no log can supply. What an inline proxy
does contribute is the runtime half that after-the-fact tooling cannot: NIST AI
RMF **MANAGE 2.4** asks for a mechanism to deactivate a system behaving
inconsistently with its intended use, and EU AI Act **Art 14** for oversight
able to intercept or halt at runtime. A deterministic blocking decision, logged,
is evidence for those in a way a monitor that only describes what already
happened is not.

Three properties the log is built for:

- **Append-only, flushed per record.** A process that dies mid-session still
  leaves everything it decided up to that point. The file is opened with
  `O_APPEND` and never truncated, so a restart does not erase the history.
- **Absent facts are omitted, not zeroed.** No `decomposition_score` on a
  session too short to have one; no scope attributes where no workspace was
  declared. A recorded `0.0` would assert that the session was measured and
  found unremarkable.
- **Decisions, not outcomes.** It records what was permitted and refused, which
  is what an audit asks. Whether the upstream then succeeded lives in the traces
  and metrics; correlating it here would mean holding records open and writing
  them out of order, costing the append-only property that makes the log worth
  trusting.

It inherits the sensitivity of what it records — targets are file paths,
hostnames and query strings. Treat it as being as confidential as the data the
agent was working on.

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

## Kubernetes (k3s)

Manifests in [`deploy/k3s/`](deploy/k3s/), with the reasoning in
[`deploy/k3s/README.md`](deploy/k3s/README.md).

The shape is not the obvious one, and it follows from the transport. chokepoint
intercepts a session by being the process the agent spawns, so it has to be
inside the agent's container at exec time — a `Deployment` with a `Service` in
front of it would have nothing on its stdin. A DaemonSet therefore stages the
binary on every node and agent pods mount it read-only, the same shape as a CNI
plugin installer.

Metrics come from each agent pod rather than from an aggregating Service, which
is also the more useful arrangement: `chokepoint_policy_denials_total` per agent
answers a question, summed across a cluster it does not.

## Known limitations

Stated plainly, because a detector whose limits are undocumented invites
exactly the over-trust the research warns about.

- **A single-tool sweep scores a constant 0.400 and never crosses the
  threshold.** See [Known defect](#known-defect-a-single-tool-sweep-is-invisible)
  above. This is the most serious limit here. A declared workspace stops the
  sweep without repairing the score, and only where one can be declared.
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
  `host`, …). A server using an unusual key will under-report breadth — and
  will under-report scope violations too, since a target nobody extracted is a
  target nobody can place inside or outside a workspace.
- **A workspace needs an operator who can declare one.** It is opt-in and off
  by default, it says nothing about a sweep that stays inside the boundary, and
  a workspace wide enough to be convenient is worth proportionately less. The
  containment check itself is sound — normalised, segment-aligned,
  traversal-resistant — but it can only be as good as the boundary it is
  given.
- **Evasion is straightforward if you know the rule, and now it is priced.**
  Padding a sweep with repeated calls lowers breadth ratio and entropy. A
  multi-tool sweep gets under 0.45 at **2× call overhead**; a single-tool sweep
  pays nothing. See [Cost of evasion](#cost-of-evasion). This raises the cost of
  a decomposed attack; it does not close the class.
- **Tool fingerprinting baselines on first sight.** A proxy cannot know what an
  operator approved, only what the server said first, so a server that is
  malicious from its opening listing is not a rug pull and is not caught. See
  [Tool-definition fingerprinting](#tool-definition-fingerprinting).
- **stdio transport only.** Streamable-HTTP and SSE are not implemented yet.
  Several controls are gated behind that; see
  [What stdio cannot close](#what-stdio-cannot-close).

## What stdio cannot close

Some controls are not missing because nobody wrote them. They need a transport
that carries the thing being checked, and under stdio there is no such thing to
check — a session is a subprocess lifetime, there are no headers, and there is
no token. Listing them as open TODOs would misrepresent the work: they are
blocked, not pending.

| control | needs | why it is inert under stdio |
|---|---|---|
| Session identity | streamable-HTTP | A session *is* the subprocess. There is nothing to bind, spoof, or validate. |
| `Origin` validation → 403 | HTTP request headers | The DNS-rebinding attack it defends against requires a browser and a network listener; there is neither. |
| Header/body disagreement → 400 | HTTP + `Mcp-Param-*` | A request-smuggling defence for a request that is one line on a pipe. |
| RFC 8707 audience validation | Bearer tokens | The confused-deputy defence needs a token to inspect. stdio has no auth layer at all. |
| Cross-server shadowing | several backends | chokepoint proxies exactly one child process. Two servers cannot collide in a namespace of one. |

The first four become live the moment an HTTP transport lands, and the design
note that matters is recorded now rather than rediscovered then: **the
2026-07-28 spec revision deprecates `Mcp-Session-Id` and tells proxies to
ignore it**, while session scoping is the whole basis of this project's score.
Any transport work has to put session identity behind an abstraction with two
backends — the header for older revisions, and a reconstructed identity (a
bound OAuth token, or `traceparent` from the JSON-RPC `_meta` object) for newer
ones. Hard-coding either is the mistake available here.

Three further controls are not blocked by transport but are **not enforceable
from this position at all**, and are recorded so nobody attempts them:

- **In-prompt confusion.** Semantic intent is not in the JSON-RPC bytes.
- **Tool-output mimicry.** Needs orchestrator-side signing of results.
- **Human-in-the-loop consent rendering.** Belongs to the client host.

## Design

```
cmd/chokepoint      CLI, process supervision, signal handling
internal/jsonrpc    JSON-RPC 2.0 codec — preserves original bytes exactly
internal/proxy      bidirectional pump, interceptor interface
internal/policy     CEL evaluation, target extraction
internal/detect     UBFS features, decomposition scoring, resource normalisation
                    and workspace containment
internal/gateway    joins the three; the only package that knows MCP shapes,
                    and renders the session report
internal/audit      canonical decision attributes + OTLP/JSON evidence log
internal/inventory  tool-definition fingerprinting and mutation detection
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

# the cost of the read paths, at 10,000 retained calls
go test ./internal/detect -bench . -benchmem -run '^$' -count=5

# the release build, without tagging anything
goreleaser check && goreleaser release --snapshot --clean
```

Nothing in CI asserts on the benchmarks. A timing threshold on a shared runner
fails for reasons unrelated to the code, and a flaky gate is one people learn
to ignore — so they are there to be read when changing `Session`'s read paths,
not to pass.

## Status

Working and tested, and now exercised on a real cluster: `v0.2.0` installs via
the k3s DaemonSet, and an agent pod in that cluster has been through a scripted
session where five policy rules produced real refusals. What that run did and
did not establish — the agent and the tool server were both stand-ins, and only
the deterministic rule path ran — is written up in
[docs/first-cluster-run.md](docs/first-cluster-run.md).

Nobody is running it against a production agent yet.

Everything stdio can support is built: policy, live scoring, the declared
workspace, the session report, the evidence log, telemetry, tool-definition
fingerprinting, schema validation, rate counters, and the k3s manifests.

Two things are left, and they are different kinds of thing.

- **Streamable-HTTP transport**, which unblocks four controls that have nothing
  to check under stdio — see [What stdio cannot close](#what-stdio-cannot-close).
  Read the note there about session identity before starting it.
- **Making a single-tool sweep scoreable at all.** This is the more serious of
  the two and it is a research problem, not a port: it needs a signal that
  survives a constant tool sequence, which means the dependency-graph structure
  of the calls rather than statistics over their vocabulary. See
  [Known defect](#known-defect-a-single-tool-sweep-is-invisible).

Those two, the smaller items behind them, and what is verified rather than
merely tested, are kept in order in
[docs/project-state.md](docs/project-state.md).

## License

Apache-2.0
