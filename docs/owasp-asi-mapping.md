# OWASP Top 10 for Agentic Applications — control mapping

Which of the [OWASP Top 10 for Agentic Applications][owasp] risks chokepoint
addresses, which it partly addresses, and which it cannot touch.

Mapped against the release published **9 December 2025**. Category titles are
quoted from that release; if you are checking this against a later revision,
check the identifiers as well as the names — OWASP's earlier *Agentic AI —
Threats and Mitigations* material used a different taxonomy, and several
familiar names (*Excessive Agency*, *Cascading Hallucinations*, *Inadequate
Sandboxing*) either moved identifier or are not in the Top 10 at all.

**This is a control mapping, not a compliance claim.** Five of ten are
addressed to any real degree. That is what a proxy in one position on one
protocol can do, and a mapping that claimed more would be less useful.

| | Category | chokepoint |
|---|---|---|
| ASI01 | Agent Goal Hijack | **Partial** — constrains a hijacked agent; cannot see the hijack |
| ASI02 | Tool Misuse | **Enforced** — the project's primary control |
| ASI03 | Identity & Privilege Abuse | Not addressed — no identity layer under stdio |
| ASI04 | Agentic Supply Chain Vulnerabilities | **Partial** — rug pulls caught; the rest of the chain is not |
| ASI05 | Unexpected Code Execution | **Partial** — expressible in policy, not built in |
| ASI06 | Memory & Context Poisoning | **Partial** — constrains where context is read from |
| ASI07 | Insecure Inter-Agent Communication | Out of architecture — one agent, one server |
| ASI08 | Cascading Failures | Out of architecture — no cross-agent view |
| ASI09 | Human-Agent Trust Exploitation | **Partial** — by an unusual route; see below |
| ASI10 | Rogue Agents | **Partial** — the main detection target after ASI02 |

---

## ASI01 — Agent Goal Hijack

**Partial.** chokepoint reads JSON-RPC bytes. A hidden instruction that
redirects an agent lives in the model's context, not in the tool-call stream,
so the hijack itself is invisible here and always will be — this is a limit of
position, not of implementation.

What it does reach is the consequence. An agent working to someone else's goal
has to act, and acting means tool calls. A [declared workspace](../README.md#declaring-a-workspace)
is the strongest control available: an agent redirected at `/home/u/.ssh` is
out of bounds on its first call regardless of what convinced it to go there.

Do not read the decomposition score as an ASI01 control. It scores how varied
behaviour is, and a hijacked agent has no obligation to vary — see the
[single-tool sweep defect](../README.md#known-defect-a-single-tool-sweep-is-invisible).

## ASI02 — Tool Misuse

**Enforced.** This is what the project is for. Every `tools/call` is evaluated
before it is forwarded: per-tool allow/deny/audit rules in CEL, over the tool
name, decoded arguments, extracted targets, and live session state. Denials are
protocol-correct, so a refusal is a decision rather than an outage.

Beyond single-call inspection, the session is scored for decomposition — the
case where every individual call is legitimate and the sequence is not.

Volume is covered separately from shape. The score measures how *varied* a
session is, so a sweep run fast is not more suspicious to it than the same
sweep run slowly — which left misuse by sheer quantity invisible. Rules now
also see `calls_in_window` and `targets_in_window` over a configurable
`rate_window` (`high-fan-out-rate` in the example policy). These are counters
handed to policy rather than a token bucket, so the limit stays legible next to
every other rule and can be combined with the tool, the scope and the score.

Three limits, all measured and all in the README: a single-tool sweep scores a
constant 0.400 at any scale and no threshold catches it; a multi-tool sweep
evades the shipped threshold at **2× call overhead**; and that overhead does
not grow with the size of the objective — 2× at 20 targets, 2× at 320 — so a
larger theft is not a louder one. Tool misuse is the category chokepoint does
most about and it is still not closed.

## ASI03 — Identity & Privilege Abuse

**Not addressed.** Under stdio there is no identity to abuse: the proxy
supervises one child process and the session is the subprocess lifetime. There
are no tokens, no audiences, no principals.

This becomes addressable with the streamable-HTTP transport, where RFC 8707
audience-claim validation on bearer tokens is the confused-deputy defence and is
genuinely proxy-enforceable. Both are on the roadmap; neither is built.

## ASI04 — Agentic Supply Chain Vulnerabilities

**Partial — the rug pull is caught; the rest of the supply chain is not.**

An earlier version of this document recorded ASI04 as the cheapest unbuilt gap
in the list, on the grounds that `tools/list` responses already cross the proxy
and were being forwarded without inspection. That is now implemented.

Every advertised tool definition is fingerprinted on first sight and compared on
every later listing. A definition that changes mid-session — the rug pull, where
a server is approved benign and then mutates a description or widens a schema —
is reported to policy as `tool_definition_changed`, and the example policy
denies calls to a tool that has changed.

Three properties worth knowing:

- **Comparison is against the first listing, not the previous one**, so a server
  cannot launder a mutation by changing a definition and changing it back.
- **The whole definition is hashed**, not a chosen subset. A rug pull can hide
  in the description, the schema, an annotation, or a field this build has never
  heard of; picking fields to hash would be picking which mutations to miss.
- **Key order is not a change; array order is.** A server that re-serialises its
  tool list differently has not mutated anything, and a check that cried wolf
  there would be turned off within a day.

The fingerprint reports that a definition moved. It cannot say whether any
individual call exploited the move, and the call is what a policy has to decide
about. Argument validation closes that half: a tool's `inputSchema` is compiled
from the listing that established its baseline, and `tools/call` arguments are
checked against **that** schema rather than the current one
(`args-violate-declared-schema` in the example policy). A server that widens a
schema mid-session to admit an exfiltration argument therefore does not get to
ratify it — the widened version is never what the call is measured against.

It also catches the case with no mutation at all. MCP servers are lax about
enforcing their own declared schemas, so an argument a tool never advertised
can still reach it; the proxy holding the server to its published contract is a
control the server itself is not reliably providing.

Still not addressed under ASI04: provenance of the server binary, its
dependencies, or its install path. chokepoint checks what a server *says* about
itself against what it said earlier. It has nothing to say about where the
server came from.

What it does not do. First sight is the baseline, because a proxy cannot know
what an operator approved — only what the server said first. That makes this
"has this changed under us", not "is this what was reviewed", which is weaker
and is the honest description of what the position affords. It also says nothing
about the rest of the agentic supply chain: a server that is malicious from its
very first listing is not a rug pull and is not caught here, and neither is a
compromised dependency inside an otherwise honest server.

One ordering limit, recorded rather than fixed: the flag is set when the
`tools/list` **reply** is processed, so a client that pipelines a call ahead of
that reply is judged against the definitions seen so far. A conforming MCP
client cannot do this — it cannot call a tool it has not discovered — but a
batch harness can, and this project's own demo did until it was paced.
`TestFingerprintCheckNeedsTheListingFirst` pins the behaviour. Holding calls
until in-flight listings resolve would put a stall in the request path of every
session to defend against a client attacking itself.

## ASI05 — Unexpected Code Execution

**Partial, and it is the operator's policy doing the work.** Rules over tool
name and arguments express this directly — refusing a `shell` tool, refusing
`eval`-shaped arguments, refusing recursive destructive operations, as the
example policy does for recursive delete.

What chokepoint does not do is *know* which tools execute code. There is no
built-in notion of a dangerous tool, because MCP does not mark one and
guessing from names would produce a control that silently misses the server
whose executor is called `run_task`. The mechanism is real; the judgement is
yours.

## ASI06 — Memory & Context Poisoning

**Partial.** The agent's memory is not visible to a tool-call proxy, so
poisoning that has already happened cannot be detected here.

What is visible is retrieval. `resources/read` and `prompts/get` are how
context enters an agent through MCP, and chokepoint observes both — they count
toward session behaviour specifically so that an agent enumerating resources
instead of calling tools does not become a blind spot. With a workspace
declared, context read from outside the boundary is a policy decision like any
other.

That constrains *where* poison can enter through this channel. It says nothing
about content, nothing about memory already poisoned, and nothing about
poisoning that arrives by any route other than MCP.

## ASI07 — Insecure Inter-Agent Communication

**Out of architecture.** chokepoint sits between one agent and one tool server.
Agent-to-agent messaging does not traverse it. A federated deployment would
need cross-server tool-name qualification to prevent shadowing — that is on the
roadmap and is a different control from securing A2A traffic, which this is not
positioned to do at all.

## ASI08 — Cascading Failures

**Out of architecture.** Detecting a failure cascading between agents needs a
view across agents. chokepoint's view is one session.

The one honest thing to say is narrow: a deterministic inline block is a
circuit breaker within its own session, so a chokepointed agent stops rather
than continuing to emit. That bounds one participant's contribution to a
cascade. It is not cascade detection and should not be presented as any.

## ASI09 — Human-Agent Trust Exploitation

**Partial, by an unusual route.** The attack is an agent producing a confident,
polished account that leads a human to approve something harmful. Consent
rendering happens in the client host, which chokepoint is not, so it cannot
intervene at the point of approval.

What it can do is remove the agent's monopoly on the account. The
[session report](../README.md#the-session-report) and the
[evidence log](../README.md#compliance-evidence) are assembled from observed
JSON-RPC traffic, not from anything the agent says about itself. A reviewer
deciding whether to trust an explanation has an independent record of what
actually happened — where the calls went, what was refused, when the session
left its workspace.

An agent cannot talk its way out of its own traffic. That is a real contribution
to this category, and it is worth being precise that it helps a human who
chooses to look rather than intercepting a bad approval.

## ASI10 — Rogue Agents

**Partial — the main detection target after ASI02.** Misalignment, concealment
and self-directed action all have to become tool calls to have effect, and this
is the category the decomposition score was built for: broad, shallow,
non-repetitive traversal where each call is individually unremarkable.

Bounded by the same measured limits as ASI02. An agent that goes rogue without
varying its tool vocabulary defeats the score entirely and is caught, if at all,
by the workspace boundary.

---

## What a proxy in this position cannot do

Recorded so that absences are not mistaken for oversights:

- **Semantic intent.** Whether a call is *meant* well is not in the JSON-RPC
  bytes. Everything here reasons about behaviour and destination.
- **Tool-output mimicry.** An upstream server forging a plausible result needs
  orchestrator-side signing to detect; the proxy sees a well-formed response.
- **Consent rendering.** What a human is shown before approving is the client
  host's, and no proxy can substitute for it.
- **Anything outside the MCP session.** Context poisoned by another channel,
  agents talking to each other, failures cascading elsewhere.

## Verification

The identifiers and titles above are pinned by
`TestASIMappingMatchesTheStandard`, and every policy rule this document names is
checked to exist in `examples/policy.yaml`. A category renamed here without
being renamed in the test fails the build, which is the point: this file makes
claims about a public standard, and claims about public standards are exactly
the ones that rot quietly.

[owasp]: https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
