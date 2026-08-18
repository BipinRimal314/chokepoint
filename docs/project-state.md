# Project state

Where chokepoint is, what has actually been verified, and what to pick up next.
Written so that someone returning after a gap — or arriving for the first time —
does not have to reconstruct it from the commit log.

**Last updated: 18 August 2026, `v0.2.0`.**

This file holds judgement and sequencing. It deliberately does not restate the
measured numbers or the deployment instructions, because duplicated facts drift
apart: the detector's limits and their figures live in
[`README.md`](../README.md), the cluster evidence in
[`first-cluster-run.md`](first-cluster-run.md), and the deployment in
[`deploy/k3s/README.md`](../deploy/k3s/README.md).

## Where it is

Working, released, and now exercised on a real cluster rather than only in
tests.

`v0.2.0` was a minor bump rather than a patch because two feature commits since
`v0.1.0` extended the policy language — `schema_known`, `args_valid`,
`schema_violations` from schema fingerprinting, and `calls_in_window`,
`targets_in_window` from the budget work. A policy written against those will
not load on `0.1.0`.

Everything stdio can support is built: the policy engine, live decomposition
scoring, the declared workspace, tool-definition fingerprinting, schema
validation, rate counters, the session report, the audit log, telemetry, the
k3s manifests, and a runnable verification fixture in `deploy/k3s/verify/`.

## What is actually verified

The distinction between "tested" and "deployed and observed" is worth keeping
sharp, because for most of this project's life the answer was the former.

**Measured on a cluster** (k3s v1.36.3+k3s1, single node): the installer stages
a verified binary; a nonexistent version fails loudly without damaging a working
install; an upgrade lands in place; an agent pod execs the staged binary with
the proxy genuinely in the process path; five policy rules produce real
refusals, one audits, one control call is allowed; a policy that does not
compile crashes the pod and names the rule, failing closed.

**Still inference**, and stated as such in the record: anything multi-node;
atomicity of the rename under a concurrent `exec`; and the behaviour of a real
MCP client, since both the agent and the tool server in the fixture were
stand-ins. The behavioural detector has never scored a session in a cluster —
the fixture is seven calls, which correctly reports no score at all.

Full evidence, including the parts that went nowhere, is in
[`first-cluster-run.md`](first-cluster-run.md).

## What is blocked rather than pending

Four controls need a transport that carries the thing being checked, and stdio
carries none of it — session identity, `Origin` validation, header/body
disagreement, RFC 8707 audience validation. A fifth, cross-server shadowing,
needs more than one backend. Listing them as open work would misrepresent them.
See [What stdio cannot close](../README.md#what-stdio-cannot-close).

Three further controls are not enforceable from this position at all and should
not be attempted here: in-prompt confusion, tool-output mimicry, and
human-in-the-loop consent rendering.

## Next, in order

1. **Make a single-tool sweep scoreable.** The most serious limit in the
   project, and the only item here that changes what chokepoint *is* rather
   than what it runs on. It needs a signal that survives a constant tool
   sequence — the dependency-graph structure of the calls rather than
   statistics over their vocabulary. That is a research problem, not a port.
   See [Known defect](../README.md#known-defect-a-single-tool-sweep-is-invisible).

2. **Streamable-HTTP transport.** Unblocks four controls at once and is
   well-scoped engineering rather than research.

   Read this before starting: the 2026-07-28 spec revision **deprecates
   `Mcp-Session-Id` and tells proxies to ignore it**, while session scoping is
   the entire basis of the score. Session identity has to go behind an
   abstraction with two backends — the header for older revisions, and a
   reconstructed identity (a bound OAuth token, or `traceparent` from the
   JSON-RPC `_meta` object) for newer ones. Hard-coding either is the mistake
   available here.

3. **A longer in-cluster fixture.** The current one exercises the deterministic
   rules and leaves the detector silent. A session long enough to produce a real
   score would test the part the research is about, in the place it is deployed.

4. **Capture `wget`'s stderr explicitly** in `10-installer-daemonset.yaml`. The
   404 message is visible only because busybox's `wget` prints HTTP errors
   despite `-q`. That is a property of `alpine:3.22`, not of the script — if the
   base image moves, the pod fails with an empty log, silent in exactly the
   place the deployment README tells an operator to look.

## Conventions worth not relearning

- **`TestPublishedNumbersHaveNotDrifted` is ungated and runs on a plain
  `go test ./...`.** It is the only thing tying published figures to the
  detector's actual behaviour. A new published number that is not pinned there
  is unguarded.
- **Records are not documentation.** `first-cluster-run.md` and the blog post
  keep saying `0.1.0` because that is the version they were run against.
  Updating measurements after the fact to match a later release is how a lab
  notebook becomes fiction.
- **The deployment fails closed, but that is a property of the arrangement,**
  not of chokepoint. An MCP client that falls back to spawning the tool server
  directly when its configured command fails would turn the same event into a
  silent bypass.
