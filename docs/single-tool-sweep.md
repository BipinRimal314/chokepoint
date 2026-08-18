# The single-tool sweep: a first pass, and a signal that did not work

[Known defect](../README.md#known-defect-a-single-tool-sweep-is-invisible) says a
session calling one tool against any number of distinct targets scores exactly
`0.400` and never crosses the `0.45` threshold, and that fixing it needs "a
signal that survives a constant tool sequence". This is the record of a first
attempt at finding one.

**The attempt failed, and the way it failed is the useful part.** The candidate
signal is not merely weak; it flags legitimate work as readily as theft. Written
down so nobody spends a second week rediscovering it.

Reproduce every number here with:

```sh
go test ./internal/detect -run SweepStructure -v
```

## The corpus could not have told us

Before proposing anything, look at what a proposal would be measured against.
`TestCalibrationTable` holds six shapes:

| | distinct targets |
| --- | --- |
| the three **benign** shapes | 1, 3, 3 |
| the three **attack** shapes | 60, 60, 60 |

Target count alone separates that corpus perfectly. Any candidate signal
correlated with breadth — and most structural signals are — scores full marks
there while demonstrating nothing, because breadth is already doing the work.

This is the same trap as the ASI02 finding elsewhere in this project: a
generator that defines the benign class narrowly will confirm whatever the
author expected. So every shape below holds breadth **fixed at sixty distinct
targets** and varies only structure. Nothing can score well by counting.

## With breadth held fixed, the current rule is wrong more often than right

The example policy's rule is `decomposition_score > 0.45 && session_targets >
25`. Applied to nine sixty-target sessions:

| shape | actual | score | rule says | |
| --- | --- | --- | --- | --- |
| benign/one-project | benign | 0.400 | allow | |
| benign/project+strays | benign | 0.400 | allow | |
| benign/multi-repo | benign | 0.400 | allow | |
| benign/ci-build | benign | 0.400 | allow | |
| benign/sysadmin-audit | benign | 0.400 | allow | |
| benign/lint-repo | benign | 0.603 | **DENY** | wrong |
| attack/one-root-sweep | attack | 0.400 | allow | wrong |
| attack/multiroot-even | attack | 0.400 | allow | wrong |
| attack/multiroot-padded | attack | 0.400 | allow | wrong |

Four of nine wrong. Three attacks pass, and the one session that gets denied is
legitimate.

The false positive is new information and it is worse than the misses. A linter
reading and rewriting every file in a repo scores `0.603` — because it uses
**two** tools, which buys `action_entropy` — while a single-tool sweep of the
same breadth scores `0.400` and is allowed. The rule denies the benign wide
session that varies its tools and permits the malicious one that does not. That
is not a threshold that is set too low; it is backwards.

**`benign/one-project` and `attack/one-root-sweep` both score exactly `0.400`.**
Reading every file in a repository and stealing every file in a directory are
the same session. Not similar — identical, on every feature the detector
computes.

## The candidate: spread across unrelated roots

`Resource.Root` already exists, so this was cheap to test. Two measures over
per-root call counts, neither of which looks at the tool name:

- **root entropy** — normalised Shannon over the counts, so "evenly spread
  across however many roots you touched" reads `1.000` regardless of how many
  that was. Raw Shannon would grow with the root count and just be another way
  of counting roots.
- **dominant share** — calls in the largest root, over all targeted calls.

It has the property the defect calls for. A constant tool sequence flattens
novelty, entropy and repetition to zero by construction; it does nothing to
where the targets are. And unlike breadth, it does not saturate:

| calls | score | root entropy |
| --- | --- | --- |
| 20 | 0.400 | 0.990 |
| 60 | 0.400 | 0.999 |
| 200 | 0.400 | 1.000 |
| 1000 | 0.400 | 1.000 |
| 5000 | 0.400 | 1.000 |

That directly addresses "breadth saturates, so a bigger theft is not a louder
one". Evasion looked expensive too — padding a 20-target cross-root theft with
same-root reads to push entropy down:

| steal | pad | root entropy | overhead |
| --- | --- | --- | --- |
| 20 | 0 | 1.000 | 1.0× |
| 20 | 20 | 0.836 | 2.0× |
| 20 | 60 | 0.538 | 4.0× |
| 20 | 140 | 0.323 | 8.0× |
| 20 | 300 | 0.187 | 16.0× |

Against the published 2× cost of evading the multi-tool rule, 8–16× is a real
price.

## Why it does not work anyway

None of that matters, because it does not discriminate:

| shape | actual | root entropy |
| --- | --- | --- |
| benign/ci-build | benign | **1.000** |
| benign/sysadmin-audit | benign | **1.000** |
| attack/multiroot-even | attack | **0.999** |

A CI build reading `/src`, `/build`, `/cache` and `/tmp`, and an audit agent
reading configuration under `/etc`, `/var`, `/usr` and `/opt`, are maximally
dispersed. So is the theft. The benign sessions actually score *higher*.

Meanwhile the shapes root entropy calls quiet include `attack/one-root-sweep` at
`0.000` — identical to `benign/one-project`, which is where this started.

So the signal is scale-invariant, expensive to evade, cheap to compute, and
useless. It would have been easy to believe: measured against the existing
corpus, whose benign shapes are all single-rooted, it separates perfectly.

**A negative result from invented fixtures is worth much more than a positive
one.** Confirming a signal this way proves only that the author's benign class
matched the author's expectations. Refuting one needs a single plausible
counterexample, and "a CI job touches several top-level directories" is not a
contrived thing to suppose.

## What this suggests the problem actually is

Not a missing feature. Every structural signal tested that separates a sweep
from a *narrow* benign session also flags a *wide* one, because:

> Wide, shallow, non-repetitive traversal is not the signature of decomposed
> attack. It is the signature of thorough work.

"Read every file and summarise the codebase" is a normal request. It produces
the same call sequence as exfiltration, and no statistic over that sequence can
separate them, because the difference is not in the sequence. It is in whether
the agent was *sent* there, and in what the targets are.

Both of those are already implemented, and neither is a score:

- **the declared workspace** answers "was this in bounds", which is the question
  that actually distinguishes these cases. Its limits are known and unchanged:
  it needs an operator who can declare a boundary, and it says nothing about a
  sweep that stays inside one.
- **path rules** (`no-credential-paths`, `no-serviceaccount-token`) answer "is
  this target sensitive", which is content, not behaviour.

That is not a satisfying answer to a research question, but it is where the
evidence points, and it sharpens rather than undermines the project's thesis.
Inline enforcement buys enforcement, not detection — and the reason is not that
the detector is looking at too little history. It is that at this layer the
attack and the legitimate task are the same behaviour.

## Where to go next

1. ~~**Fix the false positive first.**~~ **Done.** See below.
2. **Add wide benign shapes to the calibration corpus.** The gap is the reason
   this defect went unmeasured on the false-positive side. Note that
   `calibrationShapes` is shared with the paper-data generator, so changing it
   moves published figures — a deliberate decision, not a drive-by edit.
3. **Test against real traces rather than more invented ones.** Everything here
   is hand-written by one author in one sitting, which is enough to *refute* a
   signal and not enough to establish one.
4. **If the score is to be rescued at all**, the remaining candidate is the
   dependency structure the README already names: whether a target was
   discovered from a previous *result* or arrived from outside the session. An
   agent that reads sixty paths nobody ever told it about knows something it was
   not given. That needs response-body inspection, which this proxy can do but
   currently does not, and it is a larger change than anything attempted here.

## The fix for the false positive

Applied to `examples/policy.yaml` and `deploy/k3s/20-policy-configmap.yaml`.
Reproduce with `go test ./internal/detect -run SweepRuleCorroboration -v`.

The measurements above rule out the obvious repairs. Raising the threshold
cannot work: the highest-scoring benign shape here is `0.603` and the
lowest-scoring attack is `0.400`, so the bands are not merely overlapping, they
are **inverted**. No threshold on this score separates them in either direction.
Reweighting is not available either without data — and it would move every
published figure six weeks before they are cited.

So the rule stops resting on the score alone:

```yaml
- name: watch-decomposed-sweep
  match: decomposition_score > 0.45 && session_targets > 25
  effect: audit

- name: halt-decomposed-sweep
  match: decomposition_score > 0.45 && session_targets > 25 && session_out_of_scope > 0
  effect: deny
```

The score is evidence, so it is recorded every time it trips. It is not proof,
so on its own it no longer denies. Leaving the declared workspace is the
corroboration — a question about where the agent was *sent*, which is the thing
that actually distinguishes these sessions.

| shape | actual | score | rule before | rule now |
| --- | --- | --- | --- | --- |
| benign/lint-repo | benign | 0.603 | **DENY** | allow |
| benign/one-project | benign | 0.400 | allow | allow |
| benign/ci-build | benign | 0.400 | allow | allow |
| attack/one-root-sweep | attack | 0.400 | allow | allow |
| attack/multiroot-even | attack | 0.400 | allow | allow |

Four of nine wrong becomes three of nine. The three that remain are the three
attacks, all of which score `0.400` and were never denied by this rule anyway —
that is the known defect, untouched.

Two properties are asserted rather than printed, because they hold for any
session rather than only for these fixtures:

- **Corroboration can only narrow.** Adding a conjunct cannot deny something the
  score alone allowed, so the change cannot introduce a new false positive
  whatever shape a session has.
- **The specific false positive stays fixed**, and the test fails loudly if
  `lint-repo` ever stops tripping the score alone — at which point it would no
  longer be demonstrating the thing it was written for.

### What this does not fix

`session_out_of_scope` is zero when no workspace is declared, so on a deployment
that declares none the deny is inert and the audit rule is all that remains.
That is the honest outcome rather than a gap: with no boundary declared there is
nothing to corroborate against, and the measurements say the score alone cannot
carry the decision.

**A benign session can also leave its workspace.** `benign/project+strays` reads
`/etc/hosts` and a CA certificate — two out-of-scope resources in an otherwise
ordinary session. It escapes this rule only because it scores `0.400`. A
straying benign session that also scored above the threshold would still be
denied, so corroboration reduces the false-positive surface without eliminating
it. A test asserts that this shape does stray, so the caveat cannot quietly stop
being true.

Note also that the example policy's `outside-declared-workspace` rule would deny
those two calls first, on their own. Whether *that* is too aggressive for a
session which is otherwise plainly benign is a separate question about the
example policy, and is not addressed here.
