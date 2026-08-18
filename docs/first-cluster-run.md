# First cluster run

`deploy/k3s/` was written, documented and reviewed without ever being applied to
a cluster. This is the record of the first time it was, including the failure
path, so that the next person to touch those manifests knows which claims are
measured and which are still inference.

Delivery was run on **17 August 2026** against `7ef8363`, release `v0.1.0`.
Interception was run on **18 August 2026** against `064cce5`, on the same
cluster and the same staged binary. The real upgrade, `v0.1.0` → `v0.2.0`, was
run later the same day against `9bd8db4`.

| | |
| --- | --- |
| cluster | k3s v1.36.3+k3s1, **single node** (`archlinux`) |
| host | Arch Linux, kernel 7.1.6, cgroup v2, containerd 2.3.2-k3s2 |
| install | `curl -sfL https://get.k3s.io \| INSTALL_K3S_EXEC="--write-kubeconfig-mode 644" sh -` |

Single node matters for reading what follows: nothing here measures multi-node
behaviour. Every statement about a second node is inference.

## The happy path

The four commands in `deploy/k3s/README.md`, in order, all succeeded on the
first attempt. No manifest changes were needed.

```
$ kubectl apply -f 10-installer-daemonset.yaml
namespace/chokepoint-system created
daemonset.apps/chokepoint-installer created

$ kubectl apply -f 20-policy-configmap.yaml
namespace/agents created
configmap/chokepoint-policy created
configmap/agent-mcp-config created

$ kubectl -n chokepoint-system rollout status ds/chokepoint-installer
daemon set "chokepoint-installer" successfully rolled out

$ kubectl -n chokepoint-system logs ds/chokepoint-installer -c install
chokepoint_0.1.0_linux_amd64.tar.gz: OK
chokepoint 0.1.0
```

The documented check is the last line. The **first** line is the one worth
reading: that is `sha256sum -c` passing, which is the only evidence that the
archive was verified before it was unpacked. A future change that stops
printing it removes the only in-cluster signal that verification happened at
all.

### The stage actually landed

A log line is a claim. On the host:

```
$ ls -la /opt/chokepoint/bin/
-rwxr-xr-x root root 20M chokepoint

$ /opt/chokepoint/bin/chokepoint --version
chokepoint 0.1.0

$ sha256sum /opt/chokepoint/bin/chokepoint
8b663bbb9d592a07882b259b301d7485ddaaceca3a425b529fe4590a3ac145b7
```

The published archive was then downloaded independently, verified against
`checksums.txt`, unpacked, and compared: the staged binary is **byte-identical**
to the released one. So the DaemonSet, the hostPath and the version resolution
all behave as documented. Not the atomic rename — there was nothing at the
target path to replace, so that step was a rename onto empty space. See
[Upgrading in place](#upgrading-in-place).

### Why Pod Security Admission did not bite

The installer needs a `hostPath` and `runAsUser: 0`, and `chokepoint-system`
carries no PSA labels. k3s enforces no Pod Security Admission by default, so the
pod was admitted. **On a cluster that does enforce `baseline` or `restricted`,
this DaemonSet will be rejected and the symptom is a hanging `rollout status`,
not an error** — the pods are never created, so there is nothing to report on.
Use `--timeout` and read the namespace events.

## The failure path

`deploy/k3s/README.md` promises that a version that does not exist "fails loudly
on a 404 rather than staging nothing quietly". That is the dangerous failure to
get wrong: an install that 404s but reports success leaves agents exec'ing a
stale binary, or none at all, with a green dashboard.

Verified by setting `CHOKEPOINT_VERSION` to `9.9.9` and applying:

```
$ kubectl -n chokepoint-system rollout status ds/... --timeout=60s
error: timed out waiting for the condition          (rc=1)

$ kubectl -n chokepoint-system get pods
chokepoint-installer-cj8w8   0/1   Init:Error   3

$ kubectl -n chokepoint-system logs ds/chokepoint-installer -c install
wget: server returned error: HTTP/1.1 404 Not Found
```

Loud at three levels, which is the point — CI reads the exit code, a dashboard
reads the pod status, a human reads the log. Init container `exitCode: 1`,
`reason: Error`, restart count climbing.

### A good install survives a bad upgrade

Checked while the installer was in `Init:Error`:

| | before | during failure |
| --- | --- | --- |
| `--version` | `chokepoint 0.1.0` | `chokepoint 0.1.0` |
| sha256 | `8b663bbb…` | `8b663bbb…` |
| mtime | 17:46:53 | 17:46:53 |
| `.chokepoint.tmp` | absent | absent |

Untouched, and no temporary file left behind to confuse the next attempt. The
download fails before anything reaches the staging directory, so a botched
upgrade cannot damage a working install. Agents on the node keep running the
binary they already had.

Setting the version back to `0.1.0` and re-applying brought the pod up clean and
printed `chokepoint 0.1.0` again — which also demonstrates the reconcile claim in
`10-installer-daemonset.yaml`: changing `CHOKEPOINT_VERSION` re-runs the init
container, in both directions.

### Known fragility: the log line is not guaranteed

The script calls `wget -q`. Busybox's wget prints the HTTP error to stderr
despite `-q`, which is why the 404 is visible above. **That is a property of the
base image, not of this script.** A bump to a wget that honours `-q` more
aggressively would leave the pod failing with an empty log — still loud in pod
status, silent in the one place `deploy/k3s/README.md` tells the operator to
look. If `alpine:3.22` moves, capture wget's stderr explicitly rather than
relying on it.

## Upgrading in place

The failed upgrade above showed a good install surviving a bad one. The other
direction — a real version change landing on a node that already had a working
binary — was only tested once `v0.2.0` existed. Bump `CHOKEPOINT_VERSION` to
`0.2.0`, re-apply the DaemonSet:

| | before | after |
| --- | --- | --- |
| `--version` | `chokepoint 0.1.0` | `chokepoint 0.2.0` |
| sha256 | `8b663bbb…` | `3af94174…` |
| mtime | 17 Aug 17:46 | 18 Aug 17:07 |
| `.chokepoint.tmp` | absent | absent |

The install log printed `chokepoint_0.2.0_linux_amd64.tar.gz: OK` then
`chokepoint 0.2.0`. The published archive was again downloaded independently,
verified, unpacked and compared: **byte-identical** to what is now staged.
`gh attestation verify` on that archive also passed, so the build provenance the
main README points at is real for this release and not only configured.

The interception fixture was then re-run against the new binary — 7/7, same as
against `0.1.0`. So the loop closes: tag, release, node upgrades itself,
enforcement still works.

**What this does not show is atomicity.** No agent was mid-`exec` during the
swap. The claim that a rename cannot hand anyone half a binary still rests on
`rename(2)`'s guarantee rather than on anything observed here, and testing it
properly means exec'ing in a loop while an upgrade lands.

## Interception

Everything above concerns a file arriving on a node. This is the first time the
file was used for what it is for. The fixture is `deploy/k3s/verify/`, which is
`30-agent-deployment.yaml` with the placeholder image replaced by one that runs
and the upstream pointed at `testdata/mock_mcp_server.py`.

### The proxy is genuinely in the path

The claim underneath the whole deployment is process-tree interception. Read
from `/proc` inside the running pod:

```
pid=1   ppid=0   python3 -u /opt/testkit/driver.py
pid=7   ppid=1   /opt/chokepoint/bin/chokepoint --policy /etc/chokepoint/policy.yaml …
pid=18  ppid=7   python3 /opt/testkit/mock_mcp_server.py
```

The agent's child is chokepoint; chokepoint's child is the server. The server
is not reachable from the agent except through pid 7, and the binary at pid 7
is the hostPath the DaemonSet staged. That is the architecture asserted in
`deploy/k3s/README.md`, observed rather than argued.

The driver reads `mcp.json` instead of hard-coding the command, which matters:
if that config named the server directly, the driver would talk straight to it
and every deny below would fail open. The test can therefore detect the single
most likely deployment mistake.

### Rules produce real refusals

```
PASS  read a workspace file                             want=allow got=allow
PASS  read an ssh private key                           want=deny  got=deny
PASS  read the pod's serviceaccount token               want=deny  got=deny
PASS  read outside the declared workspace               want=deny  got=deny
PASS  reach cloud instance metadata                     want=deny  got=deny
PASS  read the same workspace file, after the rug pull  want=deny  got=deny
PASS  write inside the workspace (audit rule)           want=allow got=allow

driver: 7/7 as policy specifies
```

Five distinct rules fired, one audited, one allowed. The allowed call is not
filler — without it, a proxy that denied everything, or one that had crashed
into a closed pipe, would produce a table that looked like success.

The sixth line is the result worth having. It is the same call as the first,
and it is allowed the first time and denied the second. The agent did not
change its behaviour; the server changed its own tool description between the
two listings, keeping the name and schema identical. chokepoint held it to what
it published first:

```
level=WARN msg="tool definition changed since first listing" tool=read_file
  kind=modified listing=2
  was=f435ed4344fe7fb5… now=dfa786ba87ee16a4…
```

### Metrics and the audit log

Scraped from inside the pod, and independently from a second pod at
`10.42.0.19:9464` — 45 `chokepoint_` series, so the per-pod scrape target
described in `deploy/k3s/README.md` is reachable the way a Prometheus would
reach it:

```
chokepoint_policy_denials_total{rule="no-cloud-metadata",tool="read_file"}        1
chokepoint_policy_denials_total{rule="no-credential-paths",tool="read_file"}      1
chokepoint_policy_denials_total{rule="no-serviceaccount-token",tool="read_file"}  1
chokepoint_policy_denials_total{rule="outside-declared-workspace",tool="read_file"} 1
chokepoint_policy_denials_total{rule="tool-definition-changed",tool="read_file"}  1
chokepoint_policy_audits_total{rule="watch-writes"}                               1
chokepoint_tool_calls_total{effect="deny",tool="read_file"}                       5
chokepoint_tool_calls_total{effect="allow",tool="read_file"}                      1
chokepoint_tool_calls_total{effect="allow",tool="write_file"}                     1
chokepoint_session_targets                                                        6
chokepoint_decomposition_score                                                  NaN
```

`/healthz` answered `200 ok`, which is what the readiness probe used, so the pod
did not go Ready until the proxy was serving. The audit log held **7 lines for 7
calls** — allows as well as denials, in OTLP/JSON, one span each.

**The `NaN` is not a bug and is the most instructive number here.** The
decomposition detector declines to report a score for a seven-call session
rather than emitting `0.0`, which would read as "this session looks fine". That
is the right behaviour and it is also the limit of this test: what was verified
in-cluster is the *deterministic* rule path. The behavioural detector — the part
the research is about — was never given enough of a session to speak.

### A policy that does not compile stops the agent

`20-policy-configmap.yaml` claims a bad edit surfaces as a `CrashLoopBackOff`
rather than an agent running with protection its operator imagines is in place.
Verified by breaking one rule's CEL and mounting it in place of the policy:

```
$ kubectl -n agents rollout status deploy/... --timeout=60s
error: timed out waiting for the condition          (rc=1)

$ kubectl -n agents get pods
interception-broken-policy-…   0/1   CrashLoopBackOff   3

$ kubectl -n agents logs deploy/... -c agent
chokepoint: load policy: rule "watch-writes": ERROR: <input>:1:18: Syntax error:
 | tool.startsWith( || tool.startsWith("delete")
 | .................^
```

The rule is named and the column is pointed at, which is what makes this
recoverable at 3am. Note what happens to the agent: the proxy exits, the pipe
closes, and the driver dies with it. **The failure is closed** — a
misconfigured deployment yields an agent with no tool server at all, not an
agent with an unprotected one.

That property belongs to this arrangement, not to chokepoint. An MCP client
that falls back to spawning the server directly when its configured command
fails would convert the same event into a silent bypass.

## What this does not establish

Delivery works and interception works. Neither statement is as broad as it
sounds, and the distinction is worth keeping sharp:

- **The agent was a stand-in, and so was the server.** `driver.py` is fifty
  lines that speak JSON-RPC; no real MCP client has been wired through this
  deployment, and the claim that `mcp.json`'s shape matches what Claude Code
  and the reference clients read is still an assertion. The upstream was the
  mock, not `npx @modelcontextprotocol/server-filesystem` — so nothing here
  confirms a real server's own runtime is present in an agent image, which is
  the trap `30-agent-deployment.yaml` warns about.
- **Only the deterministic rules ran.** Path matching, scope containment and
  tool fingerprinting were exercised. The decomposition score, the workspace
  rate window, and every threshold rule that depends on session length were
  not; see the `NaN` above.
- **Single node only.** Multi-node scheduling, tolerations against real taints,
  and per-node staging are untested.
- **The trust caveats in `deploy/k3s/README.md` are unchanged.** The checksum
  still comes from the same host as the binary; a hostPath is still a hostPath;
  an agent that can exec arbitrary commands can still bypass the proxy entirely.

## Companion write-up

`docs/blog/where-do-you-stand.html` is a longer, plain-language piece built from
this run — why stdio leaves nowhere in the network to stand, why that forces the
installer shape, and what the run did and did not prove.
