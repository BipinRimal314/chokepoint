# First cluster run

`deploy/k3s/` was written, documented and reviewed without ever being applied to
a cluster. This is the record of the first time it was, including the failure
path, so that the next person to touch those manifests knows which claims are
measured and which are still inference.

Everything below was run on **17 August 2026** against `7ef8363`, release
`v0.1.0`.

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
to the released one. So the DaemonSet, the hostPath, the atomic rename and the
version resolution all behave as documented.

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

## What this does not establish

The delivery mechanism works. That is all it shows, and the distinction is
worth keeping sharp:

- **No interception was tested.** Staging a binary is not proxying anything. An
  agent pod exec'ing the staged binary in place of its MCP server, and a policy
  rule producing an actual denial in-cluster, has still never run.
  `30-agent-deployment.yaml` was deliberately not applied — it is a template.
- **Single node only.** Multi-node scheduling, tolerations against real taints,
  and per-node staging are untested.
- **The trust caveats in `deploy/k3s/README.md` are unchanged.** The checksum
  still comes from the same host as the binary; a hostPath is still a hostPath;
  an agent that can exec arbitrary commands can still bypass the proxy entirely.

## Companion write-up

`docs/blog/where-do-you-stand.html` is a longer, plain-language piece built from
this run — why stdio leaves nowhere in the network to stand, why that forces the
installer shape, and what the run did and did not prove.
