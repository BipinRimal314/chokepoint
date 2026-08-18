# Verifying interception in-cluster

The installer DaemonSet proves a *file* arrives on a node. That is a package
manager. This directory proves the thing the file is for: an agent process
spawning chokepoint instead of its MCP server, and policy rules producing real
refusals inside a pod.

It is a test fixture, not a deployment. Nothing here belongs in a cluster you
care about.

## What it is

| | |
| --- | --- |
| `deployment.yaml` | `../30-agent-deployment.yaml` with the placeholder image replaced by one that runs. The four wiring elements are unchanged. |
| `driver.py` | Stands in for an agent. Reads `mcp.json` the way a client would, spawns whatever it names, runs a scripted session, checks each verdict. |
| `mcp.json` | Points the proxy at `testdata/mock_mcp_server.py` instead of `npx`, so the test needs no registry and no network. |

The driver deliberately reads the config rather than hard-coding the command.
If the wiring is wrong — if `mcp.json` names the server directly — the driver
talks straight to it, every deny expectation fails open, and the test says so.
A test that spawned chokepoint itself could not detect the one mistake this
deployment is most likely to make.

## Run it

From the repository root, with the installer DaemonSet and
`20-policy-configmap.yaml` already applied:

```sh
kubectl -n agents create configmap agent-testkit \
  --from-file=deploy/k3s/verify/driver.py \
  --from-file=testdata/mock_mcp_server.py
kubectl -n agents create configmap agent-mcp-config-test \
  --from-file=deploy/k3s/verify/mcp.json
kubectl apply -f deploy/k3s/verify/deployment.yaml
kubectl -n agents rollout status deploy/interception-test --timeout=180s
kubectl -n agents logs deploy/interception-test -c agent
```

The last line should end `driver: 7/7 as policy specifies`.

On a re-run, `logs deploy/…` may pick the *previous* pod while it is still
terminating — the driver sleeps to hold the session open, so it takes the full
grace period to go away, and a stale PASS table is the most misleading thing
this fixture can show you. Name the pod when it matters:

```sh
kubectl -n agents logs -c agent \
  "$(kubectl -n agents get pods -l app.kubernetes.io/name=interception-test \
     --sort-by=.metadata.creationTimestamp -o name | tail -1)"
```

Rollout succeeding is itself a check: readiness is an HTTP probe against
`/healthz` on the metrics port, so the pod does not go ready until the proxy is
actually serving.

## What the seven calls cover

Five of the eight rules in `20-policy-configmap.yaml` fire, one rule audits,
and one call is allowed as a control — a test where everything is denied cannot
tell enforcement from a proxy that is simply broken.

| call | expected |
| --- | --- |
| read `/workspace/notes.txt` | allow — the control |
| read `/workspace/.ssh/id_rsa` | deny, `no-credential-paths` |
| read the pod's ServiceAccount token | deny, `no-serviceaccount-token` |
| read `/etc/passwd` | deny, `outside-declared-workspace` |
| read `169.254.169.254` | deny, `no-cloud-metadata` |
| read `/workspace/notes.txt` **again** | deny, `tool-definition-changed` |
| `write_file` in the workspace | allow, and audited by `watch-writes` |

The sixth call is the one to look at. It is byte-identical to the first, and it
is allowed the first time and denied the second. Nothing about the agent's
request changed; between them the server issued a second `tools/list` with an
altered description for a tool whose name and schema stayed the same. That is
the rug pull, and it is caught on the definitions rather than on the calls,
because the calls are individually unremarkable both times.

## Cleaning up

```sh
kubectl -n agents delete deploy/interception-test \
  cm/agent-testkit cm/agent-mcp-config-test
```

## Checking the failure path too

`20-policy-configmap.yaml` claims a policy that does not compile is a startup
failure rather than a warning. To confirm that rather than trust it, break a
rule in a copy of the policy, mount it in place of the real one, and expect
`CrashLoopBackOff` with the failing rule named in the pod log. Measured
behaviour is in [`docs/first-cluster-run.md`](../../../docs/first-cluster-run.md).
