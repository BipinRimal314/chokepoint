# Running chokepoint on k3s

## The thing to understand first

chokepoint is not a network service. It speaks MCP over stdio, and it
intercepts a session by **being the process the agent spawns** — the agent
execs `chokepoint -- <server command>` instead of the server, and chokepoint
runs the real server as its child.

That has one consequence that governs this whole directory: chokepoint has to
be inside the agent's container at exec time. A `Deployment` of chokepoint with
a `Service` in front of it would have nothing on its stdin and would proxy
nothing. If you are looking for a sidecar to point traffic at, there isn't one,
and there cannot be one for stdio transport.

So the deployment splits in two:

| | what it does |
| --- | --- |
| `chokepoint-installer` DaemonSet | stages the binary at `/opt/chokepoint/bin` on every node |
| agent pods | mount that path read-only, and spawn it instead of the MCP server |

Same shape as a CNI plugin installer, for the same reason: the artefact belongs
in other pods.

> **HTTP-transport MCP servers are a different deployment and this is not it.**
> chokepoint proxies stdio. A remote server reached over Streamable HTTP never
> passes through anything here.

## Apply

```sh
kubectl apply -f 10-installer-daemonset.yaml
kubectl apply -f 20-policy-configmap.yaml
# 30 is a template, not a deployable. Read it, then adapt it.
kubectl apply -f 30-agent-deployment.yaml
```

Set `CHOKEPOINT_VERSION` in `10-installer-daemonset.yaml` to a published
release before applying — the default is a placeholder and the install will
fail loudly on a 404 rather than staging nothing quietly.

Confirm the stage landed:

```sh
kubectl -n chokepoint-system rollout status ds/chokepoint-installer
kubectl -n chokepoint-system logs ds/chokepoint-installer -c install | tail -1
# chokepoint 0.1.0
```

## Wiring an agent

Four things, and only four:

1. Mount `/opt/chokepoint/bin` from the host, **read-only**.
2. Mount the policy ConfigMap at `/etc/chokepoint`.
3. Configure the agent's MCP client so the command it spawns is
   `/opt/chokepoint/bin/chokepoint --policy ... -- <the real server>`. This is
   the step that actually inserts the proxy; the mounts do nothing on their
   own. `agent-mcp-config` in `20-policy-configmap.yaml` shows the shape.
4. Expose `9464` and let Prometheus scrape it.

Introduce it the way the README describes: **no `--policy` at first**. Run it
transparently, watch `--report` and the audit log for a few days, and write
rules against what the agent actually did. A policy written from imagination
denies work people need and gets switched off.

## Metrics

Each agent pod's proxy is its own scrape target. There is deliberately no
aggregating Service: `chokepoint_policy_denials_total` per agent answers a
question, and summed across a cluster it does not.

The pod annotations in `30-agent-deployment.yaml` are for the annotation-based
scrape config a stock k3s Prometheus install usually carries. On
kube-prometheus-stack, drop them and use a `PodMonitor` selecting
`app.kubernetes.io/name: example-agent` on port `metrics`.

`GET /healthz` on the same port answers once the proxy is up, which is what to
use if you want a probe rather than a scrape.

## What this does not solve

- **The audit log dies with the pod.** `30-agent-deployment.yaml` uses an
  `emptyDir`, which is fine for looking at and useless as evidence. The
  compliance argument in the main README depends on retention this does not
  provide — ship the log off the pod before citing it.
- **The binary is trusted because of its checksum, and the checksum comes from
  the same host as the binary.** The installer verifies integrity against
  `checksums.txt`, which catches a corrupted or truncated download but not a
  compromised release. If that matters to you, verify the build provenance
  attestation (`gh attestation verify`) out of band and mirror the archive
  internally.
- **A hostPath is a hostPath.** Any pod on the node that can mount
  `/opt/chokepoint/bin` writable can replace the binary every agent on that
  node then execs. Keep the mount read-only in agent pods, and gate hostPath
  mounts with Pod Security Admission (`restricted` denies them outright) so
  that only this DaemonSet has one.
- **Nothing here stops an agent from bypassing the proxy.** An agent that can
  exec arbitrary commands can exec the MCP server directly. chokepoint is a
  control on the configured path, not a sandbox; pair it with whatever prevents
  arbitrary exec in your agent runtime.
