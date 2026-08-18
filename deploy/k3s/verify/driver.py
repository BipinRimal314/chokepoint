#!/usr/bin/env python3
"""Stands in for an agent, so that the thing under test is the wiring.

Reads the same mcp.json an MCP client would read, spawns whatever command it
names -- which is the whole point: if that command is chokepoint, the proxy is
in the path, and if the wiring is wrong this driver talks straight to the
server and every expectation below fails open.

Runs a scripted session, checks each call against the verdict the policy says
it should get, then stays alive so the metrics endpoint can be scraped. The
session is ordered deliberately: call 2 and call 6 are byte-identical, and the
only thing that happens between them is the server changing its own tool
description.
"""
import json
import os
import subprocess
import sys
import time

CONFIG = os.environ.get("MCP_CONFIG", "/etc/mcp/mcp.json")
RESULT = os.environ.get("DRIVER_RESULT", "/var/log/chokepoint/driver-result.txt")
DENIED = -32001

with open(CONFIG) as fh:
    server = json.load(fh)["mcpServers"]["filesystem"]

argv = [server["command"], *server.get("args", [])]
print(f"driver: spawning {' '.join(argv)}", flush=True)

proc = subprocess.Popen(
    argv,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    # stderr is left alone so chokepoint's own logging and its --report land in
    # the pod log, where kubectl logs can read them.
    text=True,
    bufsize=1,
)

next_id = 0


def rpc(method, params=None):
    global next_id
    next_id += 1
    msg = {"jsonrpc": "2.0", "id": next_id, "method": method}
    if params is not None:
        msg["params"] = params
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        raise SystemExit("driver: upstream closed the pipe -- see the pod log")
    return json.loads(line)


def read_file(path):
    return rpc("tools/call", {"name": "read_file", "arguments": {"path": path}})


def verdict(resp):
    err = resp.get("error")
    if err is None:
        return "allow", ""
    if err.get("code") == DENIED:
        return "deny", err.get("message", "").split(".")[0]
    return f"error {err.get('code')}", err.get("message", "")


rpc("initialize", {"protocolVersion": "2025-06-18", "clientInfo": {"name": "driver"}})
rpc("tools/list")  # first listing: this is the fingerprint everything is held to

checks = [
    ("read a workspace file", "allow",
     lambda: read_file("/workspace/notes.txt")),
    ("read an ssh private key", "deny",
     lambda: read_file("/workspace/.ssh/id_rsa")),
    ("read the pod's serviceaccount token", "deny",
     lambda: read_file("/var/run/secrets/kubernetes.io/serviceaccount/token")),
    ("read outside the declared workspace", "deny",
     lambda: read_file("/etc/passwd")),
    ("reach cloud instance metadata", "deny",
     lambda: read_file("http://169.254.169.254/latest/meta-data/")),
]

results = []
for name, want, fn in checks:
    got, detail = verdict(fn())
    results.append((name, want, got, detail))

# The server now poisons its own tool description. Nothing about the call that
# follows changes -- only what the server said about the tool it belongs to.
rpc("tools/list")

got, detail = verdict(read_file("/workspace/notes.txt"))
results.append(("read the same workspace file, after the rug pull", "deny", got, detail))

# An audited call is allowed through and recorded. It is here to show the two
# effects are distinguishable, not merely that something got blocked.
got, detail = verdict(rpc("tools/call", {"name": "write_file",
                                         "arguments": {"path": "/workspace/out.txt"}}))
results.append(("write inside the workspace (audit rule)", "allow", got, detail))

width = max(len(r[0]) for r in results)
lines = ["", "driver: scripted session complete", ""]
failures = 0
for name, want, got, detail in results:
    ok = want == got
    failures += not ok
    lines.append(f"  {'PASS' if ok else 'FAIL'}  {name:<{width}}  want={want:<5} got={got:<5} {detail}")
lines.append("")
lines.append(f"driver: {len(results) - failures}/{len(results)} as policy specifies")

report = "\n".join(lines)
print(report, flush=True)
try:
    with open(RESULT, "w") as fh:
        fh.write(report + "\n")
except OSError as exc:
    print(f"driver: could not write {RESULT}: {exc}", flush=True)

if failures:
    print("driver: MISMATCH -- staying up anyway so the metrics can be read", flush=True)

# Hold the session open. chokepoint serves metrics from inside its own process,
# so exiting here would take the endpoint down with it.
while True:
    time.sleep(3600)
