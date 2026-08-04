#!/usr/bin/env bash
# chokepoint demo — drives the real binary against a real MCP server subprocess.
#
#   ./demo.sh
#
# Nothing is mocked except the tool server itself, which answers every call
# successfully so that every block you see comes from policy, not from failure.

set -euo pipefail
cd "$(dirname "$0")"

bold=$'\033[1m'; dim=$'\033[2m'; red=$'\033[31m'; green=$'\033[32m'
yellow=$'\033[33m'; blue=$'\033[34m'; reset=$'\033[0m'

step() { printf '\n%s==> %s%s\n' "$bold" "$1" "$reset"; }

command -v go >/dev/null || { echo "go is required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }

step "Building"
go build -o chokepoint ./cmd/chokepoint
printf '   %s\n' "$(./chokepoint --version)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# The requests an agent makes. Each is a plausible thing to ask for; the point
# is that some are refused for what they are, and others for what they add up to.
# ---------------------------------------------------------------------------
python3 - > "$WORK/requests.jsonl" <<'PY'
import json

msgs = [
    # 0: handshake — must always pass, even under a deny-by-default policy
    {"jsonrpc": "2.0", "id": 0, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18"}},
    # 1: ordinary work
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "read_file", "arguments": {"path": "/srv/app/config.yaml"}}},
    # 2: blocked for WHAT IT IS — credential material
    {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
     "params": {"name": "read_file", "arguments": {"path": "/home/u/.ssh/id_rsa"}}},
    # 3: blocked for WHAT IT IS — cloud instance metadata
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
     "params": {"name": "http_get", "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}}},
    # 4: blocked for WHERE IT GOES — reads as a path inside /srv, and is not.
    # Nothing above matches it; the workspace boundary is what stops it, and
    # only because containment is tested on the resolved resource.
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
     "params": {"name": "read_file", "arguments": {"path": "/srv/data/../../etc/shadow"}}},
]

# 5..44: blocked for WHAT THEY ADD UP TO. Every one of these is an ordinary
# read of an ordinary path inside the workspace, and each would be allowed on
# its own.
tools = ["read_file", "list_dir", "grep", "stat"]
for i in range(40):
    msgs.append({"jsonrpc": "2.0", "id": i + 5, "method": "tools/call",
                 "params": {"name": tools[i % 4],
                            "arguments": {"path": f"/srv/data/record-{i:03d}.json"}}})

for m in msgs:
    print(json.dumps(m))
PY

step "Policy in force"
printf '   %s\n' "workspace: $(grep -A2 '^workspace:' examples/policy.yaml | grep '^  - ' | sed 's/^  - //' | paste -sd, -)"
grep -E '^\s+- name:|^\s+effect:' examples/policy.yaml | sed 's/^/   /'

step "Running the session (45 requests through the proxy)"
./chokepoint --policy examples/policy.yaml --log-level warn \
  -- python3 testdata/mock_mcp_server.py \
  < "$WORK/requests.jsonl" > "$WORK/responses.jsonl" 2> "$WORK/proxy.log"

step "What the agent got back"
python3 - "$WORK/requests.jsonl" "$WORK/responses.jsonl" <<'PY'
import json, sys
from collections import Counter

requests = {}
for line in open(sys.argv[1]):
    m = json.loads(line)
    p = m.get("params", {})
    args = p.get("arguments", {}) or {}
    target = args.get("path") or args.get("url") or ""
    requests[m["id"]] = (p.get("name", m.get("method", "?")), target)

GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"

responses = []
for line in open(sys.argv[2]):
    line = line.strip()
    if line:
        responses.append(json.loads(line))

# Sorted by request id for readability. On the wire they arrive out of order:
# a denial is answered by the proxy immediately, while an allowed call has to
# round-trip through the upstream first.
responses.sort(key=lambda m: m.get("id") if isinstance(m.get("id"), int) else 1 << 30)

allowed, denied, by_rule = 0, 0, Counter()
first_sweep_block = None
shown = 0

for msg in responses:
    rid = msg.get("id")
    tool, target = requests.get(rid, ("?", ""))

    if "error" in msg:
        denied += 1
        rule = msg["error"].get("data", {}).get("rule", "?")
        by_rule[rule] += 1
        if rule == "halt-decomposed-sweep" and first_sweep_block is None:
            first_sweep_block = (rid, msg["error"]["data"])
        # Show the targeted blocks in full; the sweep is summarised below.
        if rule != "halt-decomposed-sweep":
            print(f"   {RED}BLOCKED{RESET} #{rid:<3} {tool:<10} {target}")
            print(f"           {DIM}rule: {rule}{RESET}")
    else:
        allowed += 1
        if shown < 2 and rid != 0:
            print(f"   {GREEN}allowed{RESET} #{rid:<3} {tool:<10} {target}")
            shown += 1

print()
print(f"   {allowed} allowed, {denied} blocked, out of {allowed + denied} answered")
for rule, n in by_rule.most_common():
    print(f"     {n:>3}  {rule}")

if first_sweep_block:
    rid, data = first_sweep_block
    print()
    print(f"   The sweep was stopped at request #{rid}. Requests 5 through {rid - 1}")
    print("   were allowed: individually they are ordinary reads. What changed is")
    print("   the shape of the session, not the shape of any one call.")
    print()
    print(f"   {DIM}decomposition_score: {data.get('decomposition_score')}{RESET}")
    for k, v in sorted((data.get("contributions") or {}).items(),
                       key=lambda kv: -kv[1]):
        print(f"   {DIM}  {k:<20} {v}{RESET}")
PY

step "A rug pull, caught"
# Separate from the batch above, and paced, because a real MCP client waits for
# each reply before sending the next -- it cannot call a tool it has not
# discovered yet. The batch above pipelines everything, which is not how a client
# behaves and would let a call race ahead of the listing that condemns it.
#
# The mock server advertises a benign read_file, then appends exfiltration
# instructions to its description on the second listing. Same name, same schema.
python3 - <<'RUGPULL' | sed 's/^/   /'
import json, subprocess, threading, time

msgs = [
    {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
     "params": {"name": "read_file", "arguments": {"path": "/srv/data/a.json"}}},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
     "params": {"name": "read_file", "arguments": {"path": "/srv/data/b.json"}}},
]
labels = {1: "tools/list  (benign definitions)",
          2: "read_file   before the mutation",
          3: "tools/list  (server rug-pulls here)",
          4: "read_file   after the mutation"}

p = subprocess.Popen(
    ["./chokepoint", "--policy", "examples/policy.yaml", "--log-level", "error",
     "--", "python3", "testdata/mock_mcp_server.py"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

out = []
threading.Thread(target=lambda: [out.append(l) for l in p.stdout], daemon=True).start()
for m in msgs:
    p.stdin.write(json.dumps(m) + "\n"); p.stdin.flush(); time.sleep(0.2)
p.stdin.close(); time.sleep(0.4)

GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"
for line in out:
    m = json.loads(line)
    if m.get("id") not in labels:
        continue
    if "error" in m:
        print(f"{RED}BLOCKED{RESET} #{m['id']}  {labels[m['id']]}")
        print(f"        {DIM}rule: {m['error']['data']['rule']}{RESET}")
    else:
        print(f"{GREEN}allowed{RESET} #{m['id']}  {labels[m['id']]}")
print()
print("The blocked call is identical in shape to the allowed one.")
print("What changed was the definition it was made against.")
RUGPULL

step "The same run, as a report"
# The score says a number. The report says where the session actually went,
# which is the part a reviewer can act on -- and the part that separates a
# repository scan from an exfiltration crawl, since those score identically.
./chokepoint --policy examples/policy.yaml --report --audit-log "$WORK/audit.jsonl" \
  --log-level error \
  -- python3 testdata/mock_mcp_server.py \
  < "$WORK/requests.jsonl" > /dev/null 2> "$WORK/report.txt" || true
sed 's/^/   /' "$WORK/report.txt"

step "The same run, as evidence"
# OTLP/JSON spans, one per line, carrying the OTel GenAI semantic conventions --
# so the log is readable by compliance tooling that never heard of chokepoint,
# rather than a bespoke format needing its own parser.
printf '   %s decisions recorded in audit.jsonl\n\n' "$(wc -l < "$WORK/audit.jsonl" | tr -d ' ')"
python3 -c "
import json,sys
rec = json.loads(open(sys.argv[1]).readline())
attrs = {a['key']: list(a['value'].values())[0] for a in rec['attributes']}
print('   first record:')
for k in ('gen_ai.operation.name','gen_ai.tool.name','chokepoint.policy.effect',
          'chokepoint.policy.rule','chokepoint.scope.out_of_scope'):
    if k in attrs: print(f'     {k:<34} {attrs[k]}')
print(f\"     {'status':<34} {rec.get('status',{}).get('message','ok')}\")
" "$WORK/audit.jsonl"

step "The same run, with metrics"
./chokepoint --policy examples/policy.yaml --metrics-addr 127.0.0.1:9464 --log-level error \
  -- python3 testdata/mock_mcp_server.py \
  < "$WORK/requests.jsonl" > /dev/null 2>&1 &
PROXY=$!

for _ in $(seq 1 40); do
  curl -sf http://127.0.0.1:9464/healthz >/dev/null 2>&1 && break
  sleep 0.25
done
curl -sf http://127.0.0.1:9464/metrics 2>/dev/null \
  | grep -E '^chokepoint_(tool_calls_total|policy_denials_total|decomposition_score|session_)' \
  | sed 's/^/   /' || echo "   (session finished before the scrape; run again to catch it)"
wait $PROXY 2>/dev/null || true

step "Try it yourself"
cat <<EOF
   Transparent mode — no policy, forwards everything byte-for-byte:
     ${dim}./chokepoint -- python3 testdata/mock_mcp_server.py${reset}

   In front of a real MCP server:
     ${dim}./chokepoint --policy examples/policy.yaml \\
       -- npx -y @modelcontextprotocol/server-filesystem /srv${reset}

   Where the thresholds come from:
     ${dim}go test ./internal/detect -run Calibration -v${reset}
EOF
echo
