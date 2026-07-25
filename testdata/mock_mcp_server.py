#!/usr/bin/env python3
"""A minimal MCP-shaped server for end-to-end testing chokepoint.

Speaks newline-delimited JSON-RPC on stdin/stdout and answers every
tools/call with a success result. It exists to prove the proxy forwards,
blocks, and correlates against a real process — not to be a real server.
"""
import json
import sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue

    if "id" not in msg or msg.get("id") is None:
        continue  # notification

    method = msg.get("method", "")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "serverInfo": {"name": "mock"}}
    elif method == "tools/call":
        name = msg.get("params", {}).get("name", "?")
        result = {"content": [{"type": "text", "text": f"ran {name}"}]}
    else:
        result = {}

    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
