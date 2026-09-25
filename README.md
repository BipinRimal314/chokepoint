# chokepoint

[![CI](https://github.com/BipinRimal314/chokepoint/actions/workflows/ci.yml/badge.svg)](https://github.com/BipinRimal314/chokepoint/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/BipinRimal314/chokepoint.svg)](https://pkg.go.dev/github.com/BipinRimal314/chokepoint)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**A security checkpoint and audit log for what your AI agent does with its tools.**

AI agents such as Claude Code and Cursor reach files, databases and the web
through [MCP](https://modelcontextprotocol.io) tool servers. chokepoint sits
in that connection. Every tool call is checked against rules you set (stay in
this folder, never touch credentials, no internet except these sites), then
blocked or let through, and written to a log. `chokepoint report` tells you
afterwards what the agent did and every time it crossed a line, so you don't
have to watch it.

## Quickstart

```bash
cd your-project
chokepoint init              # writes chokepoint.yaml: this folder only, no secrets, no internet
chokepoint wrap .mcp.json    # routes your MCP servers through chokepoint (backup kept)
# ...use your agent as usual...
chokepoint report            # what it did, and every breach
```

`wrap` works on any config with an `mcpServers` block: Claude Code's
`.mcp.json`, Claude Desktop's `claude_desktop_config.json`, Cursor's
`.cursor/mcp.json`. `chokepoint unwrap` undoes it. Audit logs go to
`~/.local/state/chokepoint/` (`%LocalAppData%` on Windows), outside the
project so they can't be committed by accident.

Real output, from the hijacked-agent test below:

```text
chokepoint report: 14 tool calls in 2 sessions, 2026-09-25 18:34:02 to 2026-09-25 18:34:03

  breaches blocked:              11
  breaches ALLOWED (monitor):    0
  changes made (writes, edits):  1

every breach:
  18:34:02  BLOCKED  filesystem  read_text_file       no-secrets         /home/you/.ssh/id_ed25519
  18:34:02  BLOCKED  filesystem  read_multiple_files  no-secrets         /home/you/.aws/credentials, /home/you/project/.env, ...
  18:34:02  BLOCKED  filesystem  read_text_file       no-secrets         /home/you/project/../.aws/credentials
  18:34:02  BLOCKED  filesystem  write_file           outside-workspace  /home/you/.bashrc
  18:34:03  BLOCKED  fetch       fetch                outside-workspace  http://127.0.0.1:8766/collect?data=...
  18:34:03  BLOCKED  fetch       fetch                no-cloud-metadata  http://169.254.169.254/latest/meta-data/iam/...
  ...
```

Or run `./demo.sh`, which drives the real binary against a real MCP server
and shows each kind of refusal, the report, the audit log and live metrics.

## Block, or just watch

Set `mode:` in `chokepoint.yaml`, or pass `--mode` on the command line.

| Mode | A call that breaks a rule | Use it when |
|---|---|---|
| `enforce` (default) | refused; the agent gets an error starting "blocked by chokepoint" and carries on | you want the rules to hold |
| `monitor` | let through, and listed in the report as **ALLOWED** | the agent must never be stopped, e.g. an unattended run, or you are testing what it does unchecked |

Monitor mode blocks nothing and protects nothing. In testing, a hijacked
agent in monitor mode sent `.env` to a web server and rewrote `~/.bashrc`,
and the report listed both.

For the few things you never want to happen even then, mark the rule:

```yaml
  - name: no-secrets
    match: ...
    effect: deny
    always_enforce: true   # still blocks in monitor mode
```

`chokepoint init` writes that line, commented out, on the credentials and
cloud-metadata rules. When any rule is marked `always_enforce`, a request
chokepoint can't read unambiguously is refused in monitor mode too, because
it can't be shown not to break that rule.

## What it checks

The rules `chokepoint init` writes, in order:

| Rule | Blocks |
|---|---|
| `tool-definition-changed` | a server that changes a tool's definition after the session started, the signature of tool poisoning |
| `no-secrets` | SSH, AWS, GCP, Azure, Kubernetes and Docker credentials, `.env` files, private keys, `.netrc`, `/etc/shadow`, wherever they are |
| `no-cloud-metadata` | cloud instance metadata endpoints, which hand out the machine's own credentials |
| `outside-workspace` | any file outside the project folder, and any website not listed under `workspace:` |
| `watch-changes` | nothing; records every write, edit, move and delete |

Before any rule runs, chokepoint also refuses requests it can't read the same
way the server will (`ambiguous-request`, `malformed-request`). Go's JSON
decoder and most servers disagree about a message carrying both `arguments`
and `Arguments`, and before this check that disagreement let a file outside
the workspace be read.

Paths are resolved before they're compared, so `project/../.aws/credentials`
is recognised as `.aws/credentials`. Batch calls are checked path by path.
Rules are [CEL](https://cel.dev) expressions over the tool, its arguments,
the places it touches and the session so far; the full list of variables is
in [docs/reference.md](docs/reference.md#policy).

## Tested with a real agent

[docs/real-agent-test.md](docs/real-agent-test.md), rerunnable with the
scripts in [`e2e/`](e2e): the reference filesystem and fetch servers, a real
open-source project, canary credentials, and files with planted prompt
injections.

- **Claude Code, 14 sessions:** ordinary work was never blocked. Every
  attempt to read credentials, read `.env` or reach a site not on the list
  was blocked. Claude refused the planted injections by itself, so those
  never reached chokepoint.
- **A scripted hijacked agent:** all 11 attacks blocked, including path
  traversal, secrets hidden in a batch read, exfiltration to a web server,
  a `.bashrc` write and three parser tricks. All legitimate calls worked.

## What it can't see

- **Only calls that go through MCP.** An agent's own built-in tools skip it.
  Run Claude Code with `--tools ""` so MCP is the only way it can act; in
  testing, disabling `Bash` alone wasn't enough. Or pair chokepoint with a
  sandbox whose network rules are the real wall.
- **Where a call goes, not what it means.** Reading an allowed file and
  sending its contents to an allowed site is two allowed calls.
- **Relative paths** such as `.` are refused under a workspace, because
  chokepoint can't know the server's working folder. Agents recover by using
  the full path.

## Install

Releases carry static binaries for Linux, macOS and Windows (amd64 and
arm64), a `checksums.txt`, and a build provenance attestation.

```bash
# from a release
tar xzf chokepoint_<version>_linux_amd64.tar.gz
sha256sum -c checksums.txt --ignore-missing
gh attestation verify chokepoint_<version>_linux_amd64.tar.gz --repo BipinRimal314/chokepoint

# or from source (Go 1.25+)
go install github.com/BipinRimal314/chokepoint/cmd/chokepoint@latest
```

Verifying the attestation matters here specifically: this is a binary you
install to refuse things on your behalf, which makes it worth substituting.

## Running one server by hand

`wrap` sets this up for you:

```bash
chokepoint --policy chokepoint.yaml --audit-log agent.jsonl \
  -- npx -y @modelcontextprotocol/server-filesystem /srv
```

With no `--policy`, chokepoint forwards every message byte for byte and checks
nothing, so it can go into a working setup first and get rules second.
`--report`, `--metrics-addr`, `--otlp-endpoint` and the rest are covered in
[docs/reference.md](docs/reference.md#telemetry). The audit log is
OpenTelemetry JSON, so other tools can read it.

## Why it exists

It grew out of research on catching misuse by AI agents from their behaviour
([SSRN 6355658](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6355658)).
That research found behaviour-based detection has structural blind spots:
harmful work can look exactly like thorough work. chokepoint first tried a
behaviour score in the request path, and measurement showed the score can't
separate the two either. It's still computed, as an experimental signal
([docs/single-tool-sweep.md](docs/single-tool-sweep.md)). What works, and what
chokepoint is built around, is simpler: clear boundaries, checked on every
call as it happens, and a record of every decision.

## Documentation

- [How it works](docs/how-it-works.md): the plain-language version.
- [Real-agent test](docs/real-agent-test.md): what was tested and what happened.
- [Reference](docs/reference.md): policy language, every check, the evidence
  log, telemetry, Kubernetes, known limitations, and design decisions.
- [Single-tool sweep](docs/single-tool-sweep.md): why the behaviour score
  can't carry a block on its own.

## Development

```bash
go test ./...                 # unit tests
go test -race -count=3 ./...  # what CI runs
go build -o chokepoint ./cmd/chokepoint

# end to end: a real project, canary secrets, real MCP servers, a hijacked agent
e2e/setup.sh /tmp/cp-e2e && python3 e2e/hijacked_agent.py /tmp/cp-e2e

# the release build, without tagging anything
goreleaser check && goreleaser release --snapshot --clean
```

## License

Apache-2.0. See [LICENSE](LICENSE).
