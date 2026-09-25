package main

import (
	"fmt"
	"strconv"
	"strings"
)

// starterPolicy is what `chokepoint init` writes: a policy that is useful
// before anyone has read the documentation, and says why each rule is there.
//
// Every deny in it is a boundary, not a guess about behaviour, so it can be
// armed on day one without a week of tuning. The behavioural score is left
// out on purpose: measured on real sessions, it cannot separate careful work
// from a sweep (docs/single-tool-sweep.md).
//
// auditDir is where this machine's audit logs go, written into the
// self-protection rule as a literal path: a pattern cannot tell the log
// folder from any other folder named chokepoint, and it would miss a parent
// folder being deleted with the logs inside.
func starterPolicy(workspace, mode, auditDir string) string {
	logs := strconv.Quote(auditDir)
	return fmt.Sprintf(`# chokepoint policy, written by `+"`chokepoint init`"+`.
#
# Every tool call your agent makes through a wrapped MCP server is checked
# against the rules below, top to bottom. The first deny that matches decides.
# Every decision is written to the audit log; `+"`chokepoint report`"+` reads it.

# enforce: refuse a call that breaks a rule.
# monitor: let it through, so an unattended agent keeps working, and record
#          it as a violation. Switch without editing: --mode monitor.
#          Monitor mode blocks nothing, except rules marked
#          always_enforce: true (see no-secrets below).
mode: %[1]s

default_effect: allow

# Where the agent may reach. Anything else is out of bounds.
#
# Folders are matched on the real path, so "../" tricks do not get out. Add a
# URL prefix for each site the agent may fetch from; with none listed, every
# web request is out of bounds, which is what you want for an agent that
# should stay off the internet.
workspace:
  - %[2]s
  # - https://docs.python.org
  # - https://api.github.com

rules:
  # The agent may not change what watches it: these rules, its MCP config,
  # Claude Code's or Cursor's settings, or the audit logs. An agent that can
  # unwrap its servers or delete the log can end its own supervision, and in
  # monitor mode it would erase the record that mode exists to keep. So this
  # one blocks in monitor mode too; delete always_enforce to let it through.
  # Shell commands that name these files are refused whether they read or
  # write them, since a command's effect cannot be told from its text.
  - name: protect-agent-config
    match: >-
      (tool.matches("(?i)(write|edit|create|move|rename|delete|remove|notebook)") || tool == "Bash") &&
      targets.exists(t,
        t.matches("(^|[/\\\\])(chokepoint\\.yaml|\\.mcp\\.json|\\.mcp\\.json\\.chokepoint-backup|claude_desktop_config\\.json)$") ||
        t.matches("(^|[/\\\\])\\.(claude|cursor)([/\\\\]|$)") ||
        t.startsWith(%[3]s) ||
        (%[3]s.startsWith(t + "/") &&
          (tool.matches("(?i)(delete|remove|move|rename)") ||
           (tool == "Bash" && args.command.matches("(^|[\\s;&|(])(rm|mv|rmdir|shred|unlink)(\\s|$)")))))
    effect: deny
    always_enforce: true
    message: The agent may not change its own rules, tool configuration or audit logs.

  # A server that changes a tool's definition mid-session is the signature of
  # tool poisoning: the agent re-reads the new description and follows it.
  - name: tool-definition-changed
    match: tool_definition_changed
    effect: deny
    message: This tool changed after the session started. Have a person re-approve the server.

  # Credentials and keys, wherever they are, including inside the workspace.
  - name: no-secrets
    match: >-
      targets.exists(t,
        t.matches("(^|[/\\\\])(\\.ssh|\\.aws|\\.gnupg|\\.kube|\\.docker|\\.azure|\\.config/gcloud)([/\\\\]|$)") ||
        t.matches("(^|[/\\\\])\\.env(\\.(local|dev|development|prod|production|staging|test))?$") ||
        t.matches("\\.(pem|key|p12|pfx|keystore|jks)$") ||
        t.matches("(^|[/\\\\])(id_rsa|id_dsa|id_ecdsa|id_ed25519|\\.netrc|\\.git-credentials|\\.pgpass|\\.npmrc|\\.pypirc|credentials|credentials\\.json)$") ||
        t.matches("^(file://)?/etc/(shadow|gshadow|sudoers)"))
    effect: deny
    # Uncomment to keep this blocking even in monitor mode.
    # always_enforce: true
    message: Credentials and keys are off limits to the agent.

  # Cloud instance metadata hands out the machine's own cloud credentials.
  - name: no-cloud-metadata
    match: >-
      targets.exists(t,
        t.contains("169.254.169.254") || t.contains("metadata.google.internal") ||
        t.contains("100.100.100.200") || t.contains("fd00:ec2::254"))
    effect: deny
    # always_enforce: true
    message: Cloud instance metadata is off limits to the agent.

  # Raw network commands in a shell. The hook reads paths and URLs out of a
  # command's text, and "curl example.com" has no URL in it to check, so the
  # commands themselves are refused and the agent is pointed at a web tool
  # the workspace can check. Package managers (npm, pip, git) are not
  # covered; add them here if the agent must not install anything.
  - name: no-shell-network
    match: >-
      tool == "Bash" && has(args.command) &&
      args.command.matches("(^|[\\s;&|(\\x60$])(curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync|ftp)(\\s|$)")
    effect: deny
    message: Network commands in the shell are off limits; use the web fetch tool, which is checked against the allowed sites.

  # The boundary declared in workspace above.
  - name: outside-workspace
    match: scope_declared && out_of_scope.size() > 0
    effect: deny
    message: That is outside the folders and sites this agent may use.

  # Not a breach: recorded so the report can show what the agent changed.
  - name: watch-changes
    match: tool.matches("(?i)(write|edit|create|move|rename|delete|remove)")
    effect: audit
`, mode, yamlQuote(workspace), logs)
}

// yamlQuote makes a path safe as a YAML scalar.
func yamlQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
