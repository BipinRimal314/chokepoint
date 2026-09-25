package main

import (
	"fmt"
	"strings"
)

// starterPolicy is what `chokepoint init` writes: a policy that is useful
// before anyone has read the documentation, and says why each rule is there.
//
// Every deny in it is a boundary, not a guess about behaviour, so it can be
// armed on day one without a week of tuning. The behavioural score is left
// out on purpose: measured on real sessions, it cannot separate careful work
// from a sweep (docs/single-tool-sweep.md).
func starterPolicy(workspace, mode string) string {
	return fmt.Sprintf(`# chokepoint policy, written by `+"`chokepoint init`"+`.
#
# Every tool call your agent makes through a wrapped MCP server is checked
# against the rules below, top to bottom. The first deny that matches decides.
# Every decision is written to the audit log; `+"`chokepoint report`"+` reads it.

# enforce: refuse a call that breaks a rule.
# monitor: let it through, so an unattended agent keeps working, and record
#          it as a violation. Switch without editing: --mode monitor.
mode: %s

default_effect: allow

# Where the agent may reach. Anything else is out of bounds.
#
# Folders are matched on the real path, so "../" tricks do not get out. Add a
# URL prefix for each site the agent may fetch from; with none listed, every
# web request is out of bounds, which is what you want for an agent that
# should stay off the internet.
workspace:
  - %s
  # - https://docs.python.org
  # - https://api.github.com

rules:
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
        t.matches("(^|/)(\\.ssh|\\.aws|\\.gnupg|\\.kube|\\.docker|\\.azure|\\.config/gcloud)(/|$)") ||
        t.matches("(^|/)\\.env(\\.(local|dev|development|prod|production|staging|test))?$") ||
        t.matches("\\.(pem|key|p12|pfx|keystore|jks)$") ||
        t.matches("(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519|\\.netrc|\\.git-credentials|\\.pgpass|\\.npmrc|\\.pypirc|credentials|credentials\\.json)$") ||
        t.matches("^(file://)?/etc/(shadow|gshadow|sudoers)"))
    effect: deny
    message: Credentials and keys are off limits to the agent.

  # Cloud instance metadata hands out the machine's own cloud credentials.
  - name: no-cloud-metadata
    match: >-
      targets.exists(t,
        t.contains("169.254.169.254") || t.contains("metadata.google.internal") ||
        t.contains("100.100.100.200") || t.contains("fd00:ec2::254"))
    effect: deny
    message: Cloud instance metadata is off limits to the agent.

  # The boundary declared in workspace above.
  - name: outside-workspace
    match: scope_declared && out_of_scope.size() > 0
    effect: deny
    message: That is outside the folders and sites this agent may use.

  # Not a breach: recorded so the report can show what the agent changed.
  - name: watch-changes
    match: tool.matches("(?i)(write|edit|create|move|rename|delete|remove)")
    effect: audit
`, mode, yamlQuote(workspace))
}

// yamlQuote makes a path safe as a YAML scalar.
func yamlQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
