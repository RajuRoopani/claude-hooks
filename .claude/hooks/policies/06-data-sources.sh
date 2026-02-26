#!/usr/bin/env bash
# =============================================================================
# Policy 06: RESTRICTED DATA SOURCES (ICM + Kusto/ADX)
# =============================================================================
# Blocks AI agent access to internal diagnostic/telemetry systems.
#
# Why this matters for an org:
#   • ICM (Incident Communication Manager): Contains live incident data,
#     customer impact details, internal escalation paths, and unreleased
#     service health info. AI agents accessing this during an incident could
#     leak sensitive customer data or generate misleading summaries that
#     get acted on as fact.
#
#   • Kusto / Azure Data Explorer: Production telemetry database. Direct
#     queries by an AI agent risk: full-table scans that spike query costs,
#     exfiltrating customer behavioral data to the LLM context window, or
#     running expensive KQL queries that consume cluster capacity.
#
#   This policy enforces the same access controls on AI agents that your
#   org enforces on human engineers via service authentication.
#
# To add a new restricted data source:
#   1. Add the name to POLICY_NAMES
#   2. Add the pattern (ERE) to POLICY_PATTERNS (same index)
#   Done — no other changes needed.
# =============================================================================

set -euo pipefail

INPUT=$(cat < "${HOOK_INPUT_FILE:-/dev/stdin}")

TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // "unknown"')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "unknown"')
TIMESTAMP="${TIMESTAMP:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

# =============================================================================
# POLICY REGISTRY — add entries here to extend
# =============================================================================

POLICY_NAMES=(
  "ICM Dashboard"
  "Kusto / Azure Data Explorer"
  "Internal Metrics / Geneva"
  "SharePoint / Internal Docs"
)

POLICY_PATTERNS=(
  "icm\.ad\.msft\.net|icmdashboard\.microsoft\.com|icm\.microsoft\.com"
  "\.kusto\.windows\.net|\.kustomfa\.windows\.net|\.kusto\.azuresynapse\.net|kustodb\.windows\.net"
  "geneva\..*\.microsoft\.com|metrics\.azure\.com/.*internal|azuremetrics\.core"
  "sharepoint\.com/sites/(internal|confidential|restricted|hr|legal|finance)"
)

# =============================================================================

TOOL_INPUT_STR=$(echo "$INPUT" | jq -c '.tool_input // {}' | tr '[:upper:]' '[:lower:]')

BLOCKED=false
MATCHED_POLICY=""
MATCHED_PATTERN=""

for i in "${!POLICY_NAMES[@]}"; do
  pattern="${POLICY_PATTERNS[$i]}"
  if echo "$TOOL_INPUT_STR" | grep -qE "$pattern"; then
    BLOCKED=true
    MATCHED_POLICY="${POLICY_NAMES[$i]}"
    MATCHED_PATTERN="$pattern"
    break
  fi
done

if [[ "$BLOCKED" == "true" ]]; then

  mkdir -p "${AUDIT_DIR:-$HOME/.claude/audit}"
  jq -n \
    --arg ts      "$TIMESTAMP" \
    --arg tool    "$TOOL_NAME" \
    --arg policy  "$MATCHED_POLICY" \
    --arg matched "$MATCHED_PATTERN" \
    --arg session "$SESSION_ID" \
    --arg cwd     "${CWD:-}" \
    '{timestamp:$ts, event:"policy_blocked", policy:$policy, tool:$tool, matched:$matched, session:$session, cwd:$cwd}' \
    >> "${AUDIT_LOG:-$HOME/.claude/audit/policy-violations.jsonl}"

  cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║           ORG POLICY VIOLATION — RESTRICTED DATA SOURCE      ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted : $TOOL_NAME
Blocked policy : $MATCHED_POLICY
Policy         : Direct AI agent access to this data source is disabled
                 org-wide. Use approved workflows to query this system.

What to do instead:
  • Use the approved workflow for $MATCHED_POLICY in Confluence
  • Contact your on-call lead for escalation access
  • Reach out to #engineering-ops in Slack for exceptions

Violation logged to: ~/.claude/audit/policy-violations.jsonl

EOF

  exit 2
fi

exit 0
