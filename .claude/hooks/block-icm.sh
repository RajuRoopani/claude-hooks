#!/usr/bin/env bash
# =============================================================================
# block-icm.sh — Org Policy: Block restricted tools & services
# =============================================================================
# Fires on PreToolUse for ALL tools.
# Blocks any tool invocation that references a restricted endpoint in its input
# (Bash commands, WebFetch URLs, browser/MCP tool params, etc.)
#
# Blocked policies:
#   1. ICM Dashboard   — icm.ad.msft.net
#   2. Kusto / ADX     — *.kusto.windows.net, *.kusto.azuresynapse.net
#
# To add a new policy: add an entry to POLICY_NAMES and POLICY_PATTERNS below.
# =============================================================================

set -euo pipefail

# --- Read full hook input from stdin ---
INPUT=$(cat)

# --- Extract fields ---
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // "unknown"')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "unknown"')
CWD=$(echo "$INPUT" | jq -r '.cwd // ""')
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# =============================================================================
# POLICY REGISTRY
# POLICY_NAMES and POLICY_PATTERNS must have matching indexes.
# Patterns are ERE (grep -E). Separate multiple patterns per policy with |
# =============================================================================

POLICY_NAMES=(
  "ICM Dashboard"
  "Kusto / Azure Data Explorer"
)

POLICY_PATTERNS=(
  "icm\.ad\.msft\.net|icmdashboard\.microsoft\.com|icm\.microsoft\.com"
  "\.kusto\.windows\.net|\.kustomfa\.windows\.net|\.kusto\.azuresynapse\.net|kustodb\.windows\.net"
)

# =============================================================================

# --- Stringify the entire tool_input for scanning (case-insensitive) ---
TOOL_INPUT_STR=$(echo "$INPUT" | jq -c '.tool_input // {}' | tr '[:upper:]' '[:lower:]')

# --- Check each policy ---
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

# --- If blocked: audit log + hard stop ---
if [ "$BLOCKED" = true ]; then

  # Audit log (append-only, valid JSON)
  LOG_DIR="${HOME}/.claude/audit"
  mkdir -p "$LOG_DIR"
  jq -n \
    --arg ts        "$TIMESTAMP" \
    --arg tool      "$TOOL_NAME" \
    --arg policy    "$MATCHED_POLICY" \
    --arg matched   "$MATCHED_PATTERN" \
    --arg session   "$SESSION_ID" \
    --arg cwd       "$CWD" \
    '{timestamp: $ts, event: "policy_blocked", policy: $policy, tool: $tool, matched: $matched, session: $session, cwd: $cwd}' \
    >> "$LOG_DIR/policy-violations.jsonl"

  # Feedback to Claude (stderr → shown as Claude's blocker reason)
  cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║              ORG POLICY VIOLATION — ACTION BLOCKED           ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted : $TOOL_NAME
Blocked policy : $MATCHED_POLICY
Policy         : Access to this service is disabled for all Claude
                 Code sessions across this organization.

What to do instead:
  • Use the approved workflow for $MATCHED_POLICY in Confluence
  • Contact your on-call lead for escalation access
  • Reach out to #engineering-ops in Slack for exceptions

Violation logged to: ~/.claude/audit/policy-violations.jsonl

EOF

  exit 2  # exit 2 = blocking error → Claude sees this as a hard stop
fi

# --- Not blocked, allow tool to proceed ---
exit 0
