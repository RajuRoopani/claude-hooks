#!/usr/bin/env bash
# =============================================================================
# block-icm.sh — Org Policy: Block access to ICM dashboard
# =============================================================================
# Fires on PreToolUse for ALL tools.
# Blocks any tool invocation that references icm.ad.msft.net in its input
# (Bash commands, WebFetch URLs, browser/MCP tool params, etc.)
# =============================================================================

set -euo pipefail

# --- Read full hook input from stdin ---
INPUT=$(cat)

# --- Extract fields ---
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // "unknown"')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "unknown"')
CWD=$(echo "$INPUT" | jq -r '.cwd // ""')
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# --- Blocked patterns ---
# Matches icm.ad.msft.net and common variations
ICM_PATTERNS=(
  "icm\.ad\.msft\.net"
  "icmdashboard\.microsoft\.com"
  "icm\.microsoft\.com"
)

# --- Stringify the entire tool_input for scanning ---
TOOL_INPUT_STR=$(echo "$INPUT" | jq -c '.tool_input // {}' | tr '[:upper:]' '[:lower:]')

# --- Check each pattern ---
BLOCKED=false
MATCHED_PATTERN=""

for pattern in "${ICM_PATTERNS[@]}"; do
  if echo "$TOOL_INPUT_STR" | grep -qE "$pattern"; then
    BLOCKED=true
    MATCHED_PATTERN="$pattern"
    break
  fi
done

# --- If blocked: log + exit 2 to stop Claude ---
if [ "$BLOCKED" = true ]; then

  # Audit log (append-only, valid JSON via jq)
  LOG_DIR="${HOME}/.claude/audit"
  mkdir -p "$LOG_DIR"
  jq -n \
    --arg ts "$TIMESTAMP" \
    --arg tool "$TOOL_NAME" \
    --arg matched "$MATCHED_PATTERN" \
    --arg session "$SESSION_ID" \
    --arg cwd "$CWD" \
    '{timestamp: $ts, event: "icm_blocked", tool: $tool, matched: $matched, session: $session, cwd: $cwd}' \
    >> "$LOG_DIR/icm-policy-violations.jsonl"

  # Feedback to Claude (stderr → shown as Claude's blocker reason)
  cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║              ORG POLICY VIOLATION — ACTION BLOCKED           ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted : $TOOL_NAME
Blocked pattern: $MATCHED_PATTERN
Policy         : ICM dashboard access is disabled for all Claude
                 Code sessions across this organization.

What to do instead:
  • Use the approved incident management workflow in Confluence
  • Contact your on-call lead for ICM escalation access
  • Reach out to #engineering-ops in Slack for exceptions

Violation logged to: ~/.claude/audit/icm-policy-violations.jsonl

EOF

  exit 2  # exit 2 = blocking error → Claude sees this as a hard stop
fi

# --- Not blocked, allow tool to proceed ---
exit 0
