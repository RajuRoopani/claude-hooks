#!/usr/bin/env bash
# =============================================================================
# pre-tool.sh — Claude Code Org Policy Enforcer (PreToolUse hook)
# =============================================================================
# Orchestrates all active security policies. Fires before EVERY tool call.
#
# Architecture:
#   • Reads tool input from stdin once → saves to temp file
#   • Runs each enabled policy from ./policies/*.sh in order
#   • Any policy can: BLOCK (exit 2), AUDIT-only (exit 0 + log), or PASS
#   • Audit log → ~/.claude/audit/policy-violations.jsonl
#
# To add a policy: drop a *.sh file into ./policies/ — auto-discovered.
# To disable a policy: prefix the filename with _ (e.g., _01-secrets.sh)
# To configure: edit policy-config.json in this repo root
# =============================================================================

set -euo pipefail

HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICIES_DIR="$HOOK_DIR/policies"
CONFIG_FILE="$HOOK_DIR/../../policy-config.json"
AUDIT_DIR="${HOME}/.claude/audit"
AUDIT_LOG="$AUDIT_DIR/policy-violations.jsonl"

# Read stdin once into a temp file (policies can't re-read stdin)
TMPFILE=$(mktemp /tmp/claude-hook-XXXXXX.json)
trap 'rm -f "$TMPFILE"' EXIT
cat > "$TMPFILE"

# Extract common fields (all policies can reuse these env vars)
export HOOK_INPUT_FILE="$TMPFILE"
export TOOL_NAME=$(jq -r '.tool_name // "unknown"'  < "$TMPFILE")
export SESSION_ID=$(jq -r '.session_id // "unknown"' < "$TMPFILE")
export CWD=$(jq -r        '.cwd // ""'               < "$TMPFILE")
export TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
export AUDIT_LOG
export AUDIT_DIR

# Load config (mode overrides per policy)
load_policy_mode() {
  local policy_name="$1"
  if [[ -f "$CONFIG_FILE" ]] && command -v jq &>/dev/null; then
    local enabled mode
    enabled=$(jq -r --arg p "$policy_name" '.policies[$p].enabled // true' "$CONFIG_FILE" 2>/dev/null)
    mode=$(jq    -r --arg p "$policy_name" '.policies[$p].mode // "block"' "$CONFIG_FILE" 2>/dev/null)
    echo "$enabled|$mode"
  else
    echo "true|block"
  fi
}

# Run all enabled policies
mkdir -p "$AUDIT_DIR"

shopt -s nullglob
for policy_script in "$POLICIES_DIR"/[0-9]*.sh; do
  policy_name=$(basename "$policy_script" .sh | sed 's/^[0-9]*-//')
  cfg=$(load_policy_mode "$policy_name")
  enabled="${cfg%%|*}"
  mode="${cfg##*|}"

  [[ "$enabled" == "false" ]] && continue

  exit_code=0
  bash "$policy_script" < "$TMPFILE" || exit_code=$?

  if [[ $exit_code -eq 2 ]]; then
    if [[ "$mode" == "audit" ]]; then
      # Audit-only mode: log the violation but don't block
      jq -n \
        --arg ts      "$TIMESTAMP" \
        --arg tool    "$TOOL_NAME" \
        --arg policy  "$policy_name" \
        --arg session "$SESSION_ID" \
        --arg cwd     "$CWD" \
        --arg mode    "audit-only" \
        '{timestamp:$ts, event:"policy_audit", policy:$policy, tool:$tool, session:$session, cwd:$cwd, mode:$mode}' \
        >> "$AUDIT_LOG"
    else
      exit 2  # Hard block — policy script already printed the message + logged
    fi
  fi
done

exit 0
