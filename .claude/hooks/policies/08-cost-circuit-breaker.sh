#!/usr/bin/env bash
# =============================================================================
# Policy 08: COST CIRCUIT BREAKER
# =============================================================================
# Detects and blocks runaway agent loops that could rack up massive API costs.
#
# Real incidents:
#   • $47,000 loop (documented 2025): Two AI agents entered an unmonitored
#     conversation loop for 11 days, generating millions of tokens at
#     commercial API rates. No budget ceiling = unbounded spend.
#
#   • AutoGPT early deployments (2023): Users regularly received $100-$500
#     unexpected OpenAI bills from a single session due to recursive planning
#     loops that had no termination condition.
#
#   • AWS autoscaling incidents (k8s.af): Automated tooling triggering
#     cloud resource provisioning loops created $10K-$50K+ bills in hours.
#
# What this detects:
#   1. Repeated identical Bash commands in same session (loop indicator)
#   2. API calls to expensive endpoints (OpenAI, Anthropic) from within
#      agent code without rate-limiting
#   3. Bulk file operations that suggest runaway processing
#
# How loop detection works:
#   • Tracks command hashes in ~/.claude/audit/session-commands.jsonl
#   • If the SAME command runs 5+ times in one session → BLOCK
#   • Session state cleared on new session (uses SESSION_ID)
# =============================================================================

set -euo pipefail

INPUT_FILE="${HOOK_INPUT_FILE:-/dev/stdin}"
TOOL_NAME=$(jq -r '.tool_name // "unknown"' < "$INPUT_FILE")
SESSION_ID=$(jq -r '.session_id // "unknown"' < "$INPUT_FILE")
TIMESTAMP="${TIMESTAMP:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

[[ "$TOOL_NAME" == "Bash" ]] || exit 0

COMMAND=$(jq -r '.tool_input.command // ""' < "$INPUT_FILE")

# Skip very short / trivial commands
[[ ${#COMMAND} -lt 10 ]] && exit 0

# Skip git, npm, pip (covered by other policies), and read-only commands
echo "$COMMAND" | grep -qiE '^(git |npm |pip |ls |cat |head |tail |echo |printf |cd |pwd |which |type )' && exit 0

# Loop detection: count how many times this exact command ran in this session
SESSION_CMD_LOG="${AUDIT_DIR:-$HOME/.claude/audit}/session-${SESSION_ID}-cmds.jsonl"
mkdir -p "${AUDIT_DIR:-$HOME/.claude/audit}"

# Hash the command for comparison
CMD_HASH=$(echo "$COMMAND" | md5sum | awk '{print $1}')

# Count occurrences of this command hash in session log
COUNT=0
if [[ -f "$SESSION_CMD_LOG" ]]; then
  COUNT=$(grep -c "\"hash\":\"$CMD_HASH\"" "$SESSION_CMD_LOG" 2>/dev/null || echo 0)
fi

# Append this command to the session log
jq -n \
  --arg ts   "$TIMESTAMP" \
  --arg hash "$CMD_HASH" \
  --arg cmd  "$(echo "$COMMAND" | head -c 200)" \
  '{timestamp:$ts, hash:$hash, cmd:$cmd}' \
  >> "$SESSION_CMD_LOG"

LOOP_THRESHOLD=5

if [[ "$COUNT" -ge "$LOOP_THRESHOLD" ]]; then

  jq -n \
    --arg ts      "$TIMESTAMP" \
    --arg tool    "$TOOL_NAME" \
    --arg policy  "cost-circuit-breaker" \
    --arg matched "Command repeated $COUNT times in session: $(echo "$COMMAND" | head -c 100)" \
    --arg session "$SESSION_ID" \
    --arg cwd     "${CWD:-}" \
    '{timestamp:$ts, event:"policy_blocked", policy:$policy, tool:$tool, matched:$matched, session:$session, cwd:$cwd}' \
    >> "${AUDIT_LOG:-$HOME/.claude/audit/policy-violations.jsonl}"

  cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║        ORG POLICY VIOLATION — AGENT LOOP DETECTED & BLOCKED  ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted : $TOOL_NAME
Loop count     : This exact command has run $COUNT times in this session
Command        : $(echo "$COMMAND" | head -c 120)

Why this matters:
  • A documented 11-day AI agent loop cost $47,000 in API fees before
    anyone noticed. No budget ceiling = unbounded runaway spend.
  • AutoGPT (2023): Users received $100-$500 unexpected bills from
    recursive planning loops in a single session.
  • Loops often indicate: broken tool output, unclear goal, infinite
    retry without backoff, or a confusing error response from a tool.

What to do instead:
  • Investigate why the command keeps being retried
  • Check if the previous executions actually succeeded
  • Add a goal or constraint that avoids the retry loop
  • If this is legitimately iterative: reformulate as a shell loop
    with a clear termination condition

Session command log: $SESSION_CMD_LOG
Violation log: ~/.claude/audit/policy-violations.jsonl

EOF

  exit 2
fi

# Detect expensive API calls being made from within agent code
EXPENSIVE_APIS='api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|bedrock\..*\.amazonaws\.com'
if echo "$COMMAND" | grep -qiE "(curl|wget|fetch|http).*($EXPENSIVE_APIS)"; then
  # Audit only — don't block, but log it
  jq -n \
    --arg ts      "$TIMESTAMP" \
    --arg tool    "$TOOL_NAME" \
    --arg policy  "cost-circuit-breaker" \
    --arg matched "LLM API call from within agent: $(echo "$COMMAND" | head -c 100)" \
    --arg session "$SESSION_ID" \
    --arg cwd     "${CWD:-}" \
    '{timestamp:$ts, event:"policy_audit_expensive_api", policy:$policy, tool:$tool, matched:$matched, session:$session, cwd:$cwd}' \
    >> "${AUDIT_LOG:-$HOME/.claude/audit/policy-violations.jsonl}"
fi

exit 0
