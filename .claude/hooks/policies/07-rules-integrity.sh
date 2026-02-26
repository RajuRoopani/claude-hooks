#!/usr/bin/env bash
# =============================================================================
# Policy 07: AI RULES FILE INTEGRITY (Anti-Poisoning)
# =============================================================================
# Audits and optionally blocks modifications to AI instruction files.
#
# Real incident (March 2025, Pillar Security / CVE category):
#   Researchers discovered that configuration files like .cursorrules,
#   .github/copilot-instructions.md, and CLAUDE.md are read by AI assistants
#   as authoritative instructions. An attacker can embed invisible Unicode
#   characters (bidirectional text markers, zero-width joiners) that render
#   as whitespace in code reviews and GitHub PR diffs but are read by the
#   AI as explicit commands.
#
#   The poisoned rules file instructs the AI to:
#     • Insert backdoors into generated code
#     • Expose credentials found in the project
#     • Subtly alter authentication logic
#     • Exfiltrate source code via innocent-looking HTTP calls
#
#   Once merged into a repository, the poisoned file:
#     ✓ Affects EVERY developer using the AI assistant on that project
#     ✓ Survives repository forks (persistent supply chain vector)
#     ✓ Is invisible in standard code review (no diff shows hidden chars)
#
#   "IDEsaster" (December 2025): 30+ CVEs across 100% of tested AI IDEs
#   including Cursor, Windsurf, GitHub Copilot, JetBrains, Cline.
#   One attack vector: IDE Settings Overwrite via .vscode/settings.json
#   to execute arbitrary commands on file open.
#
# This policy (default: audit mode):
#   • Logs all writes to AI instruction files with full diff context
#   • Detects invisible Unicode characters in file content
#   • Flags content that instructs the AI to hide its actions
#   • In block mode: requires human approval (exit 2 → orchestrator handles)
#
# Protected files:
#   CLAUDE.md · .cursorrules · .cursorignore · .github/copilot-instructions.md
#   .claude/settings.json · .vscode/settings.json · .windsurf/rules
# =============================================================================

set -euo pipefail

INPUT_FILE="${HOOK_INPUT_FILE:-/dev/stdin}"
TOOL_NAME=$(jq -r '.tool_name // "unknown"' < "$INPUT_FILE")
SESSION_ID=$(jq -r '.session_id // "unknown"' < "$INPUT_FILE")
TIMESTAMP="${TIMESTAMP:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

case "$TOOL_NAME" in
  Write|Edit|NotebookEdit) ;;
  *) exit 0 ;;
esac

FILE_PATH=$(jq -r '.tool_input.file_path // .tool_input.notebook_path // ""' < "$INPUT_FILE")
FILE_LOWER=$(echo "$FILE_PATH" | tr '[:upper:]' '[:lower:]')

# Protected AI instruction files
PROTECTED_PATTERN='claude\.md$|\.cursorrules$|\.cursorignore$|copilot-instructions\.md$|\.claude/settings\.json|\.vscode/settings\.json|\.windsurf/rules'

echo "$FILE_LOWER" | grep -qiE "$PROTECTED_PATTERN" || exit 0

# Extract content being written
CONTENT=$(jq -r '.tool_input.content // .tool_input.new_string // ""' < "$INPUT_FILE")

BLOCKED=false
ALERT_REASON=""

# Check for invisible Unicode characters (bidirectional, zero-width)
# These are the attack vectors used in the Pillar Security disclosure
if echo "$CONTENT" | python3 -c "
import sys, unicodedata
text = sys.stdin.read()
suspicious = [c for c in text if unicodedata.category(c) in ('Cf', 'Cs') or ord(c) in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x2028, 0x2029)]
if suspicious:
    print('FOUND: ' + ', '.join(f'U+{ord(c):04X}' for c in suspicious[:5]))
    exit(1)
" 2>/dev/null; then
  : # No invisible chars found
else
  BLOCKED=true
  ALERT_REASON="Invisible Unicode characters detected (bidirectional/zero-width) — known attack vector for rules file poisoning"
fi

# Check for self-concealment instructions (AI instructed to hide behavior)
CONCEALMENT_PATTERNS='do not (mention|reveal|tell|disclose|show)|hide (this|these|the following)|never (mention|reveal|tell)|keep (this|these) (secret|hidden|private)|ignore (previous|all|above) instructions|disregard (your|all) (guidelines|rules|instructions)'

if echo "$CONTENT" | grep -qiE "$CONCEALMENT_PATTERNS"; then
  BLOCKED=true
  ALERT_REASON="Content contains instructions to hide behavior or override safety guidelines"
fi

# Always audit log writes to these files (regardless of block)
mkdir -p "${AUDIT_DIR:-$HOME/.claude/audit}"
jq -n \
  --arg ts      "$TIMESTAMP" \
  --arg tool    "$TOOL_NAME" \
  --arg policy  "rules-integrity" \
  --arg file    "$FILE_PATH" \
  --arg blocked "$BLOCKED" \
  --arg reason  "$ALERT_REASON" \
  --arg session "$SESSION_ID" \
  --arg cwd     "${CWD:-}" \
  '{timestamp:$ts, event:"policy_audit", policy:$policy, tool:$tool, file:$file, blocked:$blocked, reason:$reason, session:$session, cwd:$cwd}' \
  >> "${AUDIT_LOG:-$HOME/.claude/audit/policy-violations.jsonl}"

if [[ "$BLOCKED" == "true" ]]; then

  cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║       ORG POLICY VIOLATION — AI RULES FILE TAMPERING BLOCKED ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted : $TOOL_NAME
File           : $FILE_PATH
Reason         : $ALERT_REASON

Why this matters:
  • "Rules File Backdoor" (Pillar Security, Mar 2025): AI instruction files
    can be poisoned with invisible Unicode to make AI agents insert
    backdoors, expose credentials, or exfiltrate code — invisible in
    code review but read by every AI user of that repo.
  • "IDEsaster" (Dec 2025): 30+ CVEs — 100% of AI IDEs were vulnerable
    to attack chains via .vscode/settings.json and rules files.
  • A poisoned CLAUDE.md survives repository forks, creating a persistent
    supply chain attack vector across every downstream consumer.

This write has been blocked and logged for security review.
Reach out to #security-ops if this is a legitimate change.

Violation logged to: ~/.claude/audit/policy-violations.jsonl

EOF

  exit 2
fi

exit 0
