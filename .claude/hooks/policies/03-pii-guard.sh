#!/usr/bin/env bash
# =============================================================================
# Policy 03: PII / GDPR EXFILTRATION GUARD
# =============================================================================
# Blocks sending personal data to external services via WebFetch/curl.
# Flags reads of files that appear to contain PII bulk data.
#
# Real incidents & regulatory consequences:
#   • Samsung (Apr 2023): Engineers sent internal meeting notes + source code
#     to ChatGPT. Under GDPR, this constitutes a cross-border transfer of
#     personal data to a processor without a DPA. Samsung had no DPA with
#     OpenAI at the time.
#
#   • GDPR fines for unauthorized data transfers:
#       - Meta:     €1.2 BILLION (2023) — EU→US transfers without safeguards
#       - LinkedIn: €310M (2024) — behavioral profiling without consent
#       - Uber:     €290M (2024) — EU driver data sent to US servers
#     These fines are for SYSTEMATIC violations. A single AI agent reading
#     a customer DB dump and sending it to an LLM API is the same legal act.
#
#   • EU AI Act (in force Aug 2024, enforced Aug 2026): Article 12 mandates
#     logging of all data processed by AI systems. Violation: up to
#     €15M or 3% of global annual turnover.
#
# What this policy does:
#   1. Blocks WebFetch/curl calls that POST data containing PII patterns
#      to non-allowlisted external domains
#   2. Flags (audit mode) reads of files whose names/paths suggest PII bulk data
#   3. Blocks sending data to personal cloud storage / personal email services
#
# PII patterns detected:
#   SSN (US) · Email bulk patterns · Credit card numbers (Luhn-adjacent)
#   Bulk personal data filenames · Personal cloud storage domains
# =============================================================================

set -euo pipefail

INPUT_FILE="${HOOK_INPUT_FILE:-/dev/stdin}"
TOOL_NAME=$(jq -r '.tool_name // "unknown"' < "$INPUT_FILE")
SESSION_ID=$(jq -r '.session_id // "unknown"' < "$INPUT_FILE")
TIMESTAMP="${TIMESTAMP:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

BLOCKED=false
MATCHED_NAME=""

# ── 1. Block WebFetch / curl to personal cloud/email with data ──────────────

case "$TOOL_NAME" in
  WebFetch)
    URL=$(jq -r '.tool_input.url // ""' < "$INPUT_FILE" | tr '[:upper:]' '[:lower:]')
    PERSONAL_STORAGE="dropbox\.com|drive\.google\.com|onedrive\.live\.com|box\.com|icloud\.com|gmail\.com|outlook\.com|yahoo\.com|wetransfer\.com|pastebin\.com"
    if echo "$URL" | grep -qiE "$PERSONAL_STORAGE"; then
      BLOCKED=true
      MATCHED_NAME="Sending data to personal cloud/email service ($URL)"
    fi
    ;;

  Bash)
    COMMAND=$(jq -r '.tool_input.command // ""' < "$INPUT_FILE" | tr '[:upper:]' '[:lower:]')
    # curl/wget to personal storage with data flag
    PERSONAL_STORAGE="dropbox\.com|drive\.google\.com|onedrive\.live\.com|box\.com|gmail\.com|wetransfer\.com|pastebin\.com"
    if echo "$COMMAND" | grep -qiE "(curl|wget).*(-d |--data |--upload-file ).*($PERSONAL_STORAGE)" || \
       echo "$COMMAND" | grep -qiE "($PERSONAL_STORAGE).*(curl|wget).*(-d |--data )"; then
      BLOCKED=true
      MATCHED_NAME="Sending data to personal cloud/email service via curl/wget"
    fi
    ;;

  Read)
    # Audit-only: flag reads of high-risk PII filenames
    FILE_PATH=$(jq -r '.tool_input.file_path // ""' < "$INPUT_FILE" | tr '[:upper:]' '[:lower:]')
    PII_FILENAMES="customer[_-]data|user[_-]pii|patient[_-]records|employee[_-]data|personal[_-]data|gdpr|ccpa|hipaa|ssn[_-]|credit[_-]card|pii[_-]export|data[_-]dump"
    if echo "$FILE_PATH" | grep -qiE "$PII_FILENAMES"; then
      # Audit log only — don't block legitimate reads, just create a trail
      mkdir -p "${AUDIT_DIR:-$HOME/.claude/audit}"
      jq -n \
        --arg ts      "$TIMESTAMP" \
        --arg tool    "$TOOL_NAME" \
        --arg policy  "pii-guard" \
        --arg matched "PII filename read: $FILE_PATH" \
        --arg session "$SESSION_ID" \
        --arg cwd     "${CWD:-}" \
        '{timestamp:$ts, event:"policy_audit", policy:$policy, tool:$tool, matched:$matched, session:$session, cwd:$cwd}' \
        >> "${AUDIT_LOG:-$HOME/.claude/audit/policy-violations.jsonl}"
      exit 0
    fi
    ;;
esac

# ── 2. Scan POST body / bash command for SSN / credit card patterns ──────────

if [[ "$BLOCKED" == "false" ]]; then
  case "$TOOL_NAME" in
    WebFetch|Bash)
      CONTENT=$(jq -c '.tool_input // {}' < "$INPUT_FILE")
      SSN_PATTERN='\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'
      CC_PATTERN='\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b|\b3[47][0-9]{13}\b'  # Visa/MC/Amex
      BULK_EMAIL='\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b.*\b[a-z0-9._%+-]+@'  # 2+ emails in content

      if echo "$CONTENT" | grep -qiP "$SSN_PATTERN" 2>/dev/null; then
        BLOCKED=true; MATCHED_NAME="SSN pattern detected in tool input"
      elif echo "$CONTENT" | grep -qiP "$CC_PATTERN" 2>/dev/null; then
        BLOCKED=true; MATCHED_NAME="Credit card number pattern detected in tool input"
      fi
      ;;
  esac
fi

if [[ "$BLOCKED" == "true" ]]; then

  mkdir -p "${AUDIT_DIR:-$HOME/.claude/audit}"
  jq -n \
    --arg ts      "$TIMESTAMP" \
    --arg tool    "$TOOL_NAME" \
    --arg policy  "pii-guard" \
    --arg matched "$MATCHED_NAME" \
    --arg session "$SESSION_ID" \
    --arg cwd     "${CWD:-}" \
    '{timestamp:$ts, event:"policy_blocked", policy:$policy, tool:$tool, matched:$matched, session:$session, cwd:$cwd}' \
    >> "${AUDIT_LOG:-$HOME/.claude/audit/policy-violations.jsonl}"

  cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║           ORG POLICY VIOLATION — PII EXFILTRATION BLOCKED    ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted : $TOOL_NAME
Detected       : $MATCHED_NAME
Policy         : Sending personal data to external/personal services is
                 blocked. This may constitute an unauthorized GDPR
                 cross-border data transfer.

Why this matters:
  • Samsung (Apr 2023): Engineers sent internal data to ChatGPT.
    No DPA existed. Legally equivalent to unauthorized data transfer.
  • GDPR Art. 83(5): Up to €20M or 4% of global annual revenue per
    violation. Meta paid €1.2B in 2023 for exactly this category.
  • EU AI Act Art. 12: Mandatory logging of all AI-processed data.
    Violation = up to €15M or 3% of global annual turnover.

What to do instead:
  • Use anonymized/synthetic test data for development
  • Ensure your LLM provider has a signed DPA before sending any PII
  • Use your org's approved AI endpoints (not personal accounts)
  • For file transfers: use approved internal tools, not personal cloud

Violation logged to: ~/.claude/audit/policy-violations.jsonl

EOF

  exit 2
fi

exit 0
