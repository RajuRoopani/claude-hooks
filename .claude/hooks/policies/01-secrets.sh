#!/usr/bin/env bash
# =============================================================================
# Policy 01: SECRETS GUARD
# =============================================================================
# Blocks writing or committing known secret formats to files.
#
# Real incident: Samsung (April 2023) — 3 engineers pasted proprietary source
# code, chip-testing logic, and internal meeting notes into ChatGPT within one
# month. OpenAI's terms state inputs are used for model training — the secrets
# are now permanently in a third-party corpus.
#
# GitGuardian 2025: 23.8M new hardcoded secrets detected on GitHub in 2024
# alone (+25% YoY). Repositories using AI coding assistants have a 6.4% secret
# exposure rate vs 4.6% for all repos — a 40% HIGHER rate with AI assistance.
#
# Why this matters:
#   • An AI agent reading your project files will attach secrets as context
#   • An AI agent generating scaffolding code reproduces patterns it has seen
#   • git commit history is forever — rotating a key is insufficient if it
#     was ever pushed to a remote
#
# Blocked patterns (regex, case-insensitive):
#   Anthropic · OpenAI · GitHub · AWS · Google · Slack · Private Keys · JWT
# =============================================================================

set -euo pipefail

INPUT_FILE="${HOOK_INPUT_FILE:-/dev/stdin}"

TOOL_NAME=$(jq -r '.tool_name // "unknown"' < "$INPUT_FILE")
SESSION_ID=$(jq -r '.session_id // "unknown"' < "$INPUT_FILE")
TIMESTAMP="${TIMESTAMP:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

# Only scan writes/edits and bash commands that write to files
case "$TOOL_NAME" in
  Write|Edit|NotebookEdit|Bash) ;;
  *) exit 0 ;;
esac

# Extract tool input as a single lowercase string for scanning
TOOL_INPUT_STR=$(jq -c '.tool_input // {}' < "$INPUT_FILE" | tr '[:upper:]' '[:lower:]')

# Secret patterns — ERE format
declare -a SECRET_NAMES=(
  "Anthropic API Key"
  "OpenAI API Key"
  "GitHub Personal Access Token"
  "GitHub OAuth Token"
  "AWS Access Key ID"
  "AWS Secret Key (long pattern)"
  "Google API Key"
  "Slack Bot/User Token"
  "Private Key (PEM)"
  "Generic Bearer Token in code"
  "Generic password= assignment"
)

declare -a SECRET_PATTERNS=(
  "sk-ant-[a-z0-9_-]{10,}"
  "sk-[a-z0-9_-]{40,}"
  "ghp_[a-z0-9]{36}"
  "gho_[a-z0-9]{36}|ghs_[a-z0-9]{36}|github_pat_[a-z0-9_]{82}"
  "akia[a-z0-9]{16}"
  "(['\"])[a-z0-9/+]{40}\\1"
  "aiza[a-z0-9_-]{35}"
  "xoxb-[0-9a-z-]{50,}|xoxp-[0-9a-z-]{50,}"
  "-----begin (rsa |ec |openssh )?private key"
  "bearer [a-z0-9_\\.\\-]{30,}"
  "password\\s*=\\s*['\"][^'\"]{8,}"
)

BLOCKED=false
MATCHED_NAME=""

for i in "${!SECRET_NAMES[@]}"; do
  if echo "$TOOL_INPUT_STR" | grep -qiE "${SECRET_PATTERNS[$i]}"; then
    BLOCKED=true
    MATCHED_NAME="${SECRET_NAMES[$i]}"
    break
  fi
done

if [[ "$BLOCKED" == "true" ]]; then

  mkdir -p "${AUDIT_DIR:-$HOME/.claude/audit}"
  jq -n \
    --arg ts      "$TIMESTAMP" \
    --arg tool    "$TOOL_NAME" \
    --arg policy  "secrets" \
    --arg matched "$MATCHED_NAME" \
    --arg session "$SESSION_ID" \
    --arg cwd     "${CWD:-}" \
    '{timestamp:$ts, event:"policy_blocked", policy:$policy, tool:$tool, matched:$matched, session:$session, cwd:$cwd}' \
    >> "${AUDIT_LOG:-$HOME/.claude/audit/policy-violations.jsonl}"

  cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║            ORG POLICY VIOLATION — SECRET DETECTED            ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted : $TOOL_NAME
Secret type    : $MATCHED_NAME
Policy         : Writing secrets/credentials to files is blocked org-wide.

Why this matters:
  • Samsung (Apr 2023): 3 engineers pasted secrets into ChatGPT within
    one month. Those inputs are now in OpenAI's training corpus.
  • GitHub 2024: 39M secrets leaked in public repos. AI-assisted repos
    have 40% HIGHER secret exposure rate than non-AI repos.
  • Rotated keys are not enough — git history is permanent.

What to do instead:
  • Use environment variables: export MY_KEY=\$(op read "op://vault/key")
  • Use your secret manager: Azure Key Vault, AWS Secrets Manager, 1Password
  • Reference secrets in code: process.env.MY_KEY or os.environ['MY_KEY']
  • For .env files: ensure .env is in .gitignore BEFORE writing

Violation logged to: ~/.claude/audit/policy-violations.jsonl

EOF

  exit 2
fi

exit 0
