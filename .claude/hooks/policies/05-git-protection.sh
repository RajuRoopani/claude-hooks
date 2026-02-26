#!/usr/bin/env bash
# =============================================================================
# Policy 05: GIT BRANCH PROTECTION
# =============================================================================
# Blocks force pushes and direct commits to protected branches.
#
# Why AI agents + unprotected git = high risk:
#   • An AI agent "cleaning up" a feature branch may rewrite shared history
#   • An AI resolving a merge conflict might force-push, overwriting teammates'
#     commits — with no warning and no undo
#   • `git reset --hard` is frequently used by AI agents to "start clean"
#     but deletes untracked local work without recovery
#   • `git checkout .` discards ALL local modifications silently
#
# Real impact:
#   • A force push to `main` can destroy release-tagged commits, invalidate
#     signed commits, and break every collaborator's local clone
#   • CI/CD pipelines may auto-deploy whatever is on main — a force push
#     can trigger an unreviewed deployment to production
#   • In orgs using GitOps, `main` IS production. Force push = prod push.
#
# What this blocks:
#   • git push --force / git push -f to main, master, release, develop
#   • git push origin main (direct push without PR)
#   • git reset --hard (destructive, no undo)
#   • git checkout . (discards ALL local changes)
#   • git clean -fd (deletes untracked files permanently)
# =============================================================================

set -euo pipefail

INPUT_FILE="${HOOK_INPUT_FILE:-/dev/stdin}"
TOOL_NAME=$(jq -r '.tool_name // "unknown"' < "$INPUT_FILE")
SESSION_ID=$(jq -r '.session_id // "unknown"' < "$INPUT_FILE")
TIMESTAMP="${TIMESTAMP:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

[[ "$TOOL_NAME" == "Bash" ]] || exit 0

COMMAND=$(jq -r '.tool_input.command // ""' < "$INPUT_FILE")
CMD_LOWER=$(echo "$COMMAND" | tr '[:upper:]' '[:lower:]')

BLOCKED=false
MATCHED_NAME=""

# Rule 1: Force push to any branch
if echo "$CMD_LOWER" | grep -qiE 'git\s+push\s+.*(-f\b|--force\b)'; then
  BLOCKED=true
  MATCHED_NAME="Force push (git push --force)"

# Rule 2: Direct push to protected branches (without PR)
elif echo "$CMD_LOWER" | grep -qiE 'git\s+push\s+(origin\s+)?(main|master|develop|release|staging)(\s|$)'; then
  BLOCKED=true
  MATCHED_NAME="Direct push to protected branch (bypasses PR review)"

# Rule 3: Hard reset (highly destructive)
elif echo "$CMD_LOWER" | grep -qiE 'git\s+reset\s+--hard'; then
  BLOCKED=true
  MATCHED_NAME="git reset --hard (destroys uncommitted work, no undo)"

# Rule 4: Discard all local changes
elif echo "$CMD_LOWER" | grep -qiE 'git\s+checkout\s+\.($|\s)'; then
  BLOCKED=true
  MATCHED_NAME="git checkout . (discards all local modifications)"

# Rule 5: Delete untracked files
elif echo "$CMD_LOWER" | grep -qiE 'git\s+clean\s+(-[a-z]*f[a-z]*d?|--force)'; then
  BLOCKED=true
  MATCHED_NAME="git clean -fd (permanently deletes untracked files)"
fi

if [[ "$BLOCKED" == "true" ]]; then

  mkdir -p "${AUDIT_DIR:-$HOME/.claude/audit}"
  jq -n \
    --arg ts      "$TIMESTAMP" \
    --arg tool    "$TOOL_NAME" \
    --arg policy  "git-protection" \
    --arg matched "$MATCHED_NAME" \
    --arg session "$SESSION_ID" \
    --arg cwd     "${CWD:-}" \
    '{timestamp:$ts, event:"policy_blocked", policy:$policy, tool:$tool, matched:$matched, session:$session, cwd:$cwd}' \
    >> "${AUDIT_LOG:-$HOME/.claude/audit/policy-violations.jsonl}"

  cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║         ORG POLICY VIOLATION — DESTRUCTIVE GIT OP BLOCKED    ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted : $TOOL_NAME
Blocked op     : $MATCHED_NAME
Command        : $(echo "$COMMAND" | head -1)

Why this matters:
  • Force pushes to protected branches destroy git history for all
    collaborators and can trigger unreviewed production deployments
    in GitOps-based pipelines.
  • git reset --hard and git checkout . discard local work with no undo.
    An AI agent using these to "clean up" silently deletes your work.
  • In GitOps orgs, main IS production. Force push = prod change.

What to do instead:
  • Create a feature branch and open a PR for review
  • Use 'git stash' to temporarily set aside local changes (reversible)
  • Use 'git revert <sha>' instead of reset --hard (creates a new commit)
  • If you genuinely need force push: do it manually with explicit intent

Violation logged to: ~/.claude/audit/policy-violations.jsonl

EOF

  exit 2
fi

exit 0
