#!/usr/bin/env bash
# =============================================================================
# Policy 11: WORKSPACE BOUNDARY PROTECTION
# =============================================================================
# Blocks AI agents from reading system files, OS credentials, and paths that
# lie outside the current project workspace — preventing lateral movement.
#
# Real incidents:
#   • 21,000 exposed AI agent instances (2025):
#     Security researchers found 21,000+ AI coding agent instances exposed
#     on the internet, many with unrestricted filesystem access. Agents had
#     read /etc/passwd, /etc/shadow, and system configuration files, which
#     were then surfaced in generated code or transmitted as "context."
#
#   • Anthropic AI-orchestrated espionage campaign (September 2025):
#     After establishing a foothold via prompt injection, adversaries directed
#     Claude Code to enumerate the filesystem: read /etc/hosts, /etc/passwd,
#     ~/.bash_history, ~/.zsh_history, .git/config (to extract remote URLs
#     and tokens), and crontab files — building a map for further exfiltration.
#
#   • IDEsaster CVEs (December 2025, 30+ CVEs):
#     CVE-2025-49150 (Cursor), CVE-2025-53097 (Roo Code), CVE-2025-58335
#     (JetBrains Junie): Path traversal vulnerabilities allowed reading files
#     outside the workspace root by using `../../` sequences in tool parameters.
#     All 30+ tested AI IDEs were vulnerable to some form of this attack.
#
#   • GitHub MCP Prompt Injection Data Heist (May 2025):
#     After injection via a GitHub issue, the agent read .git/config to extract
#     the remote URL and authentication token embedded in the git remote, then
#     exfiltrated private repo contents and committed backdoors via the same
#     credentials — all within the agent's normal file-access privileges.
#
# What this blocks:
#   • System user/password databases: /etc/passwd, /etc/shadow, /etc/sudoers
#   • Shell history files: ~/.bash_history, ~/.zsh_history, ~/.sh_history
#   • Cron and scheduled task definitions
#   • System SSH configuration: /etc/ssh/sshd_config, ssh_host_*
#   • Path traversal sequences: ../../ patterns in Read tool paths
#   • Reads of .git/config (often contains embedded auth tokens)
# =============================================================================

set -euo pipefail

INPUT_FILE="${HOOK_INPUT_FILE:-/dev/stdin}"
TOOL_NAME=$(jq -r '.tool_name // "unknown"' < "$INPUT_FILE")
SESSION_ID=$(jq -r '.session_id // "unknown"' < "$INPUT_FILE")
TIMESTAMP="${TIMESTAMP:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

case "$TOOL_NAME" in
  Read|Bash) ;;
  *) exit 0 ;;
esac

if [[ "$TOOL_NAME" == "Read" ]]; then
  TARGET=$(jq -r '.tool_input.file_path // ""' < "$INPUT_FILE")
else
  TARGET=$(jq -r '.tool_input.command // ""' < "$INPUT_FILE")
fi

[[ -z "$TARGET" ]] && exit 0

MATCHED=""
REASON=""

# ---- Pattern 1: OS system credential files ----
if echo "$TARGET" | grep -qiE '(/etc/(passwd|shadow|sudoers|master\.passwd|group)|/etc/security/)'; then
  MATCHED="OS user/credential database"
  REASON="$TARGET"
fi

# ---- Pattern 2: Shell history files (contain command history with credentials) ----
if [[ -z "$MATCHED" ]] && echo "$TARGET" | grep -qiE '~/?(\.bash_history|\.zsh_history|\.sh_history|\.history|\.fish/fish_history|\.node_repl_history)'; then
  MATCHED="Shell command history"
  REASON="$TARGET"
fi

# ---- Pattern 3: Crontab / scheduled tasks (common persistence location) ----
if [[ -z "$MATCHED" ]] && echo "$TARGET" | grep -qiE '(/etc/cron|/var/spool/cron|~/?(\.crontab))'; then
  MATCHED="Cron / scheduled task definition"
  REASON="$TARGET"
fi

# ---- Pattern 4: System SSH daemon config (private host keys) ----
if [[ -z "$MATCHED" ]] && echo "$TARGET" | grep -qiE '/etc/ssh/(sshd_config|ssh_host_(rsa|ed25519|ecdsa|dsa)_key)'; then
  MATCHED="SSH daemon configuration / host private key"
  REASON="$TARGET"
fi

# ---- Pattern 5: Path traversal sequences ----
# Catches ../../ in file paths, common in IDEsaster-class vulnerabilities
if [[ -z "$MATCHED" ]] && echo "$TARGET" | grep -qE '(\.\./){2,}'; then
  MATCHED="Path traversal sequence (../../)"
  REASON="$TARGET"
fi

# ---- Pattern 6: .git/config with embedded credentials ----
# .git/config can contain: https://user:token@github.com style remotes
if [[ -z "$MATCHED" ]] && echo "$TARGET" | grep -qiE '(^|[^a-z0-9])\.git/config\b'; then
  # Only flag if it looks like a read operation (not just mentioning it)
  if [[ "$TOOL_NAME" == "Read" ]] || echo "$TARGET" | grep -qiE '(cat|head|tail|less|more|open)\s+.*\.git/config'; then
    MATCHED=".git/config (may contain embedded auth tokens)"
    REASON="$TARGET"
  fi
fi

# ---- Pattern 7: /proc filesystem enumeration ----
if [[ -z "$MATCHED" ]] && echo "$TARGET" | grep -qiE '/proc/(self|[0-9]+)/(cmdline|environ|maps|mem|fd/)'; then
  MATCHED="Process filesystem read via /proc"
  REASON="$TARGET"
fi

[[ -z "$MATCHED" ]] && exit 0

# ---- Audit log ----
mkdir -p "${AUDIT_DIR:-$HOME/.claude/audit}"
jq -n \
  --arg ts      "$TIMESTAMP" \
  --arg tool    "$TOOL_NAME" \
  --arg policy  "workspace-boundary" \
  --arg matched "$MATCHED" \
  --arg target  "$(echo "$REASON" | head -c 200)" \
  --arg session "$SESSION_ID" \
  --arg cwd     "${CWD:-}" \
  '{timestamp:$ts, event:"policy_blocked", policy:$policy, tool:$tool, matched:$matched, target:$target, session:$session, cwd:$cwd}' \
  >> "${AUDIT_LOG:-$HOME/.claude/audit/policy-violations.jsonl}"

cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║     ORG POLICY VIOLATION — WORKSPACE BOUNDARY EXCEEDED       ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted : $TOOL_NAME
Matched        : $MATCHED
Target         : $(echo "$REASON" | head -c 120)

Why this matters:
  • IDEsaster (Dec 2025, 30+ CVEs): 100% of AI IDEs had path traversal
    vulnerabilities allowing reads outside the workspace root.
  • 21,000 AI agent instances exposed: many had read /etc/passwd and
    system files that appeared verbatim in generated output.
  • AI espionage campaign (Sep 2025): ~/.bash_history and .git/config
    were the primary lateral-movement files after initial foothold.
  • GitHub MCP heist (May 2025): .git/config tokens gave repo write
    access to plant backdoors after private repo exfiltration.

What to do instead:
  • Keep file operations within the project directory
  • Check git remote URLs with: git remote -v (not .git/config directly)
  • Shell history is irrelevant to coding tasks — do not read it
  • Use /etc/os-release for OS detection, not /etc/passwd

Violation logged to: ~/.claude/audit/policy-violations.jsonl

EOF

exit 2
