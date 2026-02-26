#!/usr/bin/env bash
# =============================================================================
# Policy 04: SUPPLY CHAIN GUARD
# =============================================================================
# Blocks or audits package installations that could introduce malicious code.
#
# Real incidents:
#   • XZ Utils backdoor (CVE-2024-3094, CVSS 10.0, March 2024):
#     A 2+ year social engineering campaign compromised a widely used Linux
#     compression library. The backdoor provided pre-authentication RCE on
#     any SSH-enabled system with the affected versions installed. An AI agent
#     running `apt-get upgrade` during the 5-day exposure window would have
#     silently introduced a root-level backdoor into the build environment.
#
#   • Ultralytics PyPI attack (December 2024):
#     One of the most-used AI/ML Python packages (YOLO) was compromised via
#     a GitHub Actions workflow exploit. Versions 8.3.41-8.3.46 contained an
#     XMRig cryptominer. Live for 1-12 hours before removal. AI coding agents
#     operating in ML environments would have auto-installed these versions.
#
#   • Slopsquatting (2023-present):
#     19.7% of AI-generated package references are hallucinated names.
#     43% of hallucinated names are consistent across 10+ separate queries.
#     20-35% of hallucinated npm/PyPI names have ALREADY been registered by
#     threat actors with malicious payloads. Every AI-suggested `pip install
#     <unknown-package>` is a potential supply chain attack entry point.
#
# What this policy does:
#   MODE: audit (default) — logs all package installs without blocking
#   MODE: block — requires packages to be in .claude/package-allowlist.txt
#
# To use block mode: set "supply-chain": {"mode": "block"} in policy-config.json
# To allowlist a package: add it (one per line) to .claude/package-allowlist.txt
# =============================================================================

set -euo pipefail

INPUT_FILE="${HOOK_INPUT_FILE:-/dev/stdin}"
TOOL_NAME=$(jq -r '.tool_name // "unknown"' < "$INPUT_FILE")
SESSION_ID=$(jq -r '.session_id // "unknown"' < "$INPUT_FILE")
TIMESTAMP="${TIMESTAMP:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

[[ "$TOOL_NAME" == "Bash" ]] || exit 0

COMMAND=$(jq -r '.tool_input.command // ""' < "$INPUT_FILE")

# Package manager patterns
INSTALL_PATTERN='(npm\s+(install|i)|yarn\s+add|pnpm\s+add|pip\s+(install|3\s+install)|pip3\s+install|poetry\s+add|cargo\s+add|go\s+get|gem\s+install|apt(-get)?\s+install|brew\s+install)'

echo "$COMMAND" | grep -qiE "$INSTALL_PATTERN" || exit 0

# Extract package names (best-effort)
PACKAGES=$(echo "$COMMAND" | grep -oiP '(npm\s+(?:install|i)|pip3?\s+install|yarn\s+add|pnpm\s+add|cargo\s+add|gem\s+install)\s+\K[a-z0-9@/_.\-]+(?:\s+[a-z0-9@/_.\-]+)*' 2>/dev/null || echo "")

# Check for known malicious patterns in package names (slopsquatting + typosquatting)
SUSPICIOUS_PATTERN='nmp-|nod3-|r3act|reakt|djnago|expres[sz]|mongose|monggoose|axios2|lodsh|moment2|webpack2|babel2|eslnt'

SUSPICIOUS=false
# Scan both extracted packages and the raw command (grep -P unavailable on macOS)
if echo "${PACKAGES:-$COMMAND}" | grep -qiE "$SUSPICIOUS_PATTERN"; then
  SUSPICIOUS=true
fi

# Check allowlist if in block mode (the orchestrator handles mode, so we exit 2 and let it decide)
ALLOWLIST_FILE="${CWD:-$PWD}/.claude/package-allowlist.txt"
ALLOWLIST_USED=false
BLOCKED_PKG=""

if [[ -f "$ALLOWLIST_FILE" ]] && [[ -n "$PACKAGES" ]]; then
  for pkg in $PACKAGES; do
    # Strip version specifiers
    pkg_name=$(echo "$pkg" | sed 's/@[0-9].*//' | sed 's/==.*//' | sed 's/>=.*//')
    if ! grep -qiF "$pkg_name" "$ALLOWLIST_FILE"; then
      ALLOWLIST_USED=true
      BLOCKED_PKG="$pkg_name"
      break
    fi
  done
fi

# Audit log all package installs (supply chain requires visibility)
mkdir -p "${AUDIT_DIR:-$HOME/.claude/audit}"
jq -n \
  --arg ts       "$TIMESTAMP" \
  --arg tool     "$TOOL_NAME" \
  --arg policy   "supply-chain" \
  --arg packages "${PACKAGES:-unknown}" \
  --arg session  "$SESSION_ID" \
  --arg cwd      "${CWD:-}" \
  --arg suspicious "$SUSPICIOUS" \
  '{timestamp:$ts, event:"policy_audit", policy:$policy, tool:$tool, packages:$packages, session:$session, cwd:$cwd, suspicious_name:$suspicious}' \
  >> "${AUDIT_LOG:-$HOME/.claude/audit/policy-violations.jsonl}"

# Hard block if: suspicious typosquat name detected
if [[ "$SUSPICIOUS" == "true" ]]; then

  cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║        ORG POLICY VIOLATION — SUSPICIOUS PACKAGE BLOCKED     ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted : $TOOL_NAME
Packages       : $PACKAGES
Reason         : Package name matches known typosquatting patterns

Why this matters:
  • "Slopsquatting": 19.7% of AI-suggested packages are hallucinated.
    43% of these hallucinated names are consistent — threat actors
    pre-register them on PyPI/npm with malicious payloads.
  • Ultralytics (Dec 2024): Popular AI/ML package compromised via CI/CD.
    Cryptominer deployed in AI dev environments for up to 12 hours.
  • XZ Utils (2024, CVSS 10.0): 2-year social engineering campaign
    introduced pre-auth RCE backdoor into a core Linux library.

What to do instead:
  • Verify the exact package name at pypi.org or npmjs.com
  • Check the package's GitHub: stars, maintainers, recent commits
  • Add verified packages to .claude/package-allowlist.txt
  • Use package lock files and hash pinning

Violation logged to: ~/.claude/audit/policy-violations.jsonl

EOF
  exit 2
fi

# Exit 2 if allowlist is in use and package isn't listed (block mode via orchestrator)
if [[ "$ALLOWLIST_USED" == "true" ]]; then
  cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║       ORG POLICY VIOLATION — PACKAGE NOT ON ALLOWLIST        ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted : $TOOL_NAME
Package        : $BLOCKED_PKG (not in .claude/package-allowlist.txt)
Policy         : Your project uses a package allowlist. Only approved
                 packages can be installed by AI agents.

To approve this package:
  echo "$BLOCKED_PKG" >> .claude/package-allowlist.txt
  # Then review: is it a real package? Is it the right name?

EOF
  exit 2
fi

exit 0
