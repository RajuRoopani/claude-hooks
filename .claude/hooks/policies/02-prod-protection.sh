#!/usr/bin/env bash
# =============================================================================
# Policy 02: PRODUCTION ENVIRONMENT PROTECTION
# =============================================================================
# Blocks destructive commands targeting production environments.
#
# Real incidents:
#   • Pinecone (March 2023): A cleanup script with a SQL bug deleted 515 user
#     database indexes in production. It was deployed via a lighter approval
#     path meant for UI changes only. One bug + wrong approval track = mass
#     irreversible data loss for 515 customers.
#
#   • Amazon Q Wiper Prompt (July 2025, CVSS critical): An attacker injected
#     instructions into the aws-toolkit-vscode extension causing the AI agent
#     to execute `aws ec2 terminate-instances` against authenticated AWS
#     environments. The attack ONLY failed due to a syntax error — no permission
#     boundary prevented the agent from calling the AWS termination API.
#
#   • Kubernetes Failure Stories (k8s.af): Documented incidents where automated
#     tooling caused $10K-$50K+ cloud bills from autoscaling, deleted persistent
#     volumes, and caused cluster-wide outages from cascading rollbacks.
#
# Why an AI agent is uniquely dangerous here:
#   • AI agents confidently execute commands to "solve the problem"
#   • They may not distinguish prod vs staging if context is ambiguous
#   • A single misunderstood instruction can be irreversible in seconds
#   • Unlike a human, the agent doesn't hesitate before running `DROP TABLE`
#
# Production indicators scanned: prod · production · prd · live · release
# Destructive operations blocked:
#   kubectl: delete · drain · taint · cordon (cluster impact)
#   AWS CLI: terminate-instances · delete-bucket · remove-policy
#   Azure CLI: az group delete · az resource delete
#   Terraform: apply (without workspace guard)
#   Database: DROP TABLE · DROP DATABASE · TRUNCATE (on prod DSN)
#   Git: force push to main/master/release
# =============================================================================

set -euo pipefail

INPUT_FILE="${HOOK_INPUT_FILE:-/dev/stdin}"
TOOL_NAME=$(jq -r '.tool_name // "unknown"' < "$INPUT_FILE")
SESSION_ID=$(jq -r '.session_id // "unknown"' < "$INPUT_FILE")
TIMESTAMP="${TIMESTAMP:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

# Only intercept Bash commands
[[ "$TOOL_NAME" == "Bash" ]] || exit 0

COMMAND=$(jq -r '.tool_input.command // ""' < "$INPUT_FILE" | tr '[:upper:]' '[:lower:]')

# Production environment indicators
PROD_INDICATOR_PATTERN="(\bprod(uction)?\b|[\-_\.]prd[\-_\.]|[\-_\.]prod[\-_\.]|live[\-_\.](env|db|cluster)|release[\-_\.]env)"

# Destructive command patterns
declare -a BLOCKED_NAMES=(
  "kubectl destructive op on prod"
  "AWS terminate/delete on prod"
  "Azure resource delete on prod"
  "Terraform apply on prod"
  "Database DROP/TRUNCATE on prod"
  "Git force push to protected branch"
)

declare -a BLOCKED_PATTERNS=(
  "kubectl\s+(delete|drain|taint|cordon|scale\s+--replicas=0)"
  "aws\s+(ec2\s+terminate-instances|s3\s+rb|s3api\s+delete-bucket|iam\s+delete|rds\s+delete|cloudformation\s+delete)"
  "az\s+(group\s+delete|resource\s+delete|vm\s+delete|sql\s+db\s+delete)"
  "terraform\s+apply(?!\s+--target)"
  "(drop\s+table|drop\s+database|truncate\s+table)"
  "git\s+push\s+.*(-f\b|--force\b).*(main|master|release|prod)"
)

BLOCKED=false
MATCHED_NAME=""

for i in "${!BLOCKED_NAMES[@]}"; do
  # For most patterns, also require a prod indicator in the same command
  pattern="${BLOCKED_PATTERNS[$i]}"
  name="${BLOCKED_NAMES[$i]}"

  if echo "$COMMAND" | grep -qiP "$pattern" 2>/dev/null || \
     echo "$COMMAND" | grep -qiE "$pattern" 2>/dev/null; then

    # For git force push and DB drops: always block (no prod check needed)
    # For cloud/infra: also require prod indicator
    case "$i" in
      4|5) # DB DROP and git force push — always block regardless of env
        BLOCKED=true; MATCHED_NAME="$name"; break ;;
      *)   # Cloud/infra — require prod context
        if echo "$COMMAND" | grep -qiE "$PROD_INDICATOR_PATTERN"; then
          BLOCKED=true; MATCHED_NAME="$name"; break
        fi ;;
    esac
  fi
done

if [[ "$BLOCKED" == "true" ]]; then

  mkdir -p "${AUDIT_DIR:-$HOME/.claude/audit}"
  jq -n \
    --arg ts      "$TIMESTAMP" \
    --arg tool    "$TOOL_NAME" \
    --arg policy  "prod-protection" \
    --arg matched "$MATCHED_NAME" \
    --arg session "$SESSION_ID" \
    --arg cwd     "${CWD:-}" \
    '{timestamp:$ts, event:"policy_blocked", policy:$policy, tool:$tool, matched:$matched, session:$session, cwd:$cwd}' \
    >> "${AUDIT_LOG:-$HOME/.claude/audit/policy-violations.jsonl}"

  cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║         ORG POLICY VIOLATION — PROD COMMAND BLOCKED          ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted  : $TOOL_NAME
Blocked op      : $MATCHED_NAME
Policy          : Destructive commands targeting production environments
                  require human approval via your org's change management
                  process — they cannot be executed by an AI agent.

Why this matters:
  • Pinecone (Mar 2023): SQL bug in a cleanup script → 515 prod indexes
    permanently deleted. Auto-approved via wrong pipeline track.
  • Amazon Q (Jul 2025): Injected prompt → AI tried to run
    'aws ec2 terminate-instances' on live AWS infra. Nearly succeeded.
  • One AI-executed DROP TABLE on prod = customer data loss, PagerDuty
    all-hands, postmortem, potential SLA breach, reputational damage.

What to do instead:
  • Run this against your staging environment first
  • Use your org's change management / approval workflow for prod changes
  • Get explicit approval in your deployment ticket
  • Use --dry-run / plan / preview modes first

Violation logged to: ~/.claude/audit/policy-violations.jsonl

EOF

  exit 2
fi

exit 0
