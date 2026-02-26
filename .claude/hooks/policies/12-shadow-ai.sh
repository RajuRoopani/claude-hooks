#!/usr/bin/env bash
# =============================================================================
# Policy 12: SHADOW AI / LLMJACKING DETECTION
# =============================================================================
# Detects and blocks unauthorized AI API calls made from within agent-executed
# code — a technique called "LLMjacking" where attackers steal AI compute.
#
# Real incidents:
#   • Postmark-MCP malicious server (September 2025):
#     The first confirmed malicious MCP server in the wild (v1.0.16+). The
#     server intercepted every email sent through the Postmark integration and
#     relayed them to an attacker-controlled API endpoint while also forwarding
#     the requests to OpenAI's API using credentials stolen from the developer's
#     environment. 1,643 downloads before removal. The attacker was running
#     LLM inference for free using stolen API keys.
#
#   • Smithery supply chain attack (October 2025):
#     3,000+ hosted MCP apps were compromised. The attack injected code that
#     extracted ANTHROPIC_API_KEY, OPENAI_API_KEY, and TOGETHER_AI_KEY from
#     the environment and used them to make API calls to multiple competing
#     LLM providers — a large-scale LLMjacking operation.
#
#   • LLMjacking trend (2024-2025, Sysdig Threat Research):
#     Attackers increasingly compromise developer machines specifically to
#     steal LLM API keys. A single Claude Opus API key can cost $75/million
#     output tokens. A stolen key running inference for a week = thousands
#     of dollars in unauthorized charges before detection. LLMjacking attacks
#     increased 400% between Q1 2024 and Q1 2025 per Sysdig research.
#
# What this detects:
#   • Calls to competing/unapproved AI providers from within agent code
#   • Requests to non-standard AI endpoints (often data exfiltration)
#   • Agent code making nested AI API calls (recursive cost explosion)
#   • Known LLMjacking infrastructure patterns
# =============================================================================

set -euo pipefail

INPUT_FILE="${HOOK_INPUT_FILE:-/dev/stdin}"
TOOL_NAME=$(jq -r '.tool_name // "unknown"' < "$INPUT_FILE")
SESSION_ID=$(jq -r '.session_id // "unknown"' < "$INPUT_FILE")
TIMESTAMP="${TIMESTAMP:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

[[ "$TOOL_NAME" == "Bash" ]] || exit 0

COMMAND=$(jq -r '.tool_input.command // ""' < "$INPUT_FILE")
[[ -z "$COMMAND" ]] && exit 0

MATCHED=""
REASON=""

# ---- Pattern 1: Competing AI providers (unapproved LLM inference) ----
# These are real API endpoints used in LLMjacking attacks
# Note: We do NOT block api.anthropic.com here — that's the legitimate provider.
# We flag all others as shadow/unapproved AI usage.
SHADOW_AI_PATTERN='(api\.openai\.com|api\.together\.ai|api\.cohere\.ai|api\.mistral\.ai|api\.perplexity\.ai|generativelanguage\.googleapis\.com|api\.groq\.com|api\.fireworks\.ai|api\.replicate\.com|api\.deepinfra\.com|openrouter\.ai/api|api\.ai21\.com|api\.huggingface\.co/models|claude\.ai/api|bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com)'

if echo "$COMMAND" | grep -qiE "(curl|wget|fetch|http|requests\.get|requests\.post|axios|fetch\().*(${SHADOW_AI_PATTERN})"; then
  MATCHED="Unapproved AI provider API call"
  REASON="$COMMAND"
fi

# ---- Pattern 2: Generic /v1/chat/completions or /v1/messages endpoint ----
# This pattern matches OpenAI-compatible endpoints — often used by local proxies
# or attacker-controlled servers masquerading as legitimate AI APIs
if [[ -z "$MATCHED" ]] && echo "$COMMAND" | grep -qiE '/(v1/chat/completions|v1/messages|v1/generate|api/generate)\b'; then
  # Only flag if there's also a network call involved
  if echo "$COMMAND" | grep -qiE '(curl|wget|fetch|http|requests|axios)'; then
    MATCHED="AI chat completions endpoint call"
    REASON="$COMMAND"
  fi
fi

# ---- Pattern 3: API key for AI services being used directly ----
# Catches agent code using hardcoded/env-expanded keys for AI calls
if [[ -z "$MATCHED" ]] && echo "$COMMAND" | grep -qiE '(sk-[a-z0-9_-]{20,}|AIza[a-z0-9_-]{35})\b'; then
  if echo "$COMMAND" | grep -qiE '(curl|wget|authorization|bearer)'; then
    MATCHED="AI API key used in direct HTTP call"
    REASON="$COMMAND"
  fi
fi

[[ -z "$MATCHED" ]] && exit 0

# ---- Determine severity — is this in agent-written code or the agent itself? ----
# We always audit; we block if it looks like the agent is making the call directly

# ---- Audit log ----
mkdir -p "${AUDIT_DIR:-$HOME/.claude/audit}"
jq -n \
  --arg ts      "$TIMESTAMP" \
  --arg tool    "$TOOL_NAME" \
  --arg policy  "shadow-ai" \
  --arg matched "$MATCHED" \
  --arg cmd     "$(echo "$COMMAND" | head -c 200)" \
  --arg session "$SESSION_ID" \
  --arg cwd     "${CWD:-}" \
  '{timestamp:$ts, event:"policy_blocked", policy:$policy, tool:$tool, matched:$matched, cmd:$cmd, session:$session, cwd:$cwd}' \
  >> "${AUDIT_LOG:-$HOME/.claude/audit/policy-violations.jsonl}"

cat >&2 <<EOF

╔══════════════════════════════════════════════════════════════╗
║      ORG POLICY VIOLATION — UNAUTHORIZED AI API CALL BLOCKED ║
╚══════════════════════════════════════════════════════════════╝

Tool attempted : $TOOL_NAME
Matched        : $MATCHED
Command        : $(echo "$COMMAND" | head -c 120)

Why this matters:
  • LLMjacking (2024-2025): Attackers steal AI API keys and use them
    to run inference for free. Cost: thousands of dollars/week per
    stolen key. LLMjacking attacks +400% between Q1 2024-Q1 2025.
  • Postmark-MCP (Sep 2025): First malicious MCP server extracted
    OpenAI keys from developer env and used them for LLMjacking
    while proxying legitimate requests. 1,643 downloads affected.
  • Smithery attack (Oct 2025): 3,000+ MCP apps compromised to extract
    ANTHROPIC_API_KEY, OPENAI_API_KEY, TOGETHER_AI_KEY for free AI use.
  • Nested AI calls from within agent code can create recursive cost
    explosions — agent calls LLM which triggers another agent...

What to do instead:
  • AI API calls in your application code are fine — but run them
    outside the agent session or use the agent's built-in capabilities
  • If you need to test an AI integration: use curl manually, not
    via the agent
  • Verify MCP servers before installing: check source, stars, maintainer

Violation logged to: ~/.claude/audit/policy-violations.jsonl

EOF

exit 2
