# claude-hooks

> Org-wide security guardrails for Claude Code — 8 policies backed by real incidents, deployed in one command.

AI coding agents are powerful. They read your files, execute commands, install packages, and push code. Without guardrails, they are also the fastest path to a production outage, a GDPR violation, or a $47,000 API bill from a runaway loop.

This repo gives every engineer in your org the same baseline of protection — wired into Claude Code's `PreToolUse` hook so it fires before every tool call, automatically.

---

## The 8 Policies

### 01 · Secrets Guard
**Blocks writing API keys, tokens, and credentials to files.**

> Samsung (April 2023): Three engineers pasted proprietary source code, chip-testing logic, and internal meeting notes into ChatGPT within a single month. OpenAI's terms state inputs may be used for training — the secrets are permanently in a third-party corpus. Samsung banned all generative AI tools company-wide.
>
> GitGuardian 2025: 23.8M new hardcoded secrets on public GitHub in 2024 alone (+25% YoY). Repos using AI coding assistants have a **40% higher** secret exposure rate.

Detects: `sk-ant-` (Anthropic) · `AKIA` (AWS) · `ghp_` (GitHub PAT) · `AIza` (Google) · `xoxb-` (Slack) · `BEGIN PRIVATE KEY` · `password=` assignments

---

### 02 · Production Protection
**Blocks destructive commands targeting production environments.**

> Pinecone (March 2023): A cleanup script deleted **515 production database indexes** via a SQL bug. Wrong approval track + one logic error = mass irreversible customer data loss.
>
> Amazon Q Wiper (July 2025): An attacker injected a prompt into `aws-toolkit-vscode` instructing the AI to run `aws ec2 terminate-instances`. The attack **only failed due to a syntax error** — no permission boundary stopped the agent.

Blocks: `kubectl delete/drain` on prod · `aws ec2 terminate-instances` · `DROP TABLE/DATABASE` · `TRUNCATE` · `terraform apply` on prod workspaces

---

### 03 · PII / GDPR Guard
**Blocks sending personal data to personal cloud storage or external services.**

> GDPR enforcement is active. Meta paid **€1.2 billion** in 2023 for unauthorized EU→US data transfers. LinkedIn paid **€310M** in 2024. Uber paid **€290M** in 2024. When an AI agent reads customer records and sends them to an LLM API without a DPA, that is the same legal act. Penalty: up to **€20M or 4% of global annual revenue**.

Blocks: Sends to Dropbox/Google Drive/OneDrive/personal email · SSN patterns · Credit card patterns in outbound data

---

### 04 · Supply Chain Guard
**Blocks known typosquatted/hallucinated package names. Audits all installs.**

> XZ Utils backdoor (CVE-2024-3094, CVSS 10.0, March 2024): A 2+ year social engineering attack put pre-auth RCE in a core Linux library. An AI agent running `apt-get upgrade` during the exposure window would have silently introduced a root-level backdoor.
>
> Slopsquatting: **19.7% of AI-generated package references are hallucinated names**. 43% are consistent across queries. **20-35% have already been registered by threat actors** on PyPI/npm.

Blocks: Known typosquat patterns · Packages not in `.claude/package-allowlist.txt` · Audits all installs

---

### 05 · Git Branch Protection
**Blocks force pushes and direct commits to protected branches.**

> In GitOps orgs, `main` IS production. A force push is a production deployment. An AI agent "cleaning up" history that accidentally force-pushes to `main` can trigger an unreviewed deployment, destroy release tags, and break every collaborator's clone — in seconds, with no undo.

Blocks: `git push --force` · Direct push to `main/master/release` · `git reset --hard` · `git checkout .` · `git clean -fd`

---

### 06 · Restricted Data Sources
**Blocks AI agent access to internal telemetry and incident management systems.**

Default blocked: ICM Dashboard · Kusto/ADX · Geneva Metrics · Restricted SharePoint

Add your own data source in 2 lines — extend `POLICY_NAMES` and `POLICY_PATTERNS` in `policies/06-data-sources.sh`.

---

### 07 · AI Rules File Integrity (Anti-Poisoning)
**Audits writes to AI instruction files. Blocks invisible Unicode character attacks.**

> "Rules File Backdoor" (Pillar Security, March 2025): AI instruction files can be poisoned with **invisible Unicode characters** that are invisible in code review but executed by the AI. A poisoned `CLAUDE.md` instructs the AI to insert backdoors and exfiltrate source code — silently, for every developer on the repo. The file survives forks: persistent supply chain attack.
>
> "IDEsaster" (Dec 2025): **30+ CVEs — 100% of tested AI IDEs vulnerable** including Cursor, Windsurf, GitHub Copilot, JetBrains, Cline.

Audits: `CLAUDE.md` · `.cursorrules` · `.github/copilot-instructions.md` · `.claude/settings.json` · `.vscode/settings.json`
Blocks: Invisible Unicode characters · Instructions to conceal behavior

---

### 08 · Cost Circuit Breaker
**Blocks runaway agent loops before they become $47,000 API bills.**

> Documented incident (2025): Two AI agents looped for **11 days** — **$47,000** in API fees before detection. AutoGPT (2023): users regularly received $100–$500 unexpected bills from recursive planning loops in a single session.

Blocks: Same Bash command running 5+ times in one session · Audits all LLM API calls from within agent code

---

## Architecture

```
.claude/
├── hooks/
│   ├── pre-tool.sh           ← orchestrator (wired in settings.json)
│   └── policies/
│       ├── 01-secrets.sh
│       ├── 02-prod-protection.sh
│       ├── 03-pii-guard.sh
│       ├── 04-supply-chain.sh
│       ├── 05-git-protection.sh
│       ├── 06-data-sources.sh
│       ├── 07-rules-integrity.sh
│       └── 08-cost-circuit-breaker.sh
├── policy-config.json        ← enable/disable/mode per policy
└── settings.json             ← wires pre-tool.sh to PreToolUse
```

Each policy is independent, testable, and readable. Adding a policy = dropping one `.sh` file.

---

## Install

```bash
git clone https://github.com/RajuRoopani/claude-hooks
cd claude-hooks
./install.sh           # current project only
./install.sh --global  # all Claude Code sessions on this machine
```

### Org-wide deployment (MDM / managed settings)

| Platform | Managed settings path |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |
| Linux | `/etc/claude-code/managed-settings.json` |

Engineers cannot override managed settings. Wire it once, enforce everywhere.

---

## Configure

Edit `.claude/policy-config.json`:

```json
{
  "policies": {
    "secrets":              { "enabled": true, "mode": "block" },
    "prod-protection":      { "enabled": true, "mode": "block" },
    "pii-guard":            { "enabled": true, "mode": "block" },
    "supply-chain":         { "enabled": true, "mode": "audit" },
    "git-protection":       { "enabled": true, "mode": "block" },
    "data-sources":         { "enabled": true, "mode": "block" },
    "rules-integrity":      { "enabled": true, "mode": "audit" },
    "cost-circuit-breaker": { "enabled": true, "mode": "block" }
  }
}
```

`"mode": "audit"` — logs the violation but does NOT block. Use for gradual rollout.
`"mode": "block"` — hard stop. Claude sees this as a policy violation and stops.

---

## Audit Log

All violations logged to `~/.claude/audit/policy-violations.jsonl`:

```json
{"timestamp":"2026-01-15T09:32:11Z","event":"policy_blocked","policy":"secrets","tool":"Write","matched":"Anthropic API Key","session":"abc123","cwd":"/project"}
{"timestamp":"2026-01-15T09:45:03Z","event":"policy_blocked","policy":"prod-protection","tool":"Bash","matched":"kubectl destructive op on prod","session":"abc123","cwd":"/project"}
```

```bash
# Most common violations this month
jq -r '.policy' ~/.claude/audit/policy-violations.jsonl | sort | uniq -c | sort -rn

# All supply chain installs (audit trail)
jq 'select(.policy == "supply-chain")' ~/.claude/audit/policy-violations.jsonl
```

---

## The Risk Matrix

| Risk | Real Incident | Consequence |
|---|---|---|
| Secret exfiltration | Samsung → ChatGPT (3 incidents in 1 month) | IP in LLM training corpus — permanent |
| Credential exposure | Microsoft 38TB SAS token (2yr window) | 30K Teams messages, private keys exposed |
| AI-assisted secret leaks | GitGuardian 2025 | 40% higher rate in AI-assisted repos |
| Supply chain — backdoor | XZ Utils CVSS 10.0 (2024) | Pre-auth RCE, 2-year infiltration |
| Supply chain — hallucination | Slopsquatting (2023–present) | 20-35% of hallucinated names already malicious |
| AI agent compromise | Amazon Q wiper (Jul 2025) | Near-miss: all EC2 instances terminated |
| AI IDE 0-days | IDEsaster (Dec 2025, 30+ CVEs) | 100% of AI IDEs vulnerable |
| Production destruction | Pinecone 515 indexes deleted | Irreversible customer data loss |
| Runaway costs | $47K loop (11 days) | Unbounded API spend |
| GDPR | Meta €1.2B · LinkedIn €310M | Up to 4% global revenue per violation |

---

## Related Tools

- [session-replay](https://github.com/RajuRoopani/session-replay) — Interactive HTML timeline of Claude Code sessions
- [session-monitor](https://github.com/RajuRoopani/session-monitor) — Live on-track/drifting/stuck feedback
- [agent-handoff](https://github.com/RajuRoopani/agent-handoff) — Zero-context-loss between sessions
- [interview-teammate](https://github.com/RajuRoopani/interview-teammate) — AI-powered hiring assistant

## License

MIT
