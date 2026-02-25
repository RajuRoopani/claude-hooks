# claude-hooks

> Org-wide policy enforcement hooks for [Claude Code](https://claude.ai/code).

A collection of pre-built Claude Code hooks that enforce security, compliance, and workflow policies across your entire engineering org — deterministically, on every tool call.

---

## What are Claude Code hooks?

Hooks are shell scripts that fire at specific points in Claude Code's lifecycle (before/after every tool call). They can **block, log, or redirect** Claude's actions — enforcing rules that the LLM cannot override.

Think of them like `git hooks`, but for every action Claude takes.

---

## Hooks

### `block-icm` — Block access to ICM dashboard

Prevents Claude from accessing Microsoft ICM dashboard (`icm.ad.msft.net`) across any tool:
- `Bash` (curl, wget, open)
- `WebFetch`
- Browser / Playwright MCP tools
- Any other tool whose input references ICM URLs

Every blocked attempt is **audit logged** to `~/.claude/audit/icm-policy-violations.jsonl`.

---

## Quick start

```bash
# 1. Copy hooks into your repo
cp -r .claude/ your-repo/.claude/

# 2. Make the hook executable
chmod +x your-repo/.claude/hooks/block-icm.sh

# 3. Claude Code picks up .claude/settings.json automatically
```

That's it. Anyone who clones your repo gets the policy enforced.

---

## Org-wide enforcement (can't be disabled by engineers)

Deploy via MDM (Jamf, Kandji, Intune):

**macOS** — create `/Library/Application Support/Claude/managed-settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/local/share/claude-hooks/block-icm.sh",
            "timeout": 5,
            "statusMessage": "Checking org policy..."
          }
        ]
      }
    ]
  }
}
```

Deploy `block-icm.sh` to `/usr/local/share/claude-hooks/` on each machine. Engineers cannot override managed settings.

Full deployment guide: [.claude/hooks/DEPLOY.md](.claude/hooks/DEPLOY.md)

---

## Audit log

```jsonc
// ~/.claude/audit/icm-policy-violations.jsonl
{"timestamp":"2026-02-25T10:32:11Z","event":"icm_blocked","tool":"Bash","matched":"icm\\.ad\\.msft\\.net","session":"abc123","cwd":"/Users/eng/my-service"}
{"timestamp":"2026-02-25T11:14:03Z","event":"icm_blocked","tool":"WebFetch","matched":"icm\\.ad\\.msft\\.net","session":"def456","cwd":"/Users/eng/payments"}
```

Ship to your SIEM with a simple `tail -F` or fluentd config.

---

## Adding more blocked domains

Edit the `ICM_PATTERNS` array in [.claude/hooks/block-icm.sh](.claude/hooks/block-icm.sh):

```bash
ICM_PATTERNS=(
  "icm\.ad\.msft\.net"
  "your-blocked-tool\.company\.com"   # add here
)
```

---

## Structure

```
.claude/
├── settings.json          # wires hooks into Claude Code
└── hooks/
    ├── block-icm.sh       # ICM dashboard enforcer
    └── DEPLOY.md          # org-wide deployment playbook
```

---

## Contributing

PRs welcome. The goal is a curated library of org-policy hooks every engineering team can drop in.

Ideas:
- `block-prod-write` — block direct writes to production DBs
- `require-ticket` — block PRs without a Jira/Linear ticket reference
- `audit-all` — append every tool call to a central audit log
- `no-force-push` — block `git push --force` to protected branches

---

## License

MIT
