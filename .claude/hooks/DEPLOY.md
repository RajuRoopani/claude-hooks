# ICM Dashboard Block — Deployment Guide

## How it works

`block-icm.sh` fires on **every tool call** Claude makes (`PreToolUse`, empty matcher).
It stringifies the full tool input and scans for `icm.ad.msft.net` patterns.
If matched → exits with code `2` → Claude is **hard-blocked**, sees the policy message.
Every violation is **audit logged** to `~/.claude/audit/icm-policy-violations.jsonl`.

---

## Option 1: Per-repo enforcement (commit to repo)

Drop `.claude/settings.json` and `.claude/hooks/block-icm.sh` into any repo.
Anyone who `git clone`s it gets the policy automatically — no install step.

```
your-repo/
├── .claude/
│   ├── settings.json          ← hook config
│   └── hooks/
│       └── block-icm.sh       ← the enforcer
```

**Commit both files.** Claude Code picks up `.claude/settings.json` from the project root automatically.

---

## Option 2: Org-wide via managed policy (enforced, can't be overridden)

Managed settings are read-only to engineers — they cannot be disabled via `/hooks` or `disableAllHooks`.

### macOS (MDM / Jamf / manual)

1. Deploy `block-icm.sh` to a consistent path on every machine:
   ```
   /usr/local/share/claude-hooks/block-icm.sh
   ```

2. Create the managed policy file:
   ```
   /Library/Application Support/Claude/managed-settings.json
   ```

   With contents:
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

3. Push via MDM (Jamf, Kandji, etc.) to all engineer machines.

### Windows (Group Policy / Intune)

Deploy to:
```
C:\ProgramData\Claude\managed-settings.json
```
Script path:
```
C:\ProgramData\claude-hooks\block-icm.sh  (requires Git Bash or WSL)
```

---

## Option 3: Dotfiles repo (team-level, opt-in)

If your org uses a shared dotfiles repo:

```bash
# In dotfiles setup.sh
mkdir -p ~/.claude/hooks
cp hooks/block-icm.sh ~/.claude/hooks/
chmod +x ~/.claude/hooks/block-icm.sh

# Merge into user-level settings
jq -s '.[0] * .[1]' ~/.claude/settings.json claude-settings-patch.json \
  > ~/.claude/settings.json.tmp && mv ~/.claude/settings.json.tmp ~/.claude/settings.json
```

---

## Audit log

Every blocked attempt is logged here (per machine):
```
~/.claude/audit/icm-policy-violations.jsonl
```

Each line is a JSON record:
```json
{
  "timestamp": "2026-02-25T10:32:11Z",
  "event": "icm_blocked",
  "tool": "Bash",
  "matched": "icm\\.ad\\.msft\\.net",
  "session": "abc123",
  "cwd": "/Users/eng/my-service"
}
```

Ship these to your SIEM / Splunk / Datadog with a simple cron or fluentd tail.

---

## Adding more blocked domains

Edit the `ICM_PATTERNS` array in `block-icm.sh`:

```bash
ICM_PATTERNS=(
  "icm\.ad\.msft\.net"
  "icmdashboard\.microsoft\.com"
  "icm\.microsoft\.com"
  "your-internal-blocked-tool\.company\.com"   # ← add here
)
```

---

## Testing the hook

```bash
# Simulate a WebFetch hook input
echo '{
  "tool_name": "WebFetch",
  "session_id": "test-123",
  "cwd": "/tmp",
  "tool_input": {
    "url": "https://icm.ad.msft.net/imp/v3/incidents/123"
  }
}' | .claude/hooks/block-icm.sh

# Expected: exit code 2, policy violation message printed to stderr
echo "Exit code: $?"
```
