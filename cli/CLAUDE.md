# Scrt — Secret Access Reference

## How Secret Injection Works

Secrets are stored encrypted and injected at runtime as environment
variables. You NEVER see the actual values.

```
+----------------+     +----------------+     +----------------+
| Your Command   | --> | Scrt injects   | --> | Command runs   |
| (no secrets)   |     | $env[NAME]     |     | with secrets   |
+----------------+     +----------------+     +----------------+
```

**IMPORTANT:** Use `$env[SECRET_NAME]` syntax (NOT `$SECRET_NAME` or `${SECRET_NAME}`)

The secret value exists ONLY in the subprocess environment.
It is never written to disk or returned to the LLM.

---

## Quick Reference

```bash
scrt init                    # First-time setup (Windows Hello)
scrt setup                   # Encrypt an existing .env file
scrt unlock                  # Authenticate with Windows Hello
scrt list                    # List secret names
scrt run 'cmd $env[KEY]'     # Run command with secret injection
scrt view                    # View secrets in GUI (zenity/dialog)
scrt add KEY=value           # Add a secret
scrt edit                    # Interactive edit mode
```

---

## How to Run Commands with Secrets

```bash
scrt run 'forge script script/Deploy.s.sol --rpc-url $env[ALCHEMY_RPC_URL] --private-key $env[PRIVATE_KEY] --broadcast'
scrt run 'curl -H "Authorization: Bearer $env[API_KEY]" https://api.example.com'
scrt run 'git push https://$env[GITHUB_PAT]@github.com/user/repo.git'
```

---

## Security Model

1. **LLM never sees secrets** — Values are never returned to Claude Code
2. **LLM can use secrets** — Write commands with `$env[NAME]`, values injected at runtime
3. **Secrets exist only in subprocess** — Isolated from main process memory
4. **Encrypted at rest** — AES-256-CBC encrypted .env (master key in DPAPI)
5. **Biometric gated** — Windows Hello facial recognition required to unlock
6. **Session key isolated** — Cached in Linux kernel keyring (not shell variables)
7. **View is GUI-only** — Secret values display in system dialog (invisible to agents)

---

## What You Can See vs. What You Cannot

| You CAN See | You CANNOT See |
|-------------|----------------|
| Secret names (e.g., PRIVATE_KEY) | Secret values (e.g., 0x7f3a...) |
| Command structure | The actual injected value |
| Transaction hashes | Private keys |
| Success/failure messages | Passwords or tokens |

---

## Available Commands

| Command | Description |
|---------|-------------|
| `/learn` | Regenerate CLAUDE.md with current secret names |
| `/hide` | Verify secrets are properly hidden |

**NOTE:** Viewing secret values requires `scrt view` (opens a system dialog).
This is intentionally NOT available as a slash command to prevent AI agents
from accessing secret values.
