# scrt2 — WSL2 Secure Secret Injector (TOTP Edition)

## How Secret Injection Works

Secrets are stored encrypted and injected at runtime as environment
variables. You NEVER see the actual values.

```
+----------------+     +----------------+     +----------------+
| Your Command   | --> | scrt2 injects  | --> | Command runs   |
| (no secrets)   |     | $env[NAME]     |     | with secrets   |
+----------------+     +----------------+     +----------------+
```

**IMPORTANT:** Use `$env[SECRET_NAME]` syntax (NOT `$SECRET_NAME` or `${SECRET_NAME}`)

---

## Quick Reference

```bash
scrt2 daemon &              # Start daemon
scrt2 setup-2fa agent       # Set up 2FA for AI agent (non-interactive)
scrt2 setup-2fa             # Set up 2FA with QR code (GUI, zero-knowledge)
scrt2 setup-2fa manual      # Set up 2FA via hidden CLI input (zero-knowledge)
scrt2 unlock                # Authenticate (20 hour session)
scrt2 add KEY=value         # Add a secret
scrt2 list                  # List secret names
scrt2 run 'cmd $env[KEY]'   # Run command with secret injection
scrt2 view                  # View secrets in GUI (zenity)
scrt2 help                  # Full command list
```

---

## Installed Paths (relative to $HOME)

| Resource | Path |
|----------|------|
| Daemon binary | `~/.local/bin/scrt2-daemon` |
| CLI | `~/.local/bin/scrt2` |
| Client | `~/.local/bin/scrt2-client` |
| Socket | `$XDG_RUNTIME_DIR/scrt2.sock` |
| TOTP secret | `~/.scrt2/totp.secret` |
| Audit logs | `~/.scrt2/audit/` |

## Source Layout (relative to repo root)

| Path | Purpose |
|------|---------|
| `bin/scrt2` | CLI wrapper (bash) |
| `src/` | Daemon source (Rust) |
| `scrt-client/` | Client binary source |
| `install/install.sh` | Installer |
| `SECURITY.md` | Threat model and contributor rules |

---

## 2FA Setup Modes

| Mode | Secret visibility | Verification | GUI | Target |
|------|-------------------|-------------|-----|--------|
| `manual` | Never (hidden input) | User types TOTP code | No | Human at terminal |
| `qr` | Zenity window only | User types TOTP code | Yes | Human with display |
| `agent` | Printed to stdout once, then flushed | Auto-verified | No | AI agent |

`manual` and `qr` are **zero-knowledge** — the secret never enters any log,
pipe, or agent context. `agent` mode intentionally breaks this for automation,
then immediately flushes all traces from audit logs, shell history, temp files,
and AI session transcripts.

---

## Security Model

1. **LLM never sees secrets** — Values are never returned to Claude Code
2. **LLM can use secrets** — Write commands with `$env[NAME]`, values injected at runtime
3. **Secrets exist only in subprocess** — Isolated from main process memory
4. **Encrypted at rest** — AES-256 encrypted store, master key DPAPI-protected
5. **TOTP-gated** — Google Authenticator required to unlock
6. **Different auth = different keys** — `setup-2fa` generates fresh master key + empty store; no path from new auth to old data
7. **TOTP seed never crosses the socket** — Written to disk by daemon, read from disk by CLI
8. **View is GUI-only** — Secret values display in zenity dialog (invisible to agents)

See `SECURITY.md` for full threat model, known vulnerabilities, and contributor rules.

---

## Agent Interaction with 2FA-Protected Commands

Commands that require a Google Authenticator TOTP code: `unlock`, `view`, `2fa-disable`, `2fa-reenable`.

All accept an **optional TOTP code as an argument**. Two interaction modes:

| Mode | How it works | Who enters the code |
|------|-------------|-------------------|
| **Agent-assisted** | User gives Claude the 6-digit code, Claude passes it as an argument | User tells Claude, Claude runs command |
| **GUI prompt** | Claude runs command with no code, zenity dialog pops up | User enters code in GUI |

### Agent-assisted mode (user provides TOTP code)

**CRITICAL: TOTP codes expire in 30 seconds. When the user provides a code, run the command IMMEDIATELY — no thinking, no explanation, no delay.**

```bash
scrt2 unlock 72000 <code>     # Unlock session (TTL + TOTP code)
scrt2 view <code>             # View secrets in GUI (agent CANNOT see the values)
scrt2 2fa-disable <code>      # Disable 2FA for view
scrt2 2fa-reenable <code>     # Re-enable 2FA for view
```

### GUI prompt mode (no code argument)

```bash
scrt2 unlock                  # Zenity dialog prompts for code
scrt2 view                    # Zenity dialog prompts for code, then shows secrets
```

### Security: Why this is safe

- **Agent authenticates but never sees secrets.** `scrt2 view <code>` authenticates via the daemon, then displays secrets in a **zenity GUI dialog**. The secret values never appear in terminal stdout, so the agent never sees them.
- **Agent cannot read the TOTP seed.** The agent passes a user-provided code; it does not compute codes from `~/.scrt2/totp.secret`.
- **TOTP codes are single-use within a 30-second window.** A code seen by the agent in conversation context is expired and useless by the time the conversation continues.

---

## What You Can See vs. What You Cannot

| You CAN See | You CANNOT See |
|-------------|----------------|
| Secret names (e.g., PRIVATE_KEY) | Secret values (e.g., 0x7f3a...) |
| Command structure | The actual injected value |
| Transaction hashes | Private keys |
| Success/failure messages | Passwords or tokens |

---

## After Building from Source

```bash
# Build
cargo build --release

# Install (copies to ~/.local/bin and restarts daemon)
cp target/release/scrt2-daemon ~/.local/bin/scrt2-daemon
cp bin/scrt2 ~/.local/bin/scrt2
pkill -f scrt2-daemon 2>/dev/null; rm -f "$XDG_RUNTIME_DIR/scrt2.sock"
nohup scrt2-daemon >/dev/null 2>&1 &disown
```

---

## Troubleshooting

### "Daemon not running"
```bash
scrt2 daemon &   # Start in background
# or
nohup scrt2-daemon >/dev/null 2>&1 &disown
```

### Socket connection issues
`XDG_RUNTIME_DIR` may have a trailing slash. The CLI handles this, but if
using `nc` directly, use the full path: `/run/user/$(id -u)/scrt2.sock`

### "Secret not found"
The secret name may be different. Run `scrt2 list` to see available names.
