# Security Architecture — scrt2

This document describes the security design of scrt2, the threat model, known
risks, and the rules contributors must follow when modifying authentication or
secret-handling code.

---

## Core Principle

**Zero-knowledge secret management for humans, minimal-exposure automation for agents.**

scrt2 provides three 2FA setup modes that sit on a spectrum:

| Mode | Secret visibility | Verification | GUI required | Target user |
|------|-------------------|-------------|--------------|-------------|
| `manual` | Never shown (hidden `read -rs`) | User types TOTP code | No | Human at terminal |
| `qr` | Shown in zenity window only | User types TOTP code | Yes (zenity) | Human with display |
| `agent` | Printed to stdout once | Auto-verified via `compute_totp` | No | AI agent (Claude Code) |

`manual` and `qr` are **zero-knowledge** — the secret never enters any log,
pipe, or agent context. `agent` mode intentionally breaks this to enable
non-interactive setup, then immediately flushes all traces.

---

## Design Decisions

### Different auth = different keys = no access to prior secrets

When `setup-2fa` runs (any mode), it calls `initialize_keys` which:

1. Generates a fresh 32-byte random AES-256 master key
2. DPAPI-encrypts it (Windows CurrentUser scope) and overwrites the key file
3. **Deletes all existing `.env.encrypted.v*` files**
4. Creates a new empty secret store encrypted with the new key

This means an attacker who resets the TOTP seed via the unauthenticated
`setup_totp` socket call gets their own auth bound to their own encryption
keys — with **zero secrets** in the store. The old master key is gone. The old
encrypted data is deleted. There is no path from new-auth to old-data.

This is why `setup_totp` and `initialize_keys` do not require an active
session: the worst case is denial of service (wiping the store), not
credential theft.

### Agent mode: minimize exposure time and persistence

The `agent` mode prints the TOTP seed to stdout exactly once, then:

1. Clears the bash variable (`secret="[CLEARED]"`)
2. Auto-verifies (no second read from disk for display)
3. Calls `flush_setup_traces` which scrubs:
   - scrt2 audit logs
   - Shell history (bash/zsh)
   - Temp files (`/tmp/scrt2-qr-*`)
   - Claude Code session transcripts (exact seed replacement)

The seed's exposure window is: printed to stdout → user presses Enter →
flushed. The seed persists on disk at `~/.scrt2/totp.secret` (0600, by
design — needed for `compute_totp` on every `unlock`).

### TOTP seed never crosses the socket

The daemon's `handle_setup_totp` returns only `{"success": true}`. The seed is
written to disk by the daemon and read from disk by the CLI. It never appears
in a JSON response, socket buffer, or network payload.

---

## Strict Rules for Contributors

### Rule 1: Any new auth method MUST flush its associated seed

If you add a new authentication method (passkey, biometric, hardware token,
etc.), you **MUST** ensure the associated seed/secret is flushed from:

- [ ] Shell history (`~/.bash_history`, `~/.zsh_history`)
- [ ] scrt2 audit logs (`~/.scrt2/audit/*.jsonl`)
- [ ] Temp files in `/tmp/`
- [ ] AI agent session transcripts (`~/.claude/projects/**/*.jsonl`)
- [ ] Process environment (`/proc/*/environ`)
- [ ] Process command line (`/proc/*/cmdline`)
- [ ] Daemon tracing output (ensure `tracing::info!` never logs the seed)

This is a **non-negotiable requirement**. The `flush_setup_traces` function
exists for this purpose — extend it if your auth method introduces new
persistence vectors.

### Rule 2: Never log secrets in daemon tracing

The daemon uses `tracing` for structured logging. Secret values, TOTP seeds,
master keys, and encryption material must **never** appear in `tracing::info!`,
`tracing::debug!`, or `tracing::error!` calls. Log event types and
success/failure only.

### Rule 3: Pass secrets via stdin, not command-line arguments

Command-line arguments are visible in `/proc/*/cmdline` to any process running
as the same UID. When invoking subprocesses that need secrets:

```rust
// BAD — visible in /proc/*/cmdline
Command::new("python3").args(["-c", &format!("secret = '{}'", seed)])

// GOOD — only visible in /proc/*/environ (same-UID + root only)
Command::new("python3").args(["-c", "import sys; secret = sys.stdin.read()"])
    .stdin(Stdio::piped())
```

---

## Known Vulnerabilities and Mitigations

### V1: /proc/cmdline exposure in compute_totp

| | |
|---|---|
| **Severity** | Medium |
| **Affects** | `agent` and `qr` modes (also `unlock` in all modes) |
| **Status** | Known, unmitigated |

`compute_totp()` interpolates the TOTP secret into a `python3 -c` one-liner.
The secret is visible in `/proc/<pid>/cmdline` for the subprocess lifetime
(~100ms). Any process running as the same UID can read it.

**Mitigation path**: Pipe the secret via stdin instead:
```bash
cat "$TOTP_SECRET_FILE" | python3 -c "
import sys; secret_b32 = sys.stdin.read().strip()
# ... TOTP computation
"
```

### V2: Master key in PowerShell command string

| | |
|---|---|
| **Severity** | Medium |
| **Affects** | All modes (during `initialize_keys`) |
| **Status** | Known, unmitigated |

`dpapi.rs:generate_new_master_key()` embeds the base64 master key in a
PowerShell `-Command` string, briefly exposing it in the PowerShell process's
command line.

**Mitigation path**: Pipe the PowerShell script via stdin:
```rust
let mut child = Command::new(powershell)
    .args(["-ExecutionPolicy", "Bypass", "-Command", "-"])
    .stdin(Stdio::piped())
    .spawn()?;
child.stdin.take().unwrap().write_all(script.as_bytes())?;
```

### V3: Full audit log truncation

| | |
|---|---|
| **Severity** | Medium |
| **Affects** | All modes |
| **Status** | Known, accepted trade-off |

`flush_setup_traces` truncates the entire day's audit log, not just
setup-related entries. An attacker who triggers `setup-2fa` could use this to
erase evidence of earlier suspicious activity.

**Why accepted**: The alternative (selective grep/sed) risks leaving partial
seed fragments in log entries. Full truncation is the safer default for a
setup operation that should only happen once per installation.

### V4: Tautological auto-verification in agent mode

| | |
|---|---|
| **Severity** | Medium |
| **Affects** | `agent` mode only |
| **Status** | Accepted with warning |

Agent mode verifies TOTP by calling `compute_totp` which reads the same seed
file the daemon just wrote. This proves the file is readable, not that the user
actually enrolled the seed in an authenticator app.

**Mitigation**: The CLI prints a clear message showing the seed and asks the
user to press Enter only after adding it to their authenticator. The user
(or the AI agent acting on their behalf) is responsible for confirming
enrollment before proceeding.

### V5: Agent mode stdout exposure

| | |
|---|---|
| **Severity** | High (by design) |
| **Affects** | `agent` mode only |
| **Status** | Accepted, mitigated by flush |

The TOTP seed is printed to stdout in plaintext. This is the fundamental
trade-off of agent mode — the AI agent must see the seed to display it to
the user. The seed appears in:

- Terminal stdout (cleared by user scrollback behavior)
- AI agent context window (in-memory, session-scoped)
- AI agent session transcripts on disk (redacted by `flush_setup_traces`)

**Mitigations in place**:
1. `flush_setup_traces` redacts the exact seed from Claude Code transcripts
2. Bash variable is overwritten with `"[CLEARED]"` immediately after display
3. The seed is displayed once, never re-read for display purposes
4. `manual` and `qr` modes remain available for zero-knowledge setup

---

## Mitigations Already in Place

| Control | Description |
|---------|-------------|
| File permissions | `totp.secret`: 0600, `~/.scrt2/`: 0700, socket: 0600 |
| Variable clearing | `secret="[CLEARED]"` after use in all modes |
| Seed never crosses socket | Written to disk by daemon, read from disk by CLI |
| TOTP skew = 1 | 90-second window (current ± 1 step) |
| Session TTL cap | Maximum 86400s (24h), token bytes zeroed on `clear()` |
| Output sanitization | `run_with_secrets` replaces all secret values in command output |
| Challenge-response for reveal | 6-digit code in zenity, single-use, 60s expiry |
| Remote restrictions | Disabled by default; only `status`/`list`/`run` allowed remotely |
| Transcript redaction | `flush_setup_traces` replaces exact TOTP seed in `.jsonl` files |
| Comprehensive audit logging | Structured JSONL with sanitized commands |

---

## Threat Model Summary

| Attacker | Can do | Cannot do |
|----------|--------|-----------|
| AI agent (post-flush) | Nothing — seed redacted from transcripts | Recover seed from redacted transcripts |
| Same-UID local process | Reset TOTP + keys (DoS), read `totp.secret` | Access secrets encrypted under old keys |
| Root / ptrace-capable | Read `totp.secret`, daemon memory | Decrypt DPAPI blob without Windows user session |
| Remote attacker | Nothing (remote disabled by default) | Connect to Unix socket |

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│  User / AI Agent                                        │
│                                                         │
│  scrt2 setup-2fa [manual|qr|agent]                      │
│       │                                                 │
│       ├─ manual: read -rs (hidden) → user verifies      │
│       ├─ qr: zenity GUI → user verifies                 │
│       └─ agent: stdout (once) → auto-verify → flush     │
│                                                         │
│  ┌──────────┐    Unix Socket     ┌──────────────────┐   │
│  │ CLI      │ ──── JSON ──────── │ Daemon (Rust)    │   │
│  │ (bash)   │    (0600 perms)    │                  │   │
│  │          │                    │ setup_totp       │   │
│  │          │    seed NEVER      │   → write to     │   │
│  │          │    in JSON         │     disk only    │   │
│  │          │    response        │                  │   │
│  │          │                    │ initialize_keys  │   │
│  │          │                    │   → new AES-256  │   │
│  │          │                    │   → DPAPI wrap   │   │
│  │          │                    │   → delete old   │   │
│  │          │                    │     .env files   │   │
│  └──────────┘                    └──────────────────┘   │
│                                                         │
│  After setup:                                           │
│  ┌──────────────────────────────────────────────────┐   │
│  │ flush_setup_traces()                             │   │
│  │  1. Truncate audit logs                          │   │
│  │  2. Scrub shell history                          │   │
│  │  3. Delete temp files                            │   │
│  │  4. Redact seed from AI session transcripts      │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  Persistent on disk (by design):                        │
│  ~/.scrt2/totp.secret  (0600) ← needed for unlock      │
│  ~/.scrt2/credentials/ (DPAPI blob)                     │
│  ~/.scrt2/env/         (AES-256 encrypted store)        │
└─────────────────────────────────────────────────────────┘
```

---

*Last updated: 2026-03-08*
