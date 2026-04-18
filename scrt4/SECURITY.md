# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in scrt4, **please report it responsibly**. Do not open a public GitHub issue.

**Email:** security@llmsecrets.com
**PGP Key:** Available on request (reply to your initial report)

### What to Include

- Description of the vulnerability and its impact
- Steps to reproduce (proof of concept)
- Affected component (daemon, CLI, relay, protocol)
- Your suggested severity (Critical / High / Medium / Low)

### Response Timeline

| Stage | Target |
|-------|--------|
| First response | 48 hours |
| Triage & severity assessment | 7 days |
| Fix for Critical/High | 14 days |
| Fix for Medium/Low | 30 days |
| Public disclosure | After fix is released (coordinated with reporter) |

### Bounty Rewards

Valid, original vulnerability reports are eligible for rewards:

| Severity | Payout | Examples |
|----------|--------|----------|
| **Critical** | $500 - $2,000 | Bypass WebAuthn to reveal secret values; master key extraction without authenticator; remote code execution via socket protocol |
| **High** | $200 - $500 | Socket-level authentication bypass; vault decryption without PRF output; session hijacking across daemon restarts |
| **Medium** | $50 - $200 | Timing attacks on challenge codes; WA verification window race conditions; audit log tampering or bypass |
| **Low** | $25 - $50 | Secret name disclosure without values; information leaks in error messages; denial of service against daemon |

Payouts are at the maintainer's discretion based on impact, quality of report, and exploitability. Bonus for high-quality reports with working PoC.

---

## Scope

### In Scope

| Component | Location | Language | What to Test |
|-----------|----------|----------|--------------|
| **Daemon** | `daemon/src/` | Rust | Session management, WebAuthn verification enforcement, secret storage/retrieval, challenge system, memory handling |
| **CLI** | `daemon/bin/scrt4` | Bash | Command injection, secret leakage to stdout/stderr/`/proc`, argument handling, temp file security |
| **Keystore** | `daemon/src/keystore.rs` | Rust | AES-256-GCM vault encryption, master key derivation, PRF salt handling, key file format |
| **Socket Protocol** | `daemon/src/protocol.rs`, `handlers.rs` | Rust | JSON-RPC message handling, authentication bypass, privilege escalation between commands |
| **WebAuthn** | `daemon/src/webauthn.rs` | Rust | Credential verification, PRF output handling, relay payload decryption, state management |
| **Auth Relay** | `auth-relay/` | Node.js | Encrypted blob handling, session ID predictability, short code collisions |
| **Subprocess** | `daemon/src/subprocess.rs` | Rust | `$env[NAME]` injection, output sanitization, secret leak detection |

### Out of Scope

- Social engineering or phishing attacks
- Denial of service (volumetric / resource exhaustion)
- Attacks requiring root/admin access on the host machine (ptrace, `/proc/pid/mem`)
- Attacks requiring physical access to the hardware authenticator
- Bugs in third-party dependencies (report upstream; let us know if it affects scrt4)
- The auth relay landing page UI (`auth-relay/public/index.html`)
- Rate limiting or brute force on the relay (stateless proxy)

---

## Architecture Overview (for researchers)

```
                   ┌──────────────────────┐
                   │   Phone / Browser    │
                   │   (WebAuthn ceremony)│
                   └──────────┬───────────┘
                              │ encrypted blob (AES-256-GCM)
                              ▼
                   ┌──────────────────────┐
                   │   Auth Relay (GCP)   │
                   │   Redis blob store   │
                   └──────────┬───────────┘
                              │ poll / callback
                              ▼
┌──────────┐      ┌──────────────────────┐      ┌──────────────┐
│  CLI     │─────►│   scrt4-daemon       │─────►│  Subprocess  │
│  (bash)  │ Unix │   (Rust, in-memory)  │ fork │  (with env   │
│          │socket│                      │      │   secrets)   │
└──────────┘      │  ┌─────────────────┐ │      └──────────────┘
                  │  │ Session:        │ │
                  │  │  - secrets{}    │ │
                  │  │  - master_key   │ │
                  │  │  - wa_verified  │ │
                  │  │  - challenges   │ │
                  │  └─────────────────┘ │
                  │                      │
                  │  ~/.scrt4/           │
                  │  ├─ secrets.enc      │◄── AES-256-GCM vault
                  │  ├─ master.key       │◄── PRF-encrypted master key
                  │  ├─ webauthn.json    │◄── credential (public data)
                  │  └─ audit.jsonl      │◄── access log
                  └──────────────────────┘
```

### Key Security Properties

1. **WebAuthn is always required** for sensitive operations (reveal, backup-key, disable-wa). Enforced at the daemon level, not just CLI. Cannot be bypassed by editing state files on disk.

2. **Single-use verification** — Each WebAuthn ceremony authorizes exactly one sensitive operation. The verification is consumed atomically, preventing re-entry attacks within the time window.

3. **Secrets never touch bash** — For reveal/share operations, secret values go directly from daemon memory to Python memory to encrypted output. Never in shell variables, command arguments, or `/proc/PID/cmdline`.

4. **Master key is hardware-bound** — Derived from FIDO2 `hmac-secret` (PRF) extension. The key material never leaves the authenticator. No password or TOTP fallback.

5. **Relay sees only ciphertext** — Auth blobs are encrypted with ephemeral AES-256-GCM keys before being posted to the relay. The relay server cannot read authentication data.

### Interesting Attack Surface

- **Unix socket protocol** — Any local process with socket access can send JSON-RPC. The daemon must enforce all security invariants server-side.
- **`consume_wa_verification`** — Single-use WA gate. Can you race it? Can you make the daemon set `wa_verified` without a real WebAuthn ceremony?
- **Challenge code auto-completion** — The 6-digit code is returned in the `reveal_all` response. The real gate is the WA verification that precedes it.
- **Temp file lifecycle** — Encrypted share payloads use `$XDG_RUNTIME_DIR` (tmpfs). Is the shred-before-unlink effective?
- **Python memory handling** — Secret values exist briefly in Python memory during share/wallet operations. Is `del` + reassign sufficient in CPython?
- **Relay session IDs** — 40 hex chars (160 bits). Is the CSPRNG properly seeded?

---

## Disclosure Policy

- We practice **coordinated disclosure**. Reporters get credit in the changelog and release notes (unless they prefer anonymity).
- We aim to fix Critical/High issues before public disclosure.
- If we are unresponsive beyond our stated timelines, reporters may disclose after 90 days.
- We will never pursue legal action against researchers acting in good faith within this policy.

---

## Hall of Fame

*No reports yet. Be the first.*
