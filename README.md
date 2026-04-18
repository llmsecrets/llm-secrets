# LLM Secrets

> **Protect your `.env` secrets from AI coding assistants.** Claude, Cursor, and other agents can *use* your secrets without ever *seeing* them.

[![Downloads](https://img.shields.io/badge/Downloads-llmsecrets.com-2563eb)](https://llmsecrets.com/downloads)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-green)](LICENSE)
[![Branch: scrt4-community](https://img.shields.io/badge/Branch-scrt4--community-blueviolet)](https://github.com/llmsecrets/llm-secrets/tree/scrt4-community)

---

## The Problem

When Claude Code reads your `.env` file, your API keys, database passwords, and private keys land in the AI's context window — and every prompt cache, log line, and error report that follows.

```
[!] Claude Code just read your .env:
    PRIVATE_KEY=0x7f3a8b2c...
    STRIPE_SECRET_KEY=sk_live_...
    DATABASE_URL=postgres://admin:password@...
```

## The Solution

LLM Secrets holds your secrets in an encrypted vault. The AI writes commands with placeholder names; the values are substituted at runtime inside an isolated subprocess and scrubbed from stdout before anything returns to the model.

```
✓ Claude sees:     scrt4 run 'curl -H "Authorization: Bearer $env[API_KEY]" ...'
✗ Claude sees NOT: the actual bearer token
```

---

## scrt4 — the current generation

This branch (`scrt4-community`) ships **scrt4**, the AGPL-licensed, hardware-bound successor to the original LLM Secrets stack. Source lives under [`scrt4/`](./scrt4).

- **FIDO2 / WebAuthn** — YubiKey, Touch ID, Windows Hello, phone passkey (caBLE). The master key is derived via `hmac-secret` and never leaves the authenticator.
- **AES-256-GCM** vault at rest. Secrets live in daemon memory during a session; never written unencrypted.
- **LLM-safe by design** — the daemon scrubs every stored value from subprocess stdout before returning it to the agent.
- **Modular** — hot-pluggable modules (`cloud-crypt`, `encrypt-folder`, `import-env`, `github`, …) gated by an on-disk whitelist and SHA256-verified at install time.
- **One-command install, same across macOS, Linux, and WSL:**

```bash
curl -fsSL https://install.llmsecrets.com/native | sh
```

Full install options, per-OS details, and **SHA256 verification commands** live at **<https://llmsecrets.com/downloads>**.

### Unlock, add, and run

```bash
scrt4 setup                    # one-time FIDO2 enrollment
scrt4 unlock                   # 20-hour session
scrt4 import path/to/.env      # import existing secrets
scrt4 list                     # see names (never values)
scrt4 run 'cmd $env[NAME]'     # agent-safe execution
```

See [`scrt4/README.md`](./scrt4/README.md) for the full command reference, [`scrt4/ARCHITECTURE.md`](./scrt4/ARCHITECTURE.md) for the TCB diagram, and [`scrt4/SECURITY.md`](./scrt4/SECURITY.md) for the threat model.

### Uninstall

```bash
curl -fsSL https://install.llmsecrets.com/uninstall | sh
```

---

## Deprecated: the original LLM Secrets stack

The top-level directories below are the **original** LLM Secrets components, preserved for users who haven't migrated yet. They are **no longer actively developed**. New installs should use scrt4.

| Directory | What it is | Status |
|---|---|---|
| [`cli/`](./cli) | PowerShell CLI for Windows (`scrt.ps1`) | Deprecated — use `scrt4` |
| [`crypto-core/`](./crypto-core) | Windows Hello AES-256-CBC crypto module | Deprecated — scrt4 uses FIDO2 + AES-256-GCM |
| [`desktop-app/`](./desktop-app) | Electron app (TOTP + license-gated) | Deprecated — scrt4 is daemon + CLI |
| [`wsl-daemon/`](./wsl-daemon) | Original WSL bridge | Deprecated — scrt4 ships its own daemon |

**Why deprecated?**
1. **FIDO2 > Windows Hello + TOTP.** scrt4's key is hardware-bound via `hmac-secret` and portable across devices (phone passkeys, YubiKeys). The original stack relied on platform-specific biometric APIs and a TOTP secondary.
2. **AGPL > source-available.** scrt4 is AGPL-3.0, verifiable end-to-end. The original stack shipped binaries through a license-gated channel.
3. **Cross-platform parity.** scrt4 runs the same way on macOS, Linux, and WSL. The original stack had divergent behavior across platforms.

These directories will remain in the repo indefinitely so existing users can self-host and migrate on their own schedule. No PRs against them will be merged unless they are security fixes.

---

## Trust & verification

- **Downloads:** <https://llmsecrets.com/downloads> — lists every release, with per-platform install commands and the current published SHA256 checksums.
- **Release checksums:** <https://install.llmsecrets.com/releases/latest.txt> points to the current release tag; each release directory contains a `SHA256SUMS` file signed and published alongside the binaries.
- **Self-verification:** a running scrt4 can check its own binary against the published manifest with `scrt4 verify-self`.
- **Source:** this branch, `scrt4-community`, is what builds the binaries published to `install.llmsecrets.com`. Every commit is signed by [@VestedJosh](https://github.com/VestedJosh).

---

## Contributing

- Issues and PRs against `scrt4/` are welcome — the active development line is `scrt4-community`.
- Security issues: please email `security@llmsecrets.com` or open a private security advisory on this repo; do not file public issues for vulnerabilities.
- The original LLM Secrets stack (top-level `cli/`, `desktop-app/`, etc.) is in maintenance mode — we only accept security patches there.

## License

AGPL-3.0. See [`LICENSE`](./LICENSE) and [`legal/SOFTWARE-LICENSE.md`](./legal/SOFTWARE-LICENSE.md).
