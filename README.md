# LLM Secrets

> **Protect your `.env` secrets from AI coding assistants.** Claude, Cursor, and other agents can *use* your secrets without ever *seeing* them.

[![Downloads](https://img.shields.io/badge/Downloads-llmsecrets.com-2563eb)](https://llmsecrets.com/downloads)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-green)](LICENSE)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/llmsecrets/llm-secrets)

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

The active code lives under [`scrt4/`](./scrt4). It is AGPL-3.0, hardware-bound, under 10 MB end-to-end, and runs the same way on macOS, Linux, and WSL.

### How the key works

scrt4 derives your vault key from your hardware authenticator via the WebAuthn PRF extension (CTAP2 `hmac-secret`). The key is re-derived every session and never leaves the device.

Supported authenticators:

- **YubiKey 5 series** — firmware 5.2.3+ (YubiKey 4 / NEO do not support `hmac-secret`)
- **Trezor Safe 3 / Safe 5 / Model T** on recent firmware
- **OnlyKey**
- **Phone passkeys** via caBLE — iPhone and Android
- **Apple passkeys, Bitwarden, 1Password, Google Password Manager** — any software authenticator that speaks PRF

No passwords. No TOTP. Lose the authenticator → see the recovery section below.

### How the vault works

- **AES-256-GCM** authenticated encryption at rest
- Decrypted only in daemon memory during an active session; never written unencrypted
- The daemon scrubs every stored value from subprocess stdout before returning it to the calling agent
- `scrt4 view` opens a Zenity GUI dialog — values render in the OS window system where a CLI agent cannot read them

### Install

```bash
curl -fsSL https://install.llmsecrets.com/native | sh
```

Auto-detects OS and architecture, pulls SHA256-verified binaries from GitHub Releases, and installs a systemd user unit (Linux) or launchd plist (macOS). No Docker required. Full install options and per-OS details at **<https://llmsecrets.com/downloads>**.

### Use

```bash
scrt4 setup                        # one-time FIDO2 enrollment
scrt4 unlock                       # default 20-hour session
scrt4 import path/to/.env          # pull in an existing .env file
scrt4 add API_KEY=sk-live-...      # or add one at a time
scrt4 list                         # see names (never values)
scrt4 run 'cmd $env[NAME]'         # agent-safe execution
scrt4 view                         # GUI-only view/edit
scrt4 verify-self                  # check binary against the published manifest
scrt4 backup-key --save /usb/path  # export an encrypted recovery file
scrt4 llm                          # emit an llms.txt-style capability dump
scrt4 help                         # full command reference
```

See [`scrt4/README.md`](./scrt4/README.md) for the complete command reference, [`scrt4/ARCHITECTURE.md`](./scrt4/ARCHITECTURE.md) for the daemon / module / TCB split, and [`scrt4/SECURITY.md`](./scrt4/SECURITY.md) for the threat model.

### Client-side encrypted Drive backup (cloud-crypt)

Losing the authenticator without a backup means losing the vault. The recommended backup path is **your own Google Drive, client-side encrypted**:

- **AES-256-GCM runs locally before upload.** Drive only ever receives `.scrt4` ciphertext — bytes it cannot decrypt.
- **Your master key never leaves the device.** The storage provider sees filenames and sizes; everything else is opaque.
- **Bring your own Drive.** OAuth is scoped to `drive.file` — cloud-crypt can only read/write files it creates itself, nothing else in your account.
- **No server side.** There is no llmsecrets.com account, no hosted vault, no "forgot your key?" flow. Drive is your backend because Drive is yours.

Setup is three commands after `scrt4 unlock`:

```bash
scrt4 cloud-crypt auth setup --from-gws        # one-time Drive-scoped OAuth
scrt4 backup-key --save /media/usb             # password-protected master-key export
scrt4 cloud-crypt encrypt-and-push ~/.scrt4/vault.enc
```

Restoring on a new machine: install scrt4, `scrt4 setup` to enroll a new authenticator, `scrt4 recover <backup-file>` to re-import the master key, then `scrt4 cloud-crypt pull-and-decrypt <driveId>` to pull the encrypted vault back down.

The module ships in the native installer by default. Works with any Google account (personal, Workspace) and with software authenticators too — you don't need a hardware key to use cloud-crypt, but you do need one to unlock the vault itself. Full walkthrough: [`scrt4/modules/cloud-crypt/README.md`](./scrt4) and the [docs site](https://docs.llmsecrets.com/#cloud-crypt).

### Modules

Modules extend scrt4 without expanding the trusted computing base. The native installer ships `cloud-crypt`, `encrypt-folder`, and `import-env` by default; the rest are explicit opt-in via `--module NAME`.

- **`cloud-crypt`** — client-side encrypted Google Drive backup (see section above).
- **`encrypt-folder`** — encrypt any directory to a standalone `.scrt4` archive using the same vault key.
- **`import-env`** — parse an existing `.env` (including `export KEY=value`, quoted values, and `#` comments) into the vault.
- **Additional modules** (`github`, `gcp`, `stripe`, `dns`, …) — whitelisted in [`scrt4/install/modules-whitelist.json`](./scrt4/install/modules-whitelist.json) and SHA256-verified at install time. Run `scrt4 modules list` to see what's loaded in your install.

### Recovery

- `scrt4 backup-key --save <dir>` — writes a password-protected export of the master key. Store it on a USB you trust or in your password manager.
- `scrt4 cloud-crypt encrypt-and-push ~/.scrt4/vault.enc` — pushes the encrypted vault to your Google Drive (see [Client-side encrypted Drive backup](#client-side-encrypted-drive-backup-cloud-crypt)). Restoring requires both the backup key *and* your Drive access.
- No authenticator + no backup = no recovery, by design. There is no server-side reset because there is no server-side anything.

### Uninstall

```bash
curl -fsSL https://install.llmsecrets.com/uninstall | sh
```

Removes the daemon, CLI, and session data. The encrypted vault at `~/.scrt4/` stays on disk until you delete it.

---

## What this buys you

One month of Claude Code sessions with scrt running, recorded from the author's own workstation:

| | Count |
|---|---|
| Secret injections (`$env[NAME]` substitutions) | **1,508** |
| Distinct secrets used across deployments, blockchain, infra, APIs | 24 |
| Secret values that reached the model's context | **0** |
| Secret values that landed in shell history or logs | **0** |

The trust equation is simple: if the AI cannot see a value, it cannot leak a value. Because the security model is sound, work an operator would otherwise never delegate — mainnet contract deploys, Vercel production pushes, DocuSeal template swaps on a live server — becomes automatable.

---

## Deprecated: the original LLM Secrets stack

The top-level directories below predate scrt4 and are preserved for users who haven't migrated yet. They are **no longer actively developed.** New installs should use scrt4.

| Directory | What it is | Status |
|---|---|---|
| [`cli/`](./cli) | PowerShell CLI for Windows (`scrt.ps1`) | Deprecated — use `scrt4` |
| [`crypto-core/`](./crypto-core) | Windows Hello AES-256-CBC crypto module | Deprecated — scrt4 uses FIDO2 + AES-256-GCM |
| [`desktop-app/`](./desktop-app) | Electron app (TOTP + license-gated) | Deprecated — scrt4 is daemon + CLI |
| [`wsl-daemon/`](./wsl-daemon) | Original WSL bridge | Deprecated — scrt4 ships its own daemon |

A full pre-merge snapshot of just these legacy components lives on the [`archive/legacy-stack`](https://github.com/llmsecrets/llm-secrets/tree/archive/legacy-stack) branch.

**Why replaced?**
1. **FIDO2 > Windows Hello + TOTP.** scrt4's key is hardware-bound via `hmac-secret` and portable across devices. The original stack relied on platform-specific biometric APIs and a TOTP secondary.
2. **AGPL everywhere.** Both scrt4 and the legacy stack are now AGPL-3.0, but scrt4 was built open from day one with no license gating in the install path.
3. **Cross-platform parity.** scrt4 runs the same way on macOS, Linux, and WSL. The original stack had divergent behavior across platforms.

We'll keep the legacy directories in `main` indefinitely so existing users can self-host and migrate on their own schedule. Only security fixes are accepted against them.

---

## Trust & verification

- **Downloads page** — <https://llmsecrets.com/downloads> lists every release with per-platform install commands and the current published SHA256 checksums.
- **Two-hosts, one-hash for the installer script** — the same `scrt4-native.sh.sha256` is served from `install.llmsecrets.com/native.sha256` and committed at [`scrt4/install/scrt4-native.sh.sha256`](./scrt4/install/scrt4-native.sh.sha256). Both must match before piping to `sh`; tampering either source alone fails the check.
- **Release manifest** — <https://install.llmsecrets.com/releases/latest.txt> points to the current tag; each tag directory has a `SHA256SUMS` over every daemon binary and the bash CLI.
- **Self-verification** — a running scrt4 can check its own bytes against the published manifest with `scrt4 verify-self`.
- **Reproducible layout** — the scrt4 working tree (source, bash modules, install scripts, docs) is about 1.5 MB. "Under 10 MB" is the conservative public claim; you can audit the CLI (~2,800 lines of core bash + ~900 LoC per module) and the daemon (Rust, <2k LoC) line by line.

### Checksums

Current release: **`v0.2.14-community`** ([live pointer](https://install.llmsecrets.com/releases/latest.txt))

Installer script (served at `install.llmsecrets.com/native`):

```
21402a9cf89078680a1530094d216cfa6563c7a03480754da1731ed0ab9cf5cc  scrt4-native.sh
```

Release binaries (served at `install.llmsecrets.com/releases/v0.2.14-community/SHA256SUMS`):

```
92b187282dda56e5a2afda9536cee11f3331e688aa8dd210b10b4ae80f076e01  scrt4-daemon-darwin-aarch64
e78c5b8c9d2493e6f86f4f518f6cc8080c5c45fd4a0582c4e85d1554d8607666  scrt4-daemon-linux-aarch64
5bd23e4b4ce53adea302202b55badd416d30ad9cfd535a4704e0ff729f25f16b  scrt4-daemon-linux-x86_64
bd8973080414d3e9388feb1d492da968253475a41f985377127902195401e6fb  scrt4
```

These hashes bump every release. The authoritative live sources:

| What | URL |
|---|---|
| Installer hash (host 1) | `https://install.llmsecrets.com/native.sha256` |
| Installer hash (host 2) | `https://raw.githubusercontent.com/llmsecrets/llm-secrets/main/scrt4/install/scrt4-native.sh.sha256` |
| Current release tag | `https://install.llmsecrets.com/releases/latest.txt` |
| Release binaries manifest | `https://install.llmsecrets.com/releases/<tag>/SHA256SUMS` |

Verify the installer before running it:

```bash
EXPECTED=$(curl -fsSL https://install.llmsecrets.com/native.sha256)
PUBLISHED=$(curl -fsSL https://raw.githubusercontent.com/llmsecrets/llm-secrets/main/scrt4/install/scrt4-native.sh.sha256)
ACTUAL=$(curl -fsSL https://install.llmsecrets.com/native | sha256sum | awk '{print $1}')
[ "$EXPECTED" = "$PUBLISHED" ] && [ "$EXPECTED" = "$ACTUAL" ] && echo OK
```

All three must match. Any divergence = stop.

### AI-assisted audit

Don't want to read 2,000 lines of Rust yourself? [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/llmsecrets/llm-secrets) indexes this repo and answers questions like *"Does the daemon ever write secret values to disk?"* or *"How is the master key derived?"* against the actual source.

---

## Contributing

- Issues and PRs against [`scrt4/`](./scrt4) are welcome.
- Security issues: email `security@llmsecrets.com` or open a private security advisory on this repo. Do not file public issues for vulnerabilities.
- The legacy top-level directories (`cli/`, `desktop-app/`, etc.) are in maintenance mode — only security patches are accepted.
- There is no external audit yet. One is planned for 2026; community review is explicitly invited in the meantime.

## License

AGPL-3.0. See [`LICENSE`](./LICENSE) and [`legal/SOFTWARE-LICENSE.md`](./legal/SOFTWARE-LICENSE.md) for the full text and commercial-use notes.
