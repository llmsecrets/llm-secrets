# LLM Secrets

> **Protect your `.env` secrets from AI coding assistants.** Claude, Cursor, and other agents can *use* your secrets without ever *seeing* them.

[![Downloads](https://img.shields.io/badge/Downloads-llmsecrets.com-2563eb)](https://llmsecrets.com/downloads)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-green)](LICENSE)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/llmsecrets/llm-secrets)

**The active code lives under [`scrt4/`](./scrt4).** It is AGPL-3.0,
hardware-bound, under 10 MB end-to-end, and runs the same way on macOS,
Linux, Windows, and WSL.

| Platform | Support |
|---|---|
| **macOS** | Apple Silicon native; Intel via Rosetta 2 |
| **Linux** | `x86_64` and `aarch64` — glibc 2.34+ (Ubuntu 22.04+, Debian 12+, RHEL 9+) |
| **Windows** | PowerShell 5.1+, native — the daemon speaks a named pipe rather than a Unix socket |
| **WSL** | Same build as Linux |

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

Build from source. It takes one command each for the daemon and the client,
and it means the bytes you run came from the source you can read:

```bash
git clone https://github.com/llmsecrets/llm-secrets.git
cd llm-secrets/scrt4/daemon && cargo build --release && cd ..
bash scripts/build-scrt4.sh core-only ~/.local/bin/scrt4
```

Full walkthrough, including Windows, in **[BUILD.md](./BUILD.md)**.

Prebuilt Linux and macOS binaries of *this* repository are now published, and
every one is checksum-verified before it is installed:

```bash
SCRT4_VERSION=v0.4.3 curl -fsSL https://install.llmsecrets.com/native | sh
```

The version is pinned on purpose. The default (unpinned) install still resolves
to an older build from a different tree, and it will keep doing so until that
channel is switched over — so until then, naming the version is the difference
between getting this source and getting something else.

Once installed, `scrt4 upgrade` handles subsequent updates.

### Use

```bash
scrt4 setup                        # one-time FIDO2 enrollment
scrt4 unlock                       # default 20-hour session
scrt4 add API_KEY=sk-live-...      # add a secret
scrt4 list                         # see names (never values)
scrt4 run 'cmd $env[NAME]'         # agent-safe execution
scrt4 view                         # GUI-only view/edit
scrt4 lock                         # end the session early
scrt4 upgrade                      # install the published release (SHA256-verified)
scrt4 verify-self                  # check binary against the published manifest
scrt4 backup-key --save /usb/path  # export an encrypted recovery file
scrt4 llm                          # emit an llms.txt-style capability dump
scrt4 help                         # full command reference
```

See [`scrt4/README.md`](./scrt4/README.md) for the complete command reference, [`scrt4/ARCHITECTURE.md`](./scrt4/ARCHITECTURE.md) for the daemon / module / TCB split, and [`scrt4/SECURITY.md`](./scrt4/SECURITY.md) for the threat model.

### Recovery

- `scrt4 backup-key --save <dir>` — writes a password-protected export of the master key. Store it on a USB you trust or in your password manager.
- [`disaster-recovery/`](./disaster-recovery) recovers a vault **without scrt4 installed at all** — the backup format documented field by field, and standalone scripts for Unix and Windows that depend only on OpenSSL or .NET.
- No authenticator + no backup = no recovery, by design. There is no server-side reset because there is no server-side anything.

### Uninstall

```bash
sh scrt4/install/scrt4-uninstall.sh
```

Removes the daemon, CLI, and session data. The encrypted vault at `~/.scrt4/`
stays on disk until you delete it.

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

## Trust & verification

- **Build it yourself** — the strongest verification available, and the reason
  the source layout is kept small enough to read. See [BUILD.md](./BUILD.md).
- **Installer hash in-tree** — [`scrt4/install/scrt4-native.sh.sha256`](./scrt4/install/scrt4-native.sh.sha256)
  is committed alongside the script it covers, so the installer can be checked
  against the repository before it is run.
- **Reproducible layout** — the scrt4 working tree (source, bash modules, install scripts, docs) is about 1.5 MB. "Under 10 MB" is the conservative public claim; you can audit the CLI (~2,800 lines of core bash) and the daemon (Rust, <2k LoC) line by line.

### Self-verification

A binary that can be tampered with between the build and your disk is only as
trustworthy as the last hop. `scrt4 verify-self` closes that gap: it hashes
**the file that is actually executing** — not whatever `scrt4` happens to
resolve to on `$PATH` — and compares it against the manifest published for its
own version.

```console
$ scrt4 verify-self
Verifying scrt4 binary: /home/you/.local/bin/scrt4
Expected version: 0.4.3
Local hash:    d0f3a830a532020eebfae718a627e238a72f72e0751e6bebd18edde3c532d2b6
Fetching:      https://install.llmsecrets.com/releases/v0.4.3/SHA256SUMS
Expected hash: d0f3a830a532020eebfae718a627e238a72f72e0751e6bebd18edde3c532d2b6
✓ Match — this binary is the published 0.4.3 release.
```

It exits non-zero on a mismatch, so it works in a script or a CI step.

A mismatch is not automatically an attack. The three ordinary causes, in
rough order of likelihood: you built from source and are running your own
binary; `$PATH` resolves to a different copy than you think; or the release
was re-cut. It is worth understanding which before assuming the worst.

The same manifest is what `scrt4 upgrade` checks before it replaces anything,
so an install that fails verification will not silently become one that
passes.

### AI-assisted audit

Don't want to read 2,000 lines of Rust yourself? [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/llmsecrets/llm-secrets) indexes this repo and answers questions like *"Does the daemon ever write secret values to disk?"* or *"How is the master key derived?"* against the actual source.

---

## The original LLM Secrets stack

Four components predate scrt4 — the PowerShell CLI (`cli/`), the Windows Hello
crypto module (`crypto-core/`), the Electron app (`desktop-app/`) and the WSL
bridge (`wsl-daemon/`). All are replaced by the daemon and its clients, receive
no security fixes, and now live on the
[`archive/legacy-stack`](https://github.com/llmsecrets/llm-secrets/tree/archive/legacy-stack)
branch so that what you check out is what is maintained. If you still run one,
migrate.

They were replaced because the key should be hardware-bound rather than tied to
a platform biometric API with a TOTP secondary, and because the behaviour should
not differ per operating system. The archive branch is kept indefinitely.

## Contributing

- Issues and PRs against [`scrt4/`](./scrt4) are welcome.
- Security issues: email `security@llmsecrets.com` or open a private security advisory on this repo. Do not file public issues for vulnerabilities.
- There is no external audit yet. One is planned for 2026; community review is explicitly invited in the meantime.

## License

AGPL-3.0. See [`LICENSE`](./LICENSE) and [`legal/SOFTWARE-LICENSE.md`](./legal/SOFTWARE-LICENSE.md) for the full text and commercial-use notes.
