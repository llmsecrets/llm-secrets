# scrt4 — Hardware-Bound Secret Manager

**Protect your secrets with FIDO2/WebAuthn.** No passwords, no TOTP — your hardware authenticator IS the key.

scrt4 encrypts environment secrets with AES-256-GCM and gates access behind FIDO2 WebAuthn PRF. AI coding assistants can *use* your secrets (via `$env[NAME]` injection) without ever *seeing* them.

[![WSL/Linux](https://img.shields.io/badge/WSL-Linux-FCC624?logo=linux)](https://github.com/llmsecrets/llm-secrets)
[![License: Source Available](https://img.shields.io/badge/License-Source%20Available-green)](LICENSE)

## How It Works

```
+--------------+     +---------------+     +---------------+
| Your Command | --> | scrt4 injects | --> | Command runs  |
| (no secrets) |     | $env[NAME]    |     | with secrets  |
+--------------+     +---------------+     +---------------+
```

Secret values exist ONLY in the subprocess environment. They are never written to disk unencrypted or returned to the AI.

## Quick Start

```bash
# Build and install from source — see ../BUILD.md for the full walkthrough
cd daemon && cargo build --release && cd ..
bash scripts/build-scrt4.sh core-only ~/.local/bin/scrt4

# Setup (registers your passkey/YubiKey — one time only)
scrt4 setup

# Unlock (authenticates via WebAuthn — scan QR with phone, tap)
scrt4 unlock

# Add secrets
scrt4 add API_KEY=sk-live-...

# Use secrets in commands (AI-safe — values never exposed)
scrt4 run 'curl -H "Authorization: Bearer $env[API_KEY]" https://api.example.com'

# View/edit secrets in GUI (invisible to AI agents)
scrt4 view
```

## Commands

| Command | Description |
|---------|-------------|
| `scrt4 setup` | Register hardware authenticator (passkey/YubiKey) |
| `scrt4 unlock [seconds]` | Authenticate and start session (default 20h) |
| `scrt4 status` | Check session status |
| `scrt4 list [--tags]` | List secret names (with optional tags) |
| `scrt4 add KEY=value` | Add a secret |
| `scrt4 run [--cwd DIR] 'cmd $env[KEY]'` | Run command with secret injection, in the current directory |
| `scrt4 view` | View/edit secrets in GUI |
| `scrt4 backup-vault` | Backup encrypted vault to tar.gz |
| `scrt4 backup-key [--save DIR]` | Show or save master key (requires auth) |
| `scrt4 recover <backup.json>` | Recover from encrypted master key backup |
| `scrt4 backup-guide` | Show backup & recovery guide |
| `scrt4 extend [seconds]` | Reset session timer |
| `scrt4 logout` | Lock / clear session |
| `scrt4 help` | Full command list |

## Security Model

| Property | Detail |
|----------|--------|
| **Auth** | FIDO2/WebAuthn PRF — hardware-bound, no passwords |
| **Encryption** | AES-256-GCM (authenticated encryption) |
| **Master key** | Derived via FIDO2 `hmac-secret` — never leaves the authenticator |
| **At rest** | All secrets encrypted in `~/.scrt4/` vault |
| **In transit** | Auth relay uses encrypted blobs only (server never sees plaintext) |
| **AI protection** | Secret values injected into subprocess env only, never returned to LLM |
| **Human protection** | View command uses GUI dialog (invisible to terminal/agents) |
| **Audit** | JSONL audit log of all secret access |

## Architecture

Three layers, deliberately separated:

- **Crypto core** — the Rust daemon in `daemon/src/`. Owns the vault, runs the
  WebAuthn ceremony, injects secrets into subprocesses. Everything
  security-relevant happens here.
- **OS layer** — a thin client per platform, speaking JSON-RPC to the daemon
  over a Unix socket or a Windows named pipe. `daemon/bin/` is the bash client;
  `windows/` is the PowerShell one.
- **Modules** — optional feature surface. Not part of this repository.

Clients never touch vault crypto, so the surface you need to trust is the
daemon alone.

`scripts/build-scrt4.sh` assembles the bash client by concatenating
`daemon/bin/scrt4-core` with whichever modules a distribution names. This
repository ships the `core-only` distribution, which names none.

See [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).

## Docker

```bash
# Build
docker build -t scrt4 .

# Run against a persistent vault volume
docker run -it -v scrt4-vault:/home/scrt/.scrt4 scrt4 shell
```

There is no published image; build from this tree so you know what you are
running.

## Building from Source (without Docker)

### Daemon (Rust)

```bash
cd daemon
cargo build --release
# Binary: target/release/scrt4-daemon
```

### CLI

```bash
scripts/build-scrt4.sh core-only /usr/local/bin/scrt4
```

The build script reads `modules.manifest`, validates module headers, and
concatenates `daemon/bin/scrt4-core` + whichever modules the named
distribution lists into a single executable bash script. `core-only` lists
none, which is what this repository ships.

### Windows

The PowerShell client lives in `windows/`. See [../BUILD.md](../BUILD.md) for
the install layout — in particular, `scrt4.cmd` is the entry point on `PATH`,
not a `.ps1`.

## Recovery

scrt4 uses FIDO2/WebAuthn — your hardware authenticator derives the master key on every unlock. There are no passwords to remember.

| Scenario | What to do |
|----------|------------|
| **You have your authenticator** | Just run `scrt4 unlock` — nothing to recover |
| **Authenticator lost, have backup** | `scrt4 recover backup.json` with the password you set during `backup-key --save` |
| **No authenticator, no backup** | Secrets are **irrecoverable by design**. No backdoor exists. |

Always run `scrt4 backup-key --save /path/to/USB` after setup and store it safely.

## Releases

Build from source for now — see [../BUILD.md](../BUILD.md). A hosted channel
serving builds of this repository is being set up; until it exists, building
from the source you can read is the only install path we will point you at.

## License

Source Available — see [LICENSE](LICENSE) for terms.

---

Made with care for developers who value their secrets.
