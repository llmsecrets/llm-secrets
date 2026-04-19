# scrt4 — Hardware-Bound Secret Manager

**Protect your secrets with FIDO2/WebAuthn.** No passwords, no TOTP — your hardware authenticator IS the key.

scrt4 encrypts environment secrets with AES-256-GCM and gates access behind FIDO2 WebAuthn PRF. AI coding assistants can *use* your secrets (via `$env[NAME]` injection) without ever *seeing* them.

[![WSL/Linux](https://img.shields.io/badge/WSL-Linux-FCC624?logo=linux)](https://github.com/VestedJosh/scrt4)
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
# Install (verify the installer hash first, then run it)
curl -fsSL https://install.llmsecrets.com/native -o scrt4-native.sh \
  && sha256sum scrt4-native.sh \
  && sh scrt4-native.sh

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
| `scrt4 run 'cmd $env[KEY]'` | Run command with secret injection |
| `scrt4 view` | View/edit secrets in GUI |
| `scrt4 share` | Share secrets to another machine (wormhole) |
| `scrt4 receive` | Receive shared secrets |
| `scrt4 encrypt-folder <path>` | Encrypt a folder to `.scrt4` archive |
| `scrt4 decrypt-folder <archive>` | Decrypt a `.scrt4` archive |
| `scrt4 backup-vault` | Backup encrypted vault to tar.gz |
| `scrt4 backup-key [--save DIR]` | Show or save master key (requires auth) |
| `scrt4 recover <backup.json>` | Recover from encrypted master key backup |
| `scrt4 backup-guide` | Show backup & recovery guide |
| `scrt4 extend [seconds]` | Reset session timer |
| `scrt4 logout` | Lock / clear session |
| `scrt4 menu` | Open GUI menu |
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

scrt4 has two versions available:

### v0.1.0 — Stable monolith

The original single-file CLI. Battle-tested, ships as `Dockerfile.hardened`.

- Single 4,400-line bash script + Rust daemon
- All features in one file
- Published to Docker Hub as `joshgottlieb/scrt4-hardened:latest`

### v0.2 — Modular architecture

The new modular build. Backwards-compatible (40/40 tests pass against v0.1.0). Ships as `Dockerfile.modular`.

- `scrt4-core` (trusted computing base) + pluggable module files
- 2 distributions: **hardened** (12 modules) and **core-only** (0 modules)
- Build system: `scripts/build-scrt4.sh` reads `modules.manifest` and assembles a single executable
- Published to Docker Hub as `joshgottlieb/scrt4-hardened:v0.2-modular`

Both versions use the same Rust daemon and the same vault format. You can switch between them without losing secrets.

See [ARCHITECTURE-V0.2.md](docs/ARCHITECTURE-V0.2.md) for full details.

## Docker

### v0.1.0 Stable (recommended)

```bash
# Pull from Docker Hub
docker pull joshgottlieb/scrt4-hardened:latest

# Or build from source
docker build -f Dockerfile.hardened -t scrt4-hardened .

# Run
docker run -it -v scrt4-vault:/home/scrt/.scrt4 scrt4-hardened shell
```

### v0.2 Modular

```bash
# Pull from Docker Hub
docker pull joshgottlieb/scrt4-hardened:v0.2-modular

# Or build from source
docker build -f Dockerfile.modular -t scrt4-modular .

# Run
docker run -it -v scrt4-vault:/home/scrt/.scrt4 scrt4-modular shell
```

### Persistent vault (all versions)

```bash
docker run -it \
  -v scrt4-vault:/home/scrt/.scrt4 \
  -v scrt4-claude:/home/scrt/.claude \
  scrt4-hardened shell
```

## Building from Source (without Docker)

### Daemon (Rust)

```bash
cd daemon
cargo build --release
# Binary: target/release/scrt4-daemon
```

### CLI (v0.2 modular)

```bash
# Assemble hardened distribution
scripts/build-scrt4.sh hardened /usr/local/bin/scrt4

# Or core-only (minimal attack surface)
scripts/build-scrt4.sh core-only /usr/local/bin/scrt4
```

The build script reads `modules.manifest`, validates module headers, and concatenates `daemon/bin/scrt4-core` + the listed modules into a single executable bash script.

### Auth Relay (self-hosted, optional)

The auth relay enables phone-based authentication. It's already deployed at `auth.llmsecrets.com`. To self-host:

```bash
cd auth-relay/relay-server
docker compose up -d
# Runs Redis 7 + Node.js relay on port 4100
```

Set `RELAY_BACKEND_URL` in the Vercel frontend to point to your relay.

## Recovery

scrt4 uses FIDO2/WebAuthn — your hardware authenticator derives the master key on every unlock. There are no passwords to remember.

| Scenario | What to do |
|----------|------------|
| **You have your authenticator** | Just run `scrt4 unlock` — nothing to recover |
| **Authenticator lost, have backup** | `scrt4 recover backup.json` with the password you set during `backup-key --save` |
| **No authenticator, no backup** | Secrets are **irrecoverable by design**. No backdoor exists. |

Always run `scrt4 backup-key --save /path/to/USB` after setup and store it safely.

## Release History

| Version | Tag | Status | Image |
|---------|-----|--------|-------|
| v0.1.0 | `v0.1.0` | Stable | `joshgottlieb/scrt4-hardened:latest` |
| v0.2.0 | `architecture/v0.2.0` | Ready | `joshgottlieb/scrt4-hardened:v0.2-modular` |
| v0.2.14-community | `v0.2.14-community` | Current | Native binaries — see [llmsecrets.com/downloads](https://llmsecrets.com/downloads) |

The current installer resolves the latest tag at runtime from [`install.llmsecrets.com/releases/latest.txt`](https://install.llmsecrets.com/releases/latest.txt); checksums live at `install.llmsecrets.com/releases/<tag>/SHA256SUMS`.

## License

Source Available — see [LICENSE](LICENSE) for terms.

---

Made with care for developers who value their secrets.
