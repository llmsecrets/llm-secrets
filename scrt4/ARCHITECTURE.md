# scrt4 — Architecture

> **If you are looking for the current architecture,** see
> [`docs/ARCHITECTURE-V0.2.md`](docs/ARCHITECTURE-V0.2.md). That document
> describes the **Core vs Modules** split, the three distributions
> (hardened, dev, core-only), and the terminology used across the
> codebase. This document describes the v0.1.0 monolith (still shipping
> from `main` as the hardened release). Work in progress is on branch
> `architecture/v0.2.0`.

## v0.1.0 Overview

scrt4 v0.1.0 uses **FIDO2/WebAuthn PRF** for hardware-bound authentication. No passwords, no TOTP — your hardware authenticator IS the key.

| Property | Value |
|----------|-------|
| Auth | FIDO2/WebAuthn PRF (passkey, YubiKey, phone via caBLE) |
| Encryption | AES-256-GCM (authenticated encryption) |
| Socket | `scrt4.sock` |
| Config | `~/.scrt4/` |
| Master key | PRF-derived from hardware authenticator (never leaves device) |

---

## Directory Map

```
scrt4/                              ← repo root
│
├── ARCHITECTURE.md                 ← YOU ARE HERE
├── README.md                       Product overview
├── LICENSE                         Source Available license
│
├── daemon/                         Rust daemon + Bash CLI
│   ├── Cargo.toml                  Package: scrt4-daemon v0.1.0
│   ├── Cargo.lock                  Dependency lockfile
│   ├── DESIGN.md                   Internal design notes
│   ├── TODO.md                     Development roadmap
│   ├── bin/
│   │   └── scrt4                   Bash CLI (2600+ lines, WebAuthn PRF)
│   └── src/
│       ├── main.rs                 Daemon entry — Axum server on scrt4.sock
│       ├── handlers.rs             JSON-RPC request dispatcher
│       ├── keystore.rs             AES-256-GCM vault (encrypt/decrypt secrets)
│       ├── session.rs              In-memory session + TTL management
│       ├── webauthn.rs             FIDO2/WebAuthn PRF credential handling
│       ├── localhost.rs            Localhost browser auth flow (Axum HTTP)
│       ├── remote.rs               Remote/relay auth flow (phone via caBLE)
│       ├── protocol.rs             JSON-RPC message types
│       ├── subprocess.rs           $env[NAME] injection + output redaction
│       ├── sanitize.rs             Output leak detection
│       ├── audit.rs                JSONL audit logging
│       └── cli.rs                  CLI argument parsing helpers
│
├── auth-relay/                     Two-tier WebAuthn relay infrastructure
│   ├── vercel.json                 Vercel routing config
│   ├── package.json                Vercel project metadata
│   ├── .gitignore
│   ├── api/                        Vercel serverless functions (frontend proxy)
│   │   ├── relay/
│   │   │   ├── [id].js             POST/GET encrypted auth blobs → proxies to GCP relay
│   │   │   ├── shorten.js          Generate short codes for session IDs
│   │   │   └── resolve/
│   │   │       └── [code].js       Resolve short codes → session IDs
│   │   └── s/
│   │       └── [code].js           Server-side redirect: /s/k7x9 → auth.html?s=SESSION_ID
│   ├── public/
│   │   ├── auth.html               WebAuthn/passkey authentication UI (PRF extension)
│   │   └── index.html              Landing page
│   └── relay-server/               Self-hosted backend (replaces Vercel Edge Config)
│       ├── index.js                Node.js relay — Redis-backed blob store, port 4100
│       ├── package.json            Dependencies (express, ioredis)
│       ├── Dockerfile              Node.js container
│       └── docker-compose.yml      Redis 7 Alpine + Node.js relay
│
└── legal/                          License terms
```

---

## Auth Relay Architecture

The relay enables cross-device authentication (e.g., unlock WSL from your phone).

```
┌─────────────┐     poll      ┌──────────────────────────┐     proxy     ┌─────────────────────────┐
│  scrt4 CLI  │ ◄──────────── │  Vercel Frontend         │ ◄──────────── │  Self-Hosted GCP Relay  │
│  (WSL)      │               │  llmsecrets-auth.vercel  │               │  Redis + Node.js        │
└─────────────┘               │  .app                    │               │  Port 4100, 2-min TTL   │
                              └──────────────────────────┘               └─────────────────────────┘
                                        ▲                                          ▲
                                        │ auth.html                                │ POST blob
                                        │                                          │
                              ┌──────────────────────────┐               ┌─────────────────────────┐
                              │  Browser (phone/desktop)  │ ─────────── │  WebAuthn Authenticator  │
                              │  auth.llmsecrets.com      │  passkey    │  (YubiKey/phone/etc.)    │
                              └──────────────────────────┘               └─────────────────────────┘
```

**Flow:**
1. CLI starts unlock → generates session ID → shows QR code (or opens localhost browser)
2. User scans QR / opens link → `auth.html` loads in browser
3. Browser triggers WebAuthn with PRF extension → authenticator returns PRF output
4. Browser POSTs encrypted blob to relay (via Vercel proxy → GCP Redis)
5. CLI polls relay, receives blob, derives master key from PRF output
6. Session active — secrets unlocked

**Why two tiers?**
- CLI polls from `llmsecrets-auth.vercel.app` (bypasses corporate network filters)
- Browser hits `auth.llmsecrets.com` (Vercel domain with custom DNS)
- Self-hosted Redis on GCP gives full control — encrypted blobs only, 2-minute TTL, no third-party data retention

**GCP deployment:** `prod-repo-app-instance-v001` (us-east4-c), path `/home/jgott/scrt4-relay/`, Docker Compose (Redis 7 Alpine + Node.js)

---

## Installed Binaries

The repo contains source code. Built/installed binaries live at:

| Component | Location |
|-----------|----------|
| CLI | `~/.local/bin/scrt4` |
| Daemon | `~/.local/bin/scrt4-daemon` |
| Client | `~/.local/bin/scrt-client` |
| Config | `~/.scrt4/` |

---

## Git Tags

| Tag | Description |
|-----|-------------|
| `v0.1.0-webauthn` | Last commit with legacy code still in repo (scrt v1, scrt3, desktop app) |
