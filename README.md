# LLM Secrets — scrt4

**Your AI coding agent can use your secrets without ever seeing them.**

When an agent reads your `.env`, every API key and database password lands in
its context window. scrt4 keeps the values out of that window entirely: the
agent writes `$env[STRIPE_SECRET_KEY]`, and the value is injected directly into
the subprocess environment by a daemon the agent cannot read.

```
✓ the agent sees:     $env[STRIPE_SECRET_KEY]
✗ the agent never sees: sk_live_...
```

The vault is encrypted with AES-256-GCM under a key derived from your hardware
authenticator via the WebAuthn PRF extension (CTAP2 `hmac-secret`). No password.
No server. The key is re-derived each session and never leaves the device.

---

## Architecture

Three layers, deliberately separated:

| Layer | What it is | Where |
|---|---|---|
| **Crypto core** | The Rust daemon. Owns the vault, runs the auth ceremony, injects secrets into subprocesses. | `scrt4/daemon/src/` |
| **OS layer** | A thin client per platform speaking JSON-RPC to the daemon over a Unix socket or a Windows named pipe. | `scrt4/daemon/bin/` (bash), `scrt4/windows/` (PowerShell) |
| **Modules** | Optional feature surface. **Not part of this repository.** | — |

Clients never touch vault crypto. Everything security-relevant happens in the
daemon, so the surface you need to trust is the crypto core alone.

### How the key works

Supported authenticators:

- **YubiKey 5 series** — firmware 5.2.3+ (YubiKey 4 / NEO lack `hmac-secret`)
- **Trezor Safe 3 / Safe 5 / Model T** on recent firmware
- **OnlyKey**
- **Phone passkeys** via caBLE — iPhone and Android
- **Windows Hello**, and any software authenticator that speaks PRF — Apple
  passkeys, Bitwarden, 1Password, Google Password Manager

No passwords, no TOTP. Lose the authenticator and you need your key backup —
see [Recovery](#recovery).

### How the vault works

- **AES-256-GCM** authenticated encryption at rest
- Decrypted only in daemon memory during an active session, never written back
  in the clear
- Every stored value is scrubbed from subprocess output before it is returned
  to the calling agent
- `scrt4 view` renders values in an OS window a CLI agent cannot read

---

## Install

**Build from source.** There is no binary distribution channel for this
repository yet — see [BUILD.md](./BUILD.md).

That is a deliberate statement of fact rather than a policy: binaries exist for
internal use, but they are produced from a private tree, and pointing you at
them would mean shipping you something whose source you cannot check against
what is here. When a channel exists that serves exactly this code, it will be
documented here and nowhere else.

> **Windows:** builds you compile yourself are unsigned. SmartScreen may warn,
> and Smart App Control — if enabled — will block the binary outright with
> "An Application Control policy has blocked this file" (Event Viewer:
> `Microsoft-Windows-CodeIntegrity/Operational`, IDs 3033/3077). Code-signing
> is in progress. Until then, a debug build passes where a release build does
> not, and SAC can be disabled in Windows Security → App & browser control.

---

## Use

```bash
scrt4 setup                        # one-time authenticator enrollment
scrt4 unlock                       # start a session (default 20 hours)
scrt4 add STRIPE_SECRET_KEY=sk_live_...
scrt4 list                         # names only, never values
scrt4 run 'deploy.sh --key $env[STRIPE_SECRET_KEY]'
scrt4 view                         # GUI editor, values never hit stdout
scrt4 lock                         # end the session
```

`scrt4 run` is the point of the whole thing. The placeholder is substituted
inside the daemon, after your shell and after the agent's context.

---

## Recovery

There is no server-side reset, because there is no server side. Two things
recover a vault, and you need both:

1. A key backup — `scrt4 backup-key --save <dir>`
2. The recovery password you set when creating it

Take the backup now, and store it somewhere your authenticator is not.

[`disaster-recovery/`](./disaster-recovery) recovers a vault **without scrt4
installed at all** — standalone scripts for Unix and Windows, the backup format
documented field by field, and instructions for verifying your backup actually
works before you need it.

---

## Security

- Threat model and trust boundaries: [`scrt4/SECURITY.md`](./scrt4/SECURITY.md)
- Design rationale: [`scrt4/daemon/DESIGN.md`](./scrt4/daemon/DESIGN.md)

Report vulnerabilities privately via GitHub Security Advisories on this
repository rather than a public issue.

---

## Status

scrt4 is alpha. The cryptography is conservative and the audited crates are
named in `Cargo.toml`, but the integration around them is young, the Windows
port is the newest part, and it has not had an external audit.

Use it for development secrets. Think carefully before you use it for anything
whose loss you could not absorb — and if you do, take a key backup first.

---

## Contributing

Issues and pull requests welcome. Two things worth knowing before you open one:

- **Keep the daemon small.** Anything optional belongs in a client, not in the
  crypto core. A PR that grows `daemon/src/` to add a convenience feature will
  be asked to move it.
- **No new secret names in code or docs.** Configuration reads from the vault
  by name at runtime; nothing should hard-code what those names are.

## License

AGPL-3.0. See [LICENSE](./LICENSE).
