# Formal verification input — scrt4-hardened-v2

> **Audience:** the team running formal verification on the hardened distribution.

This is the entry point. Read this first; it points at everything else.

## What scrt4 is

A FIDO2/WebAuthn-gated secret manager. Vault encrypted with AES-256-GCM under a key derived from the authenticator's hmac-secret extension. Daemon holds decrypted secrets in memory only; CLI reaches them through a Unix-domain socket. Secret values are injected into subprocess environments via a `$env[NAME]` substitution pattern and are never returned to the LLM or to stdout.

The product `scrt4-hardened` is the Docker distribution. `scrt4-hardened-v2` is the future version that this verification effort will produce a proof for.

## What you need to verify

The high-level claims are in `docs/TCB.md` § "Invariants we want proven". In short:

1. Vault confidentiality at rest
2. Key never persisted
3. Session unforgeable
4. Reveal gated
5. Output redaction complete
6. Subprocess injection safe
7. Relay messages authenticated
8. No cross-distribution vault unseal

## What's in scope

Every file listed in `docs/TCB.md` § "What's in scope". You can re-derive the list at any time with:

```sh
grep -rn '^// TCB:\|^# TCB:' daemon/
```

The grep result is intended to match the table in `TCB.md` byte-for-byte. If they diverge, that is a bug — please open an issue.

## What's out of scope

Everything in `docs/TCB.md` § "What's out of scope". Modules under `daemon/bin/scrt4-modules/` are explicitly out — they declare `tcb: false` in their header and the build script rejects modules that try to declare `tcb: true` without a review label.

## Threat model

Summarized in `docs/TCB.md` § "Threat model". Full version in `SECURITY.md`. The TL;DR for the prover:

- The daemon process is trusted (memory inspection by root is not in scope)
- The authenticator is trusted (compromised passkey + stolen disk = compromise, by design)
- The CLI process is trusted to the extent that it is the only thing that talks to the daemon socket (Unix permissions enforce this)
- The user's terminal is **untrusted with respect to AI agents** — an agent may be reading the screen and crafting commands. Secret values must never reach the screen.

## How to clone and build

```sh
git clone https://github.com/VestedJosh/scrt4
cd scrt4
git checkout v0.1.0                                    # current release
git checkout architecture/v0.2.0                       # the v0.2 architecture (this work)

# build any of the v0.2 distributions
scripts/build-scrt4.sh hardened   /tmp/scrt4-hardened-v2
scripts/build-scrt4.sh core-only  /tmp/scrt4-core-only
```

The Rust daemon is in `daemon/src/`. Build with `cd daemon && cargo build --release`.

## What's available right now

- `docs/TCB.md` — full inventory and invariants
- `docs/ARCHITECTURE-V0.2.md` — how the new layout works
- `daemon/bin/scrt4-core` — extracted core CLI (the in-scope portion of the v0.1.0 monolith)
- `daemon/src/*.rs` — daemon source, unchanged from v0.1.0 in this scaffold
- `SECURITY.md` — disclosure policy + full threat model

## What's coming

- `// TCB:` annotations across `daemon/src/handlers.rs` (per-handler classification)
- A CI guard that fails any PR which modifies a TCB file without a TCB-review label
- Vault format magic byte enforcing no cross-distribution unseal (invariant #8)

These are tracked in issues #60, #61.

## Contact

- For questions about the TCB scope: open a comment on issue #60
- For vulnerabilities: `security@llmsecrets.com` (per `SECURITY.md`)
- For everything else: open an issue on `github.com/VestedJosh/scrt4`
