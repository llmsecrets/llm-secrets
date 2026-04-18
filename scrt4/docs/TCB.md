# scrt4 trusted computing base (TCB)

> **Status:** v0.2 inventory. Lives on branch `architecture/v0.2.0`. The v0.1.0 release is unaffected — this document describes the scope for formal verification of `scrt4-hardened-v2`.
>
> **Audience:** the formal verification team (Halmos / KLEE / equivalent), security reviewers, and any contributor about to touch one of the listed files.

## What's in scope

A bug in any item below could result in vault-confidentiality compromise, session forgery, secret leakage to disk, or unauthorized secret reveal. A bug in any item **not** below cannot.

| File | Lines | Scope | Notes |
|---|---:|---|---|
| `daemon/src/webauthn.rs` | ~700 | **Full file** | FIDO2 ceremony, hmac-secret extraction (the key derivation root), relay protocol over `auth.llmsecrets.com`. |
| `daemon/src/keystore.rs` | ~530 | **Full file** | AES-256-GCM seal/unseal of the on-disk vault. Key zeroization. Vault format. |
| `daemon/src/session.rs` | ~590 | **Full file** | Session token lifecycle, expiry, lock/clear semantics, replay resistance. |
| `daemon/src/protocol.rs` | ~200 | **Full file** | Daemon socket protocol — the message-authentication boundary between CLI and daemon. |
| `daemon/src/remote.rs` | ~400 | **Full file** | Relay client; ed25519 signatures on relay messages; nonce handling. |
| `daemon/src/main.rs` | ~100 | **Full file** | Daemon bootstrap; Unix socket setup; permission bits. |
| `daemon/src/sanitize.rs` | ~65 | **Full file** | Output redaction. A bug here leaks secrets to stdout. |
| `daemon/src/subprocess.rs` | ~155 | **Full file** | Secret injection into subprocess env. A bug here leaks secrets into argv, files, or parent env. |
| `daemon/src/localhost.rs` | ~425 | **Full file** | Localhost browser-flow auth path. Cross-process trust boundary. |
| `daemon/src/handlers.rs` | ~1000 | **Partial** — only handlers that gate secret reveal (`unlock`, `view`, `run`, `add_secrets`, `share_*`). `list`, `tag`, `add` (without view), `status`, etc. are **out** of TCB. | The largest file; per-handler annotation needed. See section below. |
| `daemon/bin/scrt4-core` (v0.2) | ~1500 (target) | **Functions marked `# TCB:`** — the auth gates, secret-pipe handlers, vault crypto handoffs. The dispatcher and feature commands are **out** of TCB. | New file in v0.2; replaces the in-scope portion of the v0.1.0 monolith. |

## What's out of scope

A bug in any item below is a normal bug — it gets fixed, but it does not affect the formal verification claims about vault confidentiality.

| File | Why out |
|---|---|
| `daemon/src/audit.rs` | Audit log records events; a bug means missing/incorrect log entries. The log is not in the auth path. |
| `daemon/src/cli.rs` | Argument parsing; user-visible errors only. |
| All v0.2 modules under `daemon/bin/scrt4-modules/` | By design — modules cannot reach into the daemon's secret state except through the protocol. The `tcb: false` header is mandatory for non-core modules and is rejected by the build script if the module file appears to call into TCB internals. One narrow exception: `cloud-crypt.sh` has a single `# TCB:` function (`_scrt4_cc_assert_ciphertext`) that enforces the ciphertext-only upload invariant. The function does no crypto; it refuses any file that does not start with the `SCRT4ENC\0` magic. This keeps the module's Drive-facing path provably plaintext-free. |
| Wallet dashboard, encrypt-folder, share/receive UX (not the crypto), menu rendering, view editor, tags, import-env | Feature surface. None of these can read a secret value without going through the daemon protocol, which itself is in scope. |
| The install wrapper (`install/scrt4-docker.sh`) | Runs on the host outside the container. Not in the scrt4 trust boundary at all. |
| The Caddy reverse-proxy serving `install.llmsecrets.com` | Distribution path; signed via TLS. Not part of the runtime trust boundary. |

## Threat model (one-page summary)

The full model lives in `SECURITY.md`. For TCB scoping:

| Adversary | Capability | Defended by |
|---|---|---|
| Malicious local user | Read/write any file as user; spawn processes; observe stdout/stderr | Vault encrypted at rest (keystore.rs); secrets never written to disk in plaintext (subprocess.rs); output redaction (sanitize.rs) |
| Malicious process with ptrace | Inspect daemon memory | Out of scope — root is root; kernel hardening is out of scope. The TCB assumes the daemon process is trusted. |
| Network adversary (passive) | Snoop network traffic | TLS to relay (remote.rs); SPAKE2 over wormhole for share/receive (out of TCB but uses the same threat-model assumption) |
| Network adversary (active) | MITM relay traffic | Ed25519 signatures pinned to a known relay key (remote.rs) |
| Stolen disk image | Read on-disk vault file | Vault is AES-GCM encrypted; key is derived from FIDO2 hmac-secret which never leaves the authenticator (keystore.rs + webauthn.rs) |
| Stolen disk + stolen authenticator | Both | Compromise. Backup key recovery requires both anyway. Out of scope for primary TCB. |
| Malicious AI agent in the same shell | Read terminal output, ask user for secret values | Output redaction (sanitize.rs); injection-only secret reveal pattern (subprocess.rs); `view` is GUI-only, never returned to stdout |
| Malicious upstream dependency | Backdoor in a Cargo dep | Out of scope. Reproducible builds + dep audit is a separate workstream. |

## Per-handler TCB classification in `daemon/src/handlers.rs`

Pending. Will be added inline as `// TCB:` comments above each in-scope handler.

Tentative classification:

| Handler | TCB |
|---|---|
| `handle_unlock` | **In** — token mint |
| `handle_status` | Out — exposes only "active/inactive + ttl"; no secret material |
| `handle_list` | Out — names only; values never touched |
| `handle_add_secrets` | **In** — writes secret values into the vault |
| `handle_view` | **In** — returns secret values to caller |
| `handle_run` | **In** — substitutes `$env[NAME]` with secret values into a subprocess env |
| `handle_tag` / `handle_untag` / `handle_tags` | Out — metadata only |
| `handle_share` (encrypt path) | **In** — exports secret material to a wormhole-bound buffer |
| `handle_logout` | **In** — must zeroize session state |
| `handle_wa_*` | **In** — toggles the WebAuthn step-up requirement |

## Source-level annotations

In every TCB file, in-scope functions carry a header in this exact format:

```rust
// TCB: <subsystem name>
// Verifies: <invariant, plain English>
// Adversary: <threat being defended against>
fn function_name(...) {
    ...
}
```

```bash
# TCB: <subsystem name>
# Verifies: <invariant>
# Adversary: <threat>
function_name() {
    ...
}
```

Grep target:
```sh
grep -rn '^// TCB:\|^# TCB:' daemon/
```

The grep should produce a complete list that matches this document. Drift is caught by a planned CI guard (issue #60 acceptance bullet 3) — not yet implemented in v0.2 scaffold; tracked.

## Invariants we want proven

These are the formal claims the verification work should target. Each maps to one or more TCB items.

1. **Vault confidentiality at rest.** No code path writes a secret value to disk in plaintext. (`keystore.rs`, `subprocess.rs`)
2. **Key never persisted.** The AES-GCM key derived from the FIDO2 hmac-secret is held in zeroizable memory and dropped at session end. (`keystore.rs`, `session.rs`)
3. **Session unforgeable.** A valid session token cannot be produced without a successful WebAuthn ceremony. (`session.rs`, `webauthn.rs`)
4. **Reveal gated.** Every code path that returns a secret value to a caller (CLI, subprocess) goes through a session-active check. (`handlers.rs` view/run/share, `scrt4-core` `_wa_gate`)
5. **Output redaction complete.** Secret values cannot reach stdout/stderr through any sanitized print path. (`sanitize.rs`)
6. **Subprocess injection safe.** `$env[NAME]` substitution puts the value in the subprocess env only — not in argv, not in the parent env, not in any file. (`subprocess.rs`)
7. **Relay messages authenticated.** The relay client refuses messages that do not carry a valid ed25519 signature from the pinned relay key. (`remote.rs`)
8. **No cross-distribution vault unseal.** A vault sealed by the hardened daemon cannot be opened by the dev daemon, and vice versa. (`keystore.rs` + planned vault format magic byte; not yet implemented)
9. **Cloud-crypt plaintext-free.** The cloud-crypt module never writes plaintext to an external endpoint. Every upload path is gated by `_scrt4_cc_assert_ciphertext`, which rejects anything missing the `SCRT4ENC\0` magic. (`daemon/bin/scrt4-modules/cloud-crypt.sh`)

Additional invariants welcome — file as a comment on issue #60.

## How this document stays current

- Every PR that touches a file in the "in scope" table requires a TCB-review label.
- The CI guard (planned) re-derives the inventory from `# TCB:` / `// TCB:` annotations and fails if it diverges from this document.
- New modules under `daemon/bin/scrt4-modules/` declare `tcb: false` in their header. The build script enforces it.
- A module that genuinely needs TCB scope (e.g. a future `wa-toggle` rewrite) must declare `tcb: true` and gets added to this document and reviewed accordingly.

## See also

- `docs/FORMAL-VERIFICATION-INPUT.md` — handoff doc for the verification team
- `docs/ARCHITECTURE-V0.2.md` — overall v0.2 architecture
- `SECURITY.md` — vulnerability disclosure policy and threat model
- Issue #60 — TCB annotation work tracking issue
