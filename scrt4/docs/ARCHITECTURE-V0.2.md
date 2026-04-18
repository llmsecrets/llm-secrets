# scrt4 v0.2 architecture

> **Status:** parallel implementation on branch `architecture/v0.2.0`. Not released. Stable v0.1.0 hardened distribution on `main` is untouched.

This document describes the v0.2 architecture: a small **core** (the trusted computing base) plus opt-in **modules** (everything else), assembled at build time via a **manifest** to produce one of several **distributions** (hardened, core-only).

## Terminology — Core vs Modules

The words "core" and "module" are load-bearing in this codebase. They are not interchangeable.

### Core (aka "Crypto Core")

The **Core** (sometimes "Crypto Core") is the baseline of scrt4 — the parts the product cannot function without. It comprises:

- The Rust daemon (`daemon/src/`) — vault, session, keystore, audit, protocol, handlers, subprocess injection, WebAuthn. Anything that touches the master key, the vault format, or the auth gate lives here.
- The core CLI commands (`daemon/bin/scrt4-core`): `unlock`, `setup`, `status`, `list`, `add`, `run`, `view`, `logout`, `extend`, `help`.
- Core cryptographic bookkeeping: encrypted-folder **inventory** and lifecycle (`list-encrypted`, `cleanup-encrypted`) and vault **rotation** (re-encrypting the vault under a new master key).

The defining test: **if it touches the master key, the vault format, the session, or the auth gate, it is Core.**

### Modules

A **module** is an optional add-on that calls daemon RPCs but can be omitted from a distribution without breaking scrt4 itself. Modules live under `daemon/bin/scrt4-modules/<name>.sh` and are included in a distribution via `modules.manifest`.

The defining test: **if removing this feature leaves a functional scrt4 for at least some users, it's a module.**

Current modules:

| Module | Purpose |
|---|---|
| `encrypt-folder` | Encrypt/decrypt filesystem folders (the operations; inventory is Core) |
| `import-env` | Import from `.env` files |
| `tags` | Tag secrets |
| `wa-toggle` | Enable/disable WebAuthn gates |
| `wallet` | Wallet operations. **Canonical example of a module.** Wallet operations depend on pre-existing secrets (private keys, RPC URLs, signer addresses). Not every scrt4 user has those — the wallet consumes the vault's value, it doesn't create it. |
| `menu` | zenity GUI launcher |

**Promoted to Core** (no longer modules): `share`/`receive` (wormhole transfer), `backup-vault`/`backup-key`/`recover`/`backup-guide` (vault lifecycle).

When classifying a new feature, the decision tree is:

1. Does it touch the master key, vault format, or auth gate? → **Core**
2. Is it core crypto bookkeeping (inventory, rotation)? → **Core**
3. Does it assume the user already has specific secrets to operate on? → **Module**
4. Can some distributions omit it entirely without breaking scrt4? → **Module**
5. Is it a convenience wrapper around existing daemon RPCs? → usually **Module**

### Reclassifications on `architecture/v0.2.0`

Two features were originally scaffolded as module stubs but are now classified as Core because they touch the vault format and the daemon's cryptographic bookkeeping:

- **`list-encrypted`** (F027) and **`cleanup-encrypted`** (F028) were originally stubbed inside the `encrypt-folder` module. They are now Core: they need a daemon-side inventory table tracking encrypted folder metadata. The encrypt/decrypt operations themselves remain in the `encrypt-folder` module, but the inventory and lifecycle is Core.
- **Vault rotation** (F043) was originally scoped as a PRO-only aspirational item. It is now Core, high priority: re-encrypting the entire vault under a new master key is a primary cryptographic operation and determines whether scrt4 can be trusted for long-lived secrets.

Wallet (F014/F015), which some planning notes previously considered moving into Core, is and remains a Module. It is the canonical example of a module precisely because it depends on the vault's existing contents and is not universal.

## Why

Two pressures, addressed by one architectural change.

1. **Formal verification of the hardened image** (issue #60) wants a small TCB to prove things about. Today the 4393-line `daemon/bin/scrt4` mixes auth gates, vault crypto handoff, and feature commands in one file. Pulling the auth/vault path into a separate `scrt4-core` lets the verification team scope to ~1500 lines instead of ~4400.

2. **Cleaner contribution surface** (issue #61). New features land as a single file under `daemon/bin/scrt4-modules/` plus one manifest line. No edits to core, no merge conflicts in the dispatcher, no risk of accidentally touching auth gates.

## Layout

```
daemon/
├── bin/
│   ├── scrt4                       # v0.1.0 monolith — UNCHANGED, ships hardened release
│   ├── scrt4-core                  # v0.2 core: auth, vault, dispatcher, basic commands
│   └── scrt4-modules/              # v0.2 modules: opt-in features
│       ├── encrypt-folder.sh       # scrt4 encrypt-folder / decrypt-folder
│       ├── import-env.sh           # scrt4 import (env file import)
│       ├── menu.sh                 # scrt4 menu (zenity GUI launcher)
│       ├── tags.sh                 # scrt4 tag / untag / tags
│       ├── wa-toggle.sh            # scrt4 wa-state / wa-on / wa-off
│       └── wallet.sh               # scrt4 wallet (stub)
├── src/                            # Rust daemon — UNCHANGED in v0.2 scaffold
│   └── ...
modules.manifest                    # which modules each distribution includes
scripts/
└── build-scrt4.sh                  # concatenates core + modules into a single bash binary
Dockerfile.hardened                 # v0.1.0 — UNCHANGED, ships joshgottlieb/scrt4-hardened
docs/
├── ARCHITECTURE-V0.2.md            # this file
├── TCB.md                          # trusted computing base inventory (issue #60)
└── FORMAL-VERIFICATION-INPUT.md    # handoff doc for verification team
```

The v0.1.0 monolith and v0.2 architecture coexist. The hardened release pipeline reads `Dockerfile.hardened` which copies `daemon/bin/scrt4`. Nothing in this branch can break v0.1.0.

## Core API

The dispatcher in `scrt4-core` exposes a stable, versioned API that modules call. The contract:

### Registration

```bash
_register_command NAME HANDLER_FUNCTION
```

Modules call this from a `scrt4_module_<name>_register` function. The build script discovers and calls the registration functions in dependency order.

### Daemon I/O

```bash
send_request '{"method":"...","params":{...}}'   # synchronous, returns JSON on stdout
ensure_unlocked                                   # gate: verifies session, prompts unlock if needed
_wa_gate                                          # gate: WebAuthn step-up for sensitive operations
```

### UI helpers

```bash
_has_gui                                          # true iff zenity binary present AND DISPLAY/WAYLAND_DISPLAY set
_bg_if_gui CMD ARGS...                            # backgrounds CMD if GUI usable, else runs in foreground
print_color $RED $GREEN $YELLOW $CYAN $NC TEXT   # color constants are exported
```

### Module metadata

A module file starts with a fixed header that the build script parses:

```bash
#!/usr/bin/env bash
# scrt4-module: share
# version: 1
# api: 1
# tcb: false
# deps: magic-wormhole, qrencode
# commands: share, receive
# requires: (none)
```

| Field | Meaning |
|---|---|
| `scrt4-module` | Unique module name |
| `version` | Module version (semver-ish) |
| `api` | Core API version this module targets; mismatch is a fatal build error |
| `tcb` | `true` if the module is in the trusted computing base. **Almost always `false`.** Modules in the TCB need explicit verification scope. |
| `deps` | Runtime dependencies that the Dockerfile must install; comma-separated package names |
| `commands` | User-facing scrt4 subcommands the module registers |
| `requires` | Other modules this module depends on |

## Manifest

`modules.manifest` declares which modules each distribution includes. Format:

```
[hardened]
share
wallet
encrypt-folder
menu
backup-vault
tags
import-env
wa-toggle

[core-only]
# no modules — the smallest possible build, target for formal verification
```

Lines starting with `#` are comments. Section headers in `[brackets]` start a new distribution. Module names match files under `daemon/bin/scrt4-modules/<name>.sh`.

## Build script

`scripts/build-scrt4.sh DISTRIBUTION OUTPUT_PATH` reads the manifest, validates the module headers, computes a topological sort of `requires`, and concatenates `daemon/bin/scrt4-core` + the selected module files into a single executable bash script at `OUTPUT_PATH`.

```sh
scripts/build-scrt4.sh hardened   /tmp/scrt4-hardened
scripts/build-scrt4.sh core-only  /tmp/scrt4-core-only
```

Each output is self-contained — drop it into `/usr/local/bin/scrt4` and run.

## What each distribution is for

### `hardened` distribution — the real product

- **Purpose:** replace the v0.1.0 monolith for end users.
- **Auth:** FIDO2/WebAuthn via the `auth.llmsecrets.com` relay. Phone scans QR, authenticates with passkey, relay returns encrypted PRF payload, daemon unwraps master key. Same flow as v0.1.0.
- **`unlock` and `setup` are fully implemented (ISS016 complete).** The daemon RPCs (`unlock_webauthn`, `unlock_webauthn_complete`, `setup_webauthn`, `setup_webauthn_complete`) are wired end-to-end with the bash-side QR render + relay poll flow (`run_unlock_flow`, `run_setup_flow` in `scrt4-core`). Same flow as the v0.1.0 monolith.
- Vault/audit at `~/.scrt4/` — same as v0.1.0 monolith, intentional for forward compatibility.

### `core-only` distribution — minimal attack surface

- **Purpose:** minimal attack surface for headless/CI use.
- **Auth:** hardened (same WebAuthn flow as hardened distribution).
- Use case: machine-to-machine secret injection where `share`/`encrypt-folder` modules aren't needed. Backup-vault/key/recover/guide are always available (they're Core).

## TCB annotations (issue #60)

Every TCB function in `scrt4-core` carries a header comment:

```bash
# TCB: <subsystem>
# Verifies: <invariant in plain English>
# Adversary: <threat this defends against>
function_name() {
    ...
}
```

Grep the inventory: `grep -n '^# TCB:' daemon/bin/scrt4-core`. The full list with rationale is in `docs/TCB.md`.

## What's NOT in v0.2 yet

The authoritative list is the tracker sheet (`1P9nNTasjCN_C_lN4onXxPSUVkMGkzJIARhBoybAMzto`), which tracks every feature's Port status and Dev harness validation per distribution. The major outstanding items as of 2026-04-13:

### Blockers for v0.2 hardened to replace the v0.1.0 monolith

- ~~**ISS016 — WebAuthn unlock/setup bash port.**~~ **DONE.** All 4 daemon RPCs wired end-to-end with bash QR/relay/complete flow. Tested: relay generation, flag parsing, RPC deserialization, invalid-payload rejection.
- ~~**Backwards compat verification.**~~ **DONE.** All user-facing commands produce matching exit codes on both binaries. Commands gated by v0.1.0's `_wa_gate` (view, backup-key, wa-off) are v0.2-only improvements. `Dockerfile.hardened` can now ship from the v0.2 build.

### Core work scheduled but not yet done

- **Vault rotation (F043).** Re-encrypting the entire vault under a new master key. Core, high priority — this determines whether scrt4 can be trusted for long-lived secrets.
- ~~**Encrypted-folder inventory (F027 list-encrypted, F028 cleanup-encrypted).**~~ **DONE.** Reclassified to Core, both commands operational in all distributions.

### PRO-only features (future hardened target, not in v0.2)

Scoped for a future hardened release, not planned for v0.2:

| Feature | What it is |
|---|---|
| F039 Vault format magic byte | Refuse to open a cross-distribution vault |
| F040 Multi-credential support | Primary + recovery passkeys |
| F041 Audit log signing | HMAC chain over audit entries |
| F042 Time-locked operations | Delayed reveal for high-value secrets |
| F044 CI smoke matrix | Per-PR build + smoke of every distribution |
| F045 FV harness for non-TCB | Deeper verification for non-TCB modules |

### Known bugs / open issues

- ~~**ISS016**~~ (closed) — WebAuthn unlock/setup ported to v0.2. All bash helpers + daemon RPCs wired and tested.

The point of this branch remains the architecture, not the feature port — but enough features have landed since the initial scaffold that "v0.2 is just the architecture" is no longer accurate. See the tracker sheet for live status.

## How to run the v0.2 builds (developer)

```sh
git checkout architecture/v0.2.0
scripts/build-scrt4.sh hardened   /tmp/scrt4-hardened-v2
scripts/build-scrt4.sh core-only  /tmp/scrt4-core-only
diff -q daemon/bin/scrt4 /tmp/scrt4-hardened-v2   # functional diff against v0.1.0 monolith
```

## How to run the v0.1.0 release (user)

```sh
curl -fsSL https://install.llmsecrets.com | sh
```

This still works. v0.1.0 ships from `main` and is untouched.
