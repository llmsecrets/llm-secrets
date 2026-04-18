# scrt4 modules — specification & ABI

> **Audience:** module authors, reviewers, AI coding agents. Read this before writing or modifying any file under `daemon/bin/scrt4-modules/`.
>
> **TL;DR:** A module is one bash file that registers new `scrt4 <name>` subcommands. It runs **outside** the trusted computing base. It can only read secrets through the daemon's `reveal` RPC. It cannot read the vault directly, cannot access session state, and cannot mint or extend sessions.

---

## 1. The TCB boundary (read this first)

scrt4 is split into two parts that do not trust each other equally:

```
+------------------------+       Unix socket        +-------------------------+
|                        |  <-------- RPC --------> |                         |
|   MODULES (bash)       |                          |    DAEMON (Rust)        |
|                        |                          |                         |
|   NOT trusted.         |                          |    TCB. Trusted.        |
|   Can only ask.        |                          |    Holds the key.       |
|                        |                          |    Decides yes/no.      |
+------------------------+                          +-------------------------+
           ^                                                    ^
           |                                                    |
      user-writable                                       root-owned,
      any author can                                      formally verified
      add a module here                                   (see docs/TCB.md)
```

**The TCB is the daemon, not the module layer.** A buggy or hostile module:

- **Cannot** read the vault file on disk — it's AES-256-GCM encrypted, key lives in the daemon's memory only.
- **Cannot** observe other modules' secret values — each `reveal` is a fresh subprocess-scoped string.
- **Cannot** bypass `--yes` / interactive confirms — those are enforced by the module itself.
- **Can** print a secret it revealed (that's the whole point — modules use secrets to do work). It is the module author's job not to leak them. See §6.

**What this means for you as a module author:** you are writing untrusted code. Treat yourself as untrusted. Never assume "we're on the same side as the crypto." You aren't.

For the full list of what's in-TCB, see [`docs/TCB.md`](TCB.md). If you find yourself needing to modify anything under `daemon/src/`, you have left module territory — that is a TCB change and requires separate review.

---

## 2. The ABI — what modules can and cannot do

### In scope (you get these)

| Capability | How | Notes |
|---|---|---|
| Register subcommands | `_register_command NAME FN` in your `scrt4_module_<name>_register` function | One or more per module. Must be unique across modules. |
| List secret names | `scrt4_rpc list` (helper in core) | Names only — values are never returned here. |
| Reveal a secret | `_module_reveal NAME` (helper in core) | Two-phase: daemon returns a challenge, caller confirms. Returns the plaintext value as a string. |
| Ensure the session is unlocked | `_require_unlocked` (helper in core) | Exits the command with a friendly error if the session has expired. |
| Read module config | `$CONFIG_DIR/<module>.json` (you own this file) | The daemon doesn't touch this. Do not put secret values here. |
| Print status / results | stdout/stderr | Subject to §6 — don't leak secrets. |
| Shell out | Any external binary (`curl`, `gcloud`, `stripe`, etc.) | Pass secrets via stdin, `--data-binary @-`, or env — never argv. |

### Out of scope (you do NOT get these — the daemon will refuse)

| Forbidden thing | Why | What the daemon does if you try |
|---|---|---|
| Call `reveal_all` without `--yes` gate | TCB: never mass-export | RPC responds but the flow requires an interactive or `--yes`-audited call. In a future hardening (issue #67), modules will be **blocklisted** from this RPC entirely unless they declare `reveals_all: true` in their header and the manifest allow-lists them. |
| Read `~/.local/share/scrt4/vault.bin` directly | Encrypted; wouldn't help anyway | N/A — you just get ciphertext. |
| Extend or mint a session token | Only `handle_unlock` does this | The only way to unlock is `scrt4 unlock`. Modules cannot fake it. |
| Write to the vault (`add_secrets`) without the user's biometric | `handle_add_secrets` is in-TCB | A vault write requires `unlock` state, which requires the user's authenticator. |
| Access another module's config | By convention, not enforcement | Don't. Module configs are siloed by filename. |
| Talk to the daemon on a socket the module opens itself | The daemon only listens on one socket | Use the provided `_scrt4_rpc` / `_module_reveal` helpers, not a custom socket client. |

### The RPCs modules actually use

These are the only daemon RPCs a module should ever invoke. Everything else is for the core CLI.

| RPC | Purpose | Helper to call it |
|---|---|---|
| `status` | Is there an active session? | `_require_unlocked` |
| `list` | Names of secrets in the vault | `_scrt4_rpc list` |
| `reveal` + `reveal_confirm` | Fetch one secret value (two-phase) | `_module_reveal NAME` |
| `tag` / `untag` / `tags` | Read or adjust tags on a secret | direct via `_scrt4_rpc` |

A future daemon-side capability system (issue #67) will enforce this at the RPC layer based on the module's declared `reveals:` / `reveals_pattern:` / `reveals_tag:` headers. For now it is documented policy that reviewers enforce.

---

## 3. Module file layout

Every module lives at **`daemon/bin/scrt4-modules/<name>.sh`**. The build script (`scripts/build-scrt4.sh`) concatenates `daemon/bin/scrt4-core` + the modules listed in `modules.manifest` for the current distribution into one executable bash file.

### The header (all fields, in order)

```bash
# shellcheck shell=bash
# scrt4-module: <name>
# version: <integer, increment on breaking change>
# api: 1
# tcb: false
# deps: <space-separated binaries needed, e.g. curl jq>
# commands: <space-separated subcommand names this module registers>
# requires: <space-separated feature flags needed from daemon, usually blank>
# reveals: <space-separated EXACT secret names this module reads>
# reveals_pattern: <space-separated glob patterns, e.g. STRIPE_*>
# reveals_tag: <space-separated tag names — read all secrets tagged X>
#
# <human-readable description>
```

**Field-by-field:**

| Field | Required | What it does |
|---|---|---|
| `scrt4-module` | Yes | Module name. Must match filename (e.g. `stripe` for `stripe.sh`). |
| `version` | Yes | Integer. Bump on any breaking change to the module's CLI. |
| `api` | Yes | ABI version this module is built against. Currently `1`. The build script may reject mismatches in the future. |
| `tcb` | Yes | Always `false`. The build script refuses to ship a module with `tcb: true`. Only the core file may be in-TCB. |
| `deps` | No | Space-separated list of binaries (`curl`, `jq`, `gcloud`, etc.). Users missing a dep get a clean error. |
| `commands` | Yes | Subcommand names. Must be unique across all modules in a distribution. |
| `requires` | No | Daemon feature flags. Blank is normal. |
| `reveals` | Recommended | Exact names of secrets the module reads. Documents least-privilege intent. Used by the future capability system to allow-list RPC calls per module. |
| `reveals_pattern` | Optional | Glob patterns when the set isn't static (e.g. `STRIPE_*`). |
| `reveals_tag` | Optional | Tag-based selection (e.g. `reveals_tag: wallet` — module can read any secret tagged `wallet`). |

### The body — required structure

```bash
# Register subcommands with the core dispatcher. The name of this function
# is fixed: scrt4_module_<name>_register. The build step calls it.
scrt4_module_<name>_register() {
    _register_command <cmd1> scrt4_module_<name>_dispatch
    # ... one _register_command per subcommand
}

# Dispatch — fans out to per-subcommand handlers.
scrt4_module_<name>_dispatch() {
    case "${1:-}" in
        help|-h|--help) _scrt4_<name>_help ;;
        foo)  shift; _scrt4_<name>_foo "$@" ;;
        bar)  shift; _scrt4_<name>_bar "$@" ;;
        *) _scrt4_<name>_help; return 2 ;;
    esac
}

# Private helpers — prefix ALL of them with _scrt4_<name>_ so you don't
# collide with core or other modules.
_scrt4_<name>_help() { ... }
_scrt4_<name>_foo()  { ... }
```

**The single rule that matters:** every function or variable your module defines must be prefixed `_scrt4_<name>_` (or `scrt4_module_<name>_` for the three publicly-called names). The build script concatenates everything into one file; name collisions silently overwrite each other.

---

## 4. Secret access — the reveal flow

### The canonical pattern

```bash
_scrt4_stripe_do_thing() {
    _require_unlocked || return 1

    local tok
    tok=$(_module_reveal STRIPE_SECRET_KEY) || {
        echo "error: STRIPE_SECRET_KEY not in vault" >&2
        return 1
    }

    # Use it. Once. Immediately.
    local resp
    resp=$(curl -sS -u "${tok}:" https://api.stripe.com/v1/balance)

    # Unset it. Always.
    unset tok
    tok=""

    echo "$resp" | jq -r '.available[0].amount'
}
```

**Rules:**

1. **Always** `_require_unlocked` first. It prints a helpful error and exits cleanly if no session.
2. **Always** fetch the token with `_module_reveal`. Never `export`, never write to a temp file, never pass on argv.
3. **Pass secrets on stdin or auth headers only.** `curl -u "${tok}:"` → OK. `curl --header "Authorization: Bearer ${tok}"` → OK. `curl --data "key=${tok}"` → **bad** (shows in `ps`).
4. **`unset`** the variable immediately after the call returns. Bash variables persist in the function scope until the function ends — `unset` ends them earlier.
5. **Never** `echo "$tok"`, even under `--verbose`. If you want a verbose mode, echo what you did, not what you used.

### Declaring what you read (least-privilege intent)

Document the exact secrets your module reads in the header:

```bash
# reveals: STRIPE_SECRET_KEY
```

For set-of-secrets patterns:

```bash
# reveals_pattern: STRIPE_*
```

For tag-based discovery (e.g. the wallet module scans vault names matching `*_PUBLIC_KEY` / `*_ADDRESS` — that's better expressed as a tag):

```bash
# reveals_tag: wallet
```

These header fields are informational today. Under issue #67 they will become the daemon-side allow-list that enforces capability scoping. Fill them in correctly now so your module keeps working when the enforcement lands.

---

## 5. Subcommand conventions

Every module's subcommands should follow the same shape so users get consistent behavior:

### Required subcommands

| Subcommand | Behavior | Example |
|---|---|---|
| `help` (and `-h`/`--help`) | Print usage. Must exit 0. | `scrt4 github help` |
| Unknown subcommand | Print help, exit non-zero. | `scrt4 github nonsense` → exit 2 |

### Required flags on any mutating subcommand

| Flag | Behavior |
|---|---|
| `--dry-run` | Print the exact API call / shell command that **would** run. Don't call out to the network. Don't touch any external system. The output must include the word `DRY RUN` and the full request line (method + path). |
| `--yes` | Skip the interactive confirm. Required for non-interactive use. |
| (no flag, interactive TTY) | Print the plan, prompt `Proceed? [y/N]`, require `y`/`yes` to continue. |
| (no flag, non-interactive — no TTY) | **Refuse.** Print `re-run with --yes to proceed in a non-interactive shell` and exit non-zero. |

### Standard confirm helper

Copy this into every module that has writes:

```bash
_scrt4_<name>_confirm() {
    # Returns 0 if the user said yes, 1 otherwise.
    # Respects --yes flag (set SCRT4_<NAME>_YES=1 in the flag parser).
    if [ "${SCRT4_<NAME>_YES:-}" = "1" ]; then
        return 0
    fi
    if [ ! -t 0 ]; then
        echo "error: non-interactive shell — re-run with --yes to proceed" >&2
        return 1
    fi
    read -r -p "$1 " reply
    case "$reply" in
        y|Y|yes|YES) return 0 ;;
        *) echo "aborted." >&2; return 1 ;;
    esac
}
```

### Output conventions

- **Plans** before dry-runs: `Plan: create issue in me/repo`
- **Dry-run banner:** `DRY RUN: no API call will be made.`
- **Method + path on its own line:** `GitHub POST /repos/me/repo/issues` (so tests can grep for it).
- **Errors to stderr.** Exit non-zero on any failure.
- **No color codes if stdout is not a TTY.** The core provides color helpers that already respect `NO_COLOR`.

---

## 6. The don't-leak-secrets checklist

Before opening a PR for any module, verify each line:

- [ ] No `echo "$secret"` (or any variant: `printf`, `echo -e`, heredoc with `$secret` in it).
- [ ] No secret passed as a positional argument to another process (shows in `ps`).
- [ ] No secret written to a temp file, even with `mktemp` + `chmod 600`.
- [ ] No secret in a URL query string (shows in access logs on the other side).
- [ ] No secret in a shell prompt, `PS4`, `set -x` trace, or debug log.
- [ ] `unset VAR` after every `VAR=$(_module_reveal ...)` call.
- [ ] Errors from the network don't echo the request body if the body contained the secret.

If in doubt: `grep -n "$tok\|$key\|$pat" <(command_output)` in your code. If it matches, you have a leak.

---

## 7. Registering in the manifest

The file `modules.manifest` at the repo root lists which modules ship in which distribution. There are three:

| Distribution | Purpose | Auth | What ships |
|---|---|---|---|
| `[hardened]` | Production. FIDO2 required. | Biometric-gated on every reveal. | All stable modules. |
| `[dev]` | Dev/test only. Zero auth. | None (see issue #59). | Everything in hardened, plus test-only modules. |
| `[core-only]` | Smallest possible build for formal verification. | Biometric-gated. | **No modules.** Just the core file. |

Add a new module with a one-line explanation of opt-in status:

```
# Stripe REST API wrapper — balance / charges / customers / subs / refunds.
# Uses STRIPE_SECRET_KEY from the vault. Refunds are --yes-gated with
# optional --amount CENTS for partial refunds.
stripe
```

**Opt-in rule:** a module should only execute its code paths when the user explicitly invokes `scrt4 <name>`. Modules must NOT auto-run anything at registration time. The build appends module code to the binary, but nothing runs until the dispatcher is invoked.

---

## 8. Existing modules — use as reference

| Module | Flavor | Good example of |
|---|---|---|
| `wallet.sh` | Local CLI (no external API calls for the main command) | Secret **discovery** (scans names by regex for `*_PUBLIC_KEY`), local config file in `$CONFIG_DIR`. |
| `domain.sh` | Multi-provider REST API | Subcommand routing when there are many providers (cf / vercel / godaddy / aws / gcp), per-provider token selection. |
| `github.sh` | REST API with bearer auth | `curl` with `Authorization: Bearer`, `--dry-run` that emits `METHOD /path`, `_scrt4_gh_confirm`. |
| `gcp.sh` | CLI wrapper (not REST) | Shelling out to a pre-installed binary (`gcloud`), PATH-shim-compatible for tests. |
| `stripe.sh` | REST API with basic auth | `curl -u "${key}:"` pattern, partial-amount flag, lifecycle-gated write (refund). |

When writing a new module, pick the one closest to your shape and copy the skeleton.

---

## 9. FAQ

**Q: My module needs to store state between runs. Where?**

`$CONFIG_DIR/<module>.json` is yours to write. It is not encrypted, so do not put secret values there — only references (names, IDs, preferences). If you need encrypted per-module state, that's a daemon feature request, not a module feature.

**Q: Can I spawn long-running processes from a module?**

Yes, but the lifetime is bounded by the CLI invocation. If you need a background service, that's a daemon feature request.

**Q: Can I talk to the daemon directly via the socket?**

Use the provided helpers (`_scrt4_rpc`, `_module_reveal`, `_require_unlocked`). The socket protocol is stable but the helpers handle challenge-confirm and error mapping for you.

**Q: Can two modules collaborate?**

Yes — a module can call `scrt4 <other-module> <subcommand>` via its own shell. But the preferred pattern is: if functionality is shared, factor it into the core and expose a helper that both modules can call.

**Q: My module calls an SDK (e.g. `stripe-node`, `google-cloud-sdk`). Do I have to use curl directly?**

No. Shell out to the SDK. Follow the same secret-handling rules: pass the token via the env var the SDK expects, and `unset` after.

**Q: What if my module needs to read a lot of secrets?**

Document them all in `reveals:` or use `reveals_pattern:` / `reveals_tag:`. Still fetch them one at a time via `_module_reveal`. Do not use `reveal_all` — that exists for the user-facing `view` command, not for modules.

**Q: Who reviews new modules?**

Modules are not TCB. They get a normal code review focused on the checklist in §6. They do not require formal verification — unlike TCB changes (see `docs/TCB.md`).

---

## 10. Reference: the ABI helpers in core

These are the functions exposed to modules by `daemon/bin/scrt4-core`. They are stable (API version 1).

| Helper | Signature | Purpose |
|---|---|---|
| `_register_command` | `NAME FUNCTION` | Called from your register function to bind a subcommand name to a dispatch function. |
| `_require_unlocked` | (no args) | Exits the current command with a friendly error if there's no active session. |
| `_scrt4_rpc` | `METHOD [params...]` | Low-level JSON-RPC call to the daemon. Most modules don't need this directly. |
| `_module_reveal` | `SECRET_NAME` | Two-phase reveal. Returns the plaintext on stdout, or non-zero if the secret isn't in the vault. |
| Color helpers | `_c_red` / `_c_green` / `_c_yellow` / `_c_cyan` / `_c_reset` | Respect `NO_COLOR` and TTY detection. |

If you need something that's not in this list, that's a core feature request — file an issue before adding it to a module.

---

**Next:** see [`CREATE-A-MODULE.md`](CREATE-A-MODULE.md) for a step-by-step walkthrough of building your first module end-to-end.
