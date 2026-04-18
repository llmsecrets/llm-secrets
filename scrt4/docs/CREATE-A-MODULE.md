# Create a scrt4 module — step-by-step

> **Prereq:** read [`MODULES.md`](MODULES.md) §1 (the TCB boundary) and §2 (the ABI). Everything below assumes you understand that modules are not trusted code and can only read secrets through the daemon's `reveal` RPC.

We're going to build a module called **`slack`** that posts a message to a Slack channel using a stored Slack token. We'll use this as a running example through all the steps. At each step you'll see the exact files changed and a copy-pasteable snippet.

If you want an even faster path, the `create-scrt4-module` skill scaffolds most of this for you. See §9.

---

## Step 0 — Prerequisites

- A working scrt4 v0.2 checkout on branch `architecture/v0.2.0`
- The daemon binary built: `cargo build --release --manifest-path daemon/Cargo.toml`
- A hardened CLI built: `bash scripts/build-scrt4.sh hardened /tmp/scrt4-hardened`
- An active session (`scrt4 unlock`) so you can actually read secrets while testing
- Your target API/tool works end-to-end from the command line with a real token (so you know the happy path before you script it)

Quick sanity check:

```bash
/tmp/scrt4-hardened help
/tmp/scrt4-hardened list
```

If those work, you're ready.

---

## Step 1 — Pick a name and plan the secrets

**Name rules:**
- Lowercase, one word, `[a-z0-9-]+`
- Matches the file you'll create: `daemon/bin/scrt4-modules/<name>.sh`
- Doesn't collide with any existing subcommand

**Secret plan:** before writing any code, list the secrets your module reads. For the Slack example:

| Secret name | Purpose | Required? |
|---|---|---|
| `SLACK_BOT_TOKEN` | Bot token with `chat:write` scope | Yes |
| `SLACK_DEFAULT_CHANNEL` | Fallback channel if user doesn't pass one | No |

This planning matters because it goes straight into the module's `reveals:` header and (once issue #67 lands) the daemon will enforce it.

**Document how to generate each secret in [`SECRETS.md`](SECRETS.md).** This
is not optional. If your module introduces a new secret name, add a
subsection under your module's section in `SECRETS.md` covering:

1. *What it is* — one sentence on what the secret authorizes.
2. *Scopes / permissions* — the least-privilege set to pick during generation.
3. *Generate* — the numbered UI / CLI steps to produce the value.
4. *Install* — the exact `scrt4 add` line (including any required quoting).
5. *Rotate* — how to replace it when it leaks or expires.

A PR that adds a `reveals:` secret without a matching `SECRETS.md` entry
will be held at review. See the existing sections (github, gcp, stripe,
domain, wallet, messages) as templates.

**Seed them in your vault** so you can test locally:

```bash
/tmp/scrt4-hardened add SLACK_BOT_TOKEN=xoxb-your-real-token
/tmp/scrt4-hardened add SLACK_DEFAULT_CHANNEL=#engineering
```

---

## Step 2 — Create the module file with the header

Create `daemon/bin/scrt4-modules/slack.sh`:

```bash
# shellcheck shell=bash
# scrt4-module: slack
# version: 1
# api: 1
# tcb: false
# deps: curl jq
# commands: slack
# requires:
# reveals: SLACK_BOT_TOKEN SLACK_DEFAULT_CHANNEL
#
# Slack messaging — post a message to a channel via chat.postMessage.
#
#   scrt4 slack post CHANNEL MESSAGE [--dry-run] [--yes]
#   scrt4 slack channels                  # list channels the bot is in
```

**What each field is doing:**

| Field | Value | Why |
|---|---|---|
| `scrt4-module` | `slack` | Must match filename. |
| `version` | `1` | First cut. |
| `api` | `1` | The ABI version defined in `MODULES.md` §10. |
| `tcb` | `false` | Modules are never in TCB. The build script rejects `true`. |
| `deps` | `curl jq` | So users get a clean error if either is missing. |
| `commands` | `slack` | Must be unique across all modules. |
| `reveals` | `SLACK_BOT_TOKEN SLACK_DEFAULT_CHANNEL` | Exact names the module reads — least-privilege intent. |

---

## Step 3 — Register your subcommand

Every module has one required function: `scrt4_module_<name>_register`. The build script calls it once at startup. It binds your subcommand names to dispatch functions:

```bash
scrt4_module_slack_register() {
    _register_command slack scrt4_module_slack_dispatch
}
```

Then the dispatcher fans out based on `$1`:

```bash
scrt4_module_slack_dispatch() {
    case "${1:-}" in
        help|-h|--help) _scrt4_slack_help ;;
        post)     shift; _scrt4_slack_post "$@" ;;
        channels) shift; _scrt4_slack_channels "$@" ;;
        *) _scrt4_slack_help; return 2 ;;
    esac
}
```

**Rule:** every function your module defines must start with `_scrt4_slack_` (or the three `scrt4_module_slack_` public ones). See `MODULES.md` §3 for why.

---

## Step 4 — Write the help subcommand

Every module needs `help` to exit 0 and print a usage banner that contains the string `scrt4 <name>`:

```bash
_scrt4_slack_help() {
    cat <<'EOF'
scrt4 slack — Slack messaging

USAGE:
    scrt4 slack post CHANNEL "MESSAGE" [--dry-run] [--yes]
    scrt4 slack channels
    scrt4 slack help

EXAMPLES:
    scrt4 slack post "#eng" "deploy finished"
    scrt4 slack post "@josh" "ping" --dry-run
    scrt4 slack channels

NOTES:
    Posts go via chat.postMessage. The bot must be a member of the
    channel (public channels you haven't invited the bot to will 404).

SECRETS USED:
    SLACK_BOT_TOKEN           (required)
    SLACK_DEFAULT_CHANNEL     (optional — fallback when no channel given)
EOF
}
```

---

## Step 5 — Implement the read subcommand (no writes, no confirms)

Read ops are the simplest — fetch the token, hit the API, print the result, `unset` the token:

```bash
_scrt4_slack_channels() {
    _require_unlocked || return 1

    local tok
    tok=$(_module_reveal SLACK_BOT_TOKEN) || {
        echo "error: SLACK_BOT_TOKEN not in vault" >&2
        return 1
    }

    local resp
    resp=$(curl -sS \
        -H "Authorization: Bearer ${tok}" \
        "https://slack.com/api/conversations.list?types=public_channel,private_channel&limit=100")

    unset tok

    if [ "$(echo "$resp" | jq -r .ok)" != "true" ]; then
        echo "error: $(echo "$resp" | jq -r .error)" >&2
        return 1
    fi

    echo "$resp" | jq -r '.channels[] | "\(.is_private|if . then "[priv]" else "[pub] " end) #\(.name)"'
}
```

**Do the dry-run-style output check yourself right now:**

```bash
/tmp/scrt4-hardened slack channels
```

You should see a list of channels. If you see the token printed, stop and fix it before continuing.

---

## Step 6 — Implement the write subcommand with --dry-run and --yes

Write ops are where the real discipline lives. Every mutating command must support three modes:

1. **Interactive + no flag** → print plan, prompt `Proceed? [y/N]`, require `y`.
2. **Non-interactive + no flag** → refuse with `re-run with --yes`.
3. **`--dry-run`** → print the plan, **do not** call the network.
4. **`--yes`** → skip the prompt, proceed.

### 6a. The flag parser

```bash
_scrt4_slack_parse_flags() {
    # Reads leftover args after positional ones, sets two env vars:
    #   SCRT4_SLACK_DRY_RUN=1 if --dry-run was present
    #   SCRT4_SLACK_YES=1     if --yes was present
    SCRT4_SLACK_DRY_RUN=0
    SCRT4_SLACK_YES=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run) SCRT4_SLACK_DRY_RUN=1 ;;
            --yes|-y)  SCRT4_SLACK_YES=1 ;;
            *) echo "error: unknown flag: $1" >&2; return 2 ;;
        esac
        shift
    done
}
```

### 6b. The confirm helper

```bash
_scrt4_slack_confirm() {
    [ "${SCRT4_SLACK_YES:-0}" = "1" ] && return 0
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

### 6c. The post subcommand

```bash
_scrt4_slack_post() {
    local channel="${1:-}"
    local message="${2:-}"
    shift 2 2>/dev/null || true
    _scrt4_slack_parse_flags "$@" || return $?

    if [ -z "$channel" ] || [ -z "$message" ]; then
        echo "usage: scrt4 slack post CHANNEL \"MESSAGE\" [--dry-run] [--yes]" >&2
        return 2
    fi

    echo "Plan: post to ${channel}"
    echo "  message: ${message}"

    if [ "${SCRT4_SLACK_DRY_RUN}" = "1" ]; then
        echo "DRY RUN: no API call will be made."
        echo "  Slack POST /api/chat.postMessage  body: channel=${channel} text=<redacted>"
        return 0
    fi

    _scrt4_slack_confirm "Proceed? [y/N]" || return 1
    _require_unlocked || return 1

    local tok
    tok=$(_module_reveal SLACK_BOT_TOKEN) || {
        echo "error: SLACK_BOT_TOKEN not in vault" >&2
        return 1
    }

    local resp
    resp=$(curl -sS \
        -H "Authorization: Bearer ${tok}" \
        -H "Content-Type: application/json; charset=utf-8" \
        -d "$(jq -n --arg c "$channel" --arg t "$message" '{channel:$c, text:$t}')" \
        https://slack.com/api/chat.postMessage)

    unset tok

    if [ "$(echo "$resp" | jq -r .ok)" = "true" ]; then
        echo "posted to ${channel} (ts: $(echo "$resp" | jq -r .ts))"
    else
        echo "error: $(echo "$resp" | jq -r .error)" >&2
        return 1
    fi
}
```

**Notice the things that matter:**

- Token is fetched *after* the confirm, so aborting the confirm doesn't even touch the vault.
- `--dry-run` returns **before** the token fetch.
- `unset tok` runs immediately after the request.
- The dry-run line shows `<redacted>` for the message body — even though the message itself isn't a secret, this keeps the output shape predictable and grep-friendly.
- The method and path (`Slack POST /api/chat.postMessage`) are on one grep-able line.

---

## Step 7 — Add the module to the manifest

Edit `modules.manifest`. Add `slack` under `[hardened]`:

```
[hardened]
...
# Slack messaging — post to channels via chat.postMessage. Uses
# SLACK_BOT_TOKEN from the vault. Writes (post) are --yes-gated.
slack
```

Rebuild:

```bash
bash scripts/build-scrt4.sh hardened /tmp/scrt4-hardened
```

If the build fails, the error is usually one of:
- **Module file missing** — typo in the manifest name vs filename.
- **Syntax error in your `.sh` file** — `bash -n daemon/bin/scrt4-modules/slack.sh` catches most.
- **Missing `scrt4_module_slack_register`** — the required public function isn't defined.

---

## Step 8 — Commit and open a PR

```bash
git add daemon/bin/scrt4-modules/slack.sh modules.manifest
git commit -m "add slack module — chat.postMessage via SLACK_BOT_TOKEN"
```

In the PR description, include:

- **What the module does** (one paragraph).
- **Which secrets it reads** (paste the `reveals:` line).
- **Which subcommands are mutating** and how they're gated.

Reviewers will check against the don't-leak-secrets checklist in `MODULES.md` §6.

---

## 9. Faster path: the `create-scrt4-module` skill

If you're using Claude Code, the `create-scrt4-module` skill automates steps 2–7 from a short description:

```
/create-scrt4-module
```

The skill will ask you:
1. Module name
2. Which secrets it reads (for the `reveals:` header)
3. One sentence on what each subcommand does
4. For each subcommand: read-only or mutating?
5. External tool: REST API (like github/stripe), CLI wrapper (like gcp), or local-only (like wallet)?

Then it scaffolds the module file and the manifest entry. You still need to fill in the actual curl/CLI calls for each subcommand, but the boilerplate (header, register, dispatch, help, flag parser, confirm helper) is written for you.

---

## 10. Cheat sheet

```bash
# File to create
daemon/bin/scrt4-modules/<name>.sh

# Required public functions in your .sh
scrt4_module_<name>_register()     # binds subcommands
scrt4_module_<name>_dispatch()     # fans out based on $1

# Required internal helpers (convention, not enforced)
_scrt4_<name>_help()               # 'help' subcommand
_scrt4_<name>_parse_flags()        # --dry-run, --yes
_scrt4_<name>_confirm()            # interactive vs --yes
_scrt4_<name>_<subcommand>()       # one per subcommand

# Must-have header fields
# scrt4-module: <name>
# version: 1
# api: 1
# tcb: false
# commands: <space-separated>
# reveals: <space-separated exact names>

# Build
bash scripts/build-scrt4.sh hardened /tmp/scrt4-hardened
```

That's it. If something here doesn't work, read `MODULES.md` — this doc is the how, that doc is the why.
