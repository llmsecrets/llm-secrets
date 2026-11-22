# AGENTS.md

Guidance for coding agents (Claude Code, Codex, Cursor, …) and contributors working in this repository.
How to build, test and run scrt4 locally is in **[BUILD.md](./BUILD.md)**. This file is the short version
plus the rules that keep a local build from touching anyone's real vault.

## What is where

| Path | What it is |
|---|---|
| `scrt4/daemon/` | The Rust daemon (`scrt4-daemon`) and the Rust CLI (`scrt4`). Owns the key, runs the passkey ceremonies, injects secrets. |
| `scrt4/daemon/src/protocol.rs` | Every request the daemon accepts. |
| `scrt4/daemon/src/session_binding.rs` | Which requests need the session token. The `match` is exhaustive on purpose. |
| `scrt4/daemon/bin/scrt4-core` | The bash client for Linux, macOS and WSL. |
| `scrt4/scripts/build-scrt4.sh` | Assembles the installable bash client from `scrt4-core` (`core-only`). |
| `scrt4/windows/` | The PowerShell client. |
| `scrt4/auth-relay/` | The phone ceremony page served by the relay. |
| `disaster-recovery/` | Recovering a vault without scrt4 installed. |

## Build and test

```bash
cd scrt4/daemon
cargo build                 # or --release
cargo test                  # needs no authenticator
cd ..
bash scripts/build-scrt4.sh core-only /tmp/scrt4    # assembles the client and runs bash -n on it
```

Before opening a PR, all three must pass, and `cargo build` must not add new warnings.

## Running a local build without touching a real vault

A person running this repo very likely has a real scrt4 on the same machine: a daemon on
`$XDG_RUNTIME_DIR/scrt4.sock`, a vault in `~/.scrt4`, and the approval page on `localhost:9474`.

- **Never** run tests against the real `~/.scrt4`, the real socket, or the user's daemon. Don't stop,
  restart or replace a daemon you did not start.
- Isolate a test daemon and client with their own folders: the client takes its socket from
  `XDG_RUNTIME_DIR` and its config (including `session.token`) from `$HOME/.scrt4`; the daemon also honours
  `SCRT4_CONFIG_DIR`.

  ```bash
  export HOME=/tmp/scrt4-test/home XDG_RUNTIME_DIR=/tmp/scrt4-test/run
  mkdir -p "$HOME" "$XDG_RUNTIME_DIR" && chmod 700 "$XDG_RUNTIME_DIR"
  ./daemon/target/debug/scrt4-daemon &      # check the socket is under /tmp/scrt4-test before using the client
  bash /tmp/scrt4 status
  ```

- The local approval page always listens on port 9474. While the user's own daemon shows a ceremony there,
  a second daemon cannot, so don't run local ceremonies next to a real one.
- `SCRT4_DEV_MODE=1` starts the daemon unlocked with a fixed, **public** key (vault in `~/.scrt4-dev`). It is
  for daemon development only. Known gap: the bash client can't get a session token from a dev daemon, so
  `list`/`add` through the client are refused with "requires the session token".

## Rules for changes

- **New daemon request:** add it to `protocol.rs`, the dispatch in `handlers.rs`, **and** `session_binding.rs`.
  The match there is exhaustive so the build forces the decision. A new token-exempt method must also update
  the exempt-set test and say why it is exempt.
- **Session tokens:** every ceremony that completes an unlock (`unlock_local_complete`, the relay unlock, and the
  step-up inside `_wa_gate`) starts a new session with a new token. The client must save it with
  `_save_session_token`, or every following request is refused.
- **Key wrappers:** the master key is stored wrapped by a passkey (`master-local.key` for the local passkey,
  `master.key` for the phone). Anything that changes the master key must re-wrap the wrapper or report it stale
  (see `rotate_vault_local`).
- **Approvals are per purpose:** a pending local ceremony is tagged unlock / register / rotate, and a completion
  only accepts its own kind. Keep it that way for new ceremonies.
- **Socket timeouts:** a request that waits for a person (any `*_complete`) needs a long timeout. `send_request`
  passes it to socat with `-t`; the socat default (0.5 s) silently drops the reply.
- **Secrets:** never print, log or commit a secret value or a master key, including in tests, PR text and
  terminal output you paste. `backup-key` and `rotate` print the master key; keep that output out of an agent's
  context.
- **Windows checkouts:** clone with `git -c core.autocrlf=false clone …`. The bash client must keep LF line
  endings.

## Commits and PRs

Conventional prefixes (`fix(cli):`, `fix(daemon):`, `feat(unix):`, `docs:`). PRs are squash-merged with `(#N)`
in the title. Say how the change was checked.
