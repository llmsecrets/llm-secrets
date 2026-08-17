# scrt4

**Let an AI coding agent use your credentials without ever seeing them.**

When Claude Code, Cursor, or any agent with shell access reads a `.env` file,
your keys land in its context window — and in the prompt cache, the logs, and
every error you paste afterwards. Nothing has gone wrong; the value is simply
in more places than you can enumerate.

scrt4 keeps secrets in an encrypted vault. The agent writes a command with a
placeholder; the daemon substitutes the real value into that one subprocess
and scrubs it back out of the output before anything returns to the model.

```console
$ scrt4 add STRIPE_SECRET_KEY=sk_live_...
$ scrt4 run 'stripe --api-key $env[STRIPE_SECRET_KEY] charges list'
```

The agent sees the command. It never sees the value.

## The key is not a file

The vault key is derived from a FIDO2 authenticator via the WebAuthn PRF
extension (CTAP2 `hmac-secret`), re-derived each session, and never written
to disk.

That distinction is the whole design. Encrypted-`.env` tools keep a private
key on disk — anything that can read the filesystem can decrypt. There is no
file to read here: opening the vault needs a tap on your phone, a security
key, or Touch ID / Windows Hello.

Encrypted `.env` is *git-safe*. This is *agent-safe*. Different problems.

## Install

```sh
cargo install scrt4
```

That builds two binaries: `scrt4-daemon`, which owns the vault, and `scrt4`,
the client that talks to it over a Unix socket (a named pipe on Windows).

Prebuilt, checksum-verified binaries and the full bash client are at
**<https://llmsecrets.com/downloads>**. `scrt4 verify-self` checks a running
binary against the published manifest at any time.

## What it does not do

- It cannot help if you paste a secret into a chat window. Nothing can.
- It does not touch your editor. If a completion model has already indexed a
  file containing a key, that has happened.
- It is not a team secrets manager — one person, their devices, their keys.
- Lose the authenticator with no backup and the vault is gone. There is no
  reset, because there is no server.

## Platforms

macOS (Apple Silicon), Linux (`x86_64` / `aarch64`, glibc 2.34+), Windows
(PowerShell 5.1+), and WSL.

## Links

- Source and issues: <https://github.com/llmsecrets/llm-secrets>
- Documentation: <https://docs.llmsecrets.com>
- Threat model: [`SECURITY.md`](https://github.com/llmsecrets/llm-secrets/blob/main/scrt4/SECURITY.md)

AGPL-3.0-only.
