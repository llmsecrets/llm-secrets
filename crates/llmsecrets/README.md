# LLM Secrets

**This crate is the project namespace. The tool you want is [`scrt4`](https://crates.io/crates/scrt4).**

```sh
cargo install scrt4
```

---

## What the project does

When an AI coding agent with shell access reads a `.env` file, your keys land
in its context window — and in the prompt cache, the logs, and every error you
paste afterwards. Nothing has gone wrong; the value is simply in more places
than you can enumerate.

LLM Secrets keeps secrets in an encrypted vault. The agent writes a command
with a placeholder; the daemon substitutes the real value into that one
subprocess and scrubs it back out of the output before anything returns to the
model.

```console
$ scrt4 add STRIPE_SECRET_KEY=sk_live_...
$ scrt4 run 'stripe --api-key $env[STRIPE_SECRET_KEY] charges list'
```

The agent sees the command. It never sees the value.

## The key is not a file

The vault key is derived from a FIDO2 authenticator via the WebAuthn PRF
extension (CTAP2 `hmac-secret`), re-derived each session, and never written to
disk.

Encrypted-`.env` tools keep a private key on disk — anything that can read the
filesystem can decrypt. There is no file to read here: opening the vault needs
a tap on your phone, a security key, or Windows Hello.

Encrypted `.env` is *git-safe*. This is *agent-safe*.

## Not to be confused with

The **`llm-secrets`** crate — with a hyphen — is an unrelated project by a
different author. This one is <https://llmsecrets.com>.

## Links

- Install: `cargo install scrt4`, or <https://llmsecrets.com/downloads>
- Source: <https://github.com/llmsecrets/llm-secrets>
- Docs: <https://docs.llmsecrets.com>

AGPL-3.0-only.
