# Using scrt4 with coding agents

Written in response to a question about GitHub Copilot, which is the worked
example throughout. The same three points apply to Claude Code, Cursor, Aider,
Continue, or anything else that reads your workspace and proposes commands.

The short version: **scrt4 does not integrate with an agent, and that is the
design.** There is no plugin, no extension, and nothing to configure per tool.

---

## A day with it

Maya is adding a webhook handler. Her project needs a live Stripe key to test
against, and she has Copilot on in the editor and Copilot CLI in the terminal.

**Before.** `STRIPE_SECRET_KEY=sk_live_…` sits in `.env`. The moment Copilot
indexes the workspace, that value is in its context. When she asks for help
with the handler, the value travels with the request. It lands in the
completion cache. If she pastes an error, it goes with it. Nothing has gone
wrong yet — the key just exists in a great many more places than she intended,
and she cannot enumerate them.

**After.** The value lives in the vault. `.env` is gone. Her editor sees:

```python
stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
```

which is what she would have written anyway, and tells Copilot nothing.

She needs to hit the API to check a charge. Copilot CLI suggests:

```bash
curl -H "Authorization: Bearer $STRIPE_SECRET_KEY" https://api.stripe.com/v1/charges
```

She runs it through scrt4:

```bash
scrt4 run 'curl -H "Authorization: Bearer $env[STRIPE_SECRET_KEY]" https://api.stripe.com/v1/charges'
```

The daemon substitutes the value into the environment of that one `curl`
process. It is not in her shell, not in `~/.bash_history`, not in any
environment variable Copilot could read, and the daemon scrubs it from the
output before she sees it — so even if Stripe echoed the key back in an error,
pasting that error somewhere would not carry it.

Her terminal was never a place the secret existed.

Later she runs the test suite the same way:

```bash
scrt4 run 'pytest tests/test_webhook.py'
```

Same story. `pytest` gets the environment; she does not.

**What is still on her.** If she pastes a suggestion that has a literal key in
it, scrt4 is not in the path and cannot help. The wrapping is a habit, not an
interception.

---

## How it works

Substitution happens inside the daemon, into the environment of a child
process:

```
your command  ──▶  daemon substitutes $env[NAME]  ──▶  child process runs
                   (values from the vault)             with the values
                                                              │
       output  ◀──  values scrubbed from stdout  ◀────────────┘
```

The boundary is the subprocess. Not the agent's API, not an editor plugin.
That is why there is nothing to integrate: whatever drives your terminal, the
mechanism is identical, and a per-agent hook would have nothing to attach to.

It also means the guarantee is narrow and worth stating exactly. scrt4 keeps
values out of **your shell, your history, your environment, and command
output**. It cannot do anything about a value you type into a chat window.

---

## Copilot CLI

Copilot CLI proposes a command; you decide whether to run it. So wrap what it
gives you:

```bash
scrt4 run 'aws s3 ls --profile $env[AWS_PROFILE]'
scrt4 run 'psql $env[DATABASE_URL] -c "select count(*) from users"'
```

On Windows the placeholder is the same, but the command runs through
`cmd.exe`, so quote for that shell:

```powershell
scrt4 run "curl -H ""Authorization: Bearer $env[GITHUB_PAT]"" https://api.github.com/user"
```

Two things to know:

- **Nothing is intercepted automatically.** A pasted suggestion containing a
  real value bypasses scrt4 entirely.
- **`run` uses your current directory** and takes `--cwd DIR` to override it.
  Before 0.4.0 it ran from the daemon's own directory, which broke relative
  paths and project-local interpreters. If relative paths behave oddly,
  check your version first.

---

## Copilot in the editor

This is a different situation and the distinction matters.

Editor completions are drawn from your open files and your workspace. **scrt4
cannot filter that.** It never sees your editor, and it has no view of what is
sent for a completion.

What it does instead is remove the reason a secret is in a file. The value is
in the vault; your code reads it from the environment at runtime. If the value
is not in a file, it cannot be completed from one, sent as context, or cached
alongside a suggestion.

The protection is structural, not active. That is a weaker-sounding claim than
"we block it", and a considerably more reliable one.

If you want a second control, GitHub's **content exclusion** settings keep
specified paths out of Copilot's context at the repository or organisation
level. The two complement each other: content exclusion says "do not read this
file", scrt4 says "this file does not contain the secret".

---

## Setting it up

```bash
scrt4 setup                                  # once — enrol your authenticator
scrt4 unlock                                 # start a session
scrt4 add STRIPE_SECRET_KEY=sk_live_...      # move the value into the vault
scrt4 list                                   # names only, never values
scrt4 run 'your-command $env[STRIPE_SECRET_KEY]'
```

Then **delete the plaintext `.env`.**

That last step is the one people skip, and it is the one that decides whether
any of this mattered. Everything above is theatre while a copy is still in the
workspace.

If a teammate needs the same secret, they run `scrt4 add` on their own machine
against their own authenticator. There is no shared file to leak.

---

## What this does not do

Stated plainly, because a security tool that oversells itself is worse than
one that does less:

- **It does not read your mind about pasting.** Type a secret into a chat and
  it is in that chat.
- **It does not inspect editor traffic.** No completion is filtered, blocked
  or rewritten.
- **It does not protect a value you have already leaked.** Rotate it; scrt4
  helps from the next key onward, not the last one.
- **It does not change your PATH.** A command runs with the daemon's
  environment, so an activated virtualenv is reachable as `.venv/bin/python`,
  not as bare `python`.

What it does do is make the common case — a long-lived credential sitting in a
file that every tool on your machine can read — stop being the default.
