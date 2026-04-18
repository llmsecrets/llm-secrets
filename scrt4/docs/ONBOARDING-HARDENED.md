# Getting started with scrt4 — hardened Docker distribution

> **This guide is specifically for the hardened Docker distribution of scrt4** (`joshgottlieb/scrt4-hardened`), released as **v0.1.0**. It does not cover the bash/GPG `scrt` build or the `scrt2` daemon — those are separate distributions with their own setup. If you ran `curl -fsSL https://install.llmsecrets.com | sh`, this is the right guide for you.
>
> From zero to your first shared secret in about 5 minutes.

## The whole install

```sh
curl -fsSL https://install.llmsecrets.com | sh
```

That's it. One line. After it finishes you'll be inside a container with everything ready. Read on for what to do next.

---

## What scrt4 actually does

scrt4 is a secret manager — it stores API keys, private keys, RPC URLs, passwords, and any other text you don't want sitting in plain files. The values are encrypted on disk with AES-256-GCM, and the encryption key is derived from a passkey on your phone or YubiKey via FIDO2/WebAuthn. There's no master password to remember, no `.env` files to accidentally commit, and the secret values are never returned to anything you might paste into a chat window.

When you need to use a secret in a shell command, you write the command with a placeholder like `$env[ALCHEMY_RPC_URL]`, hand the whole thing to `scrt4 run`, and the value is injected into the subprocess environment at the moment of execution. The value never appears on your terminal or in shell history.

The **hardened distribution** — the one this guide covers — is all of the above, packaged as a Docker container with Claude Code preinstalled. It runs entirely inside Docker and never touches your host filesystem outside the container's own volumes, so it works the same on WSL, Linux, and macOS. If you want scrt4 to live on your host instead of inside a container, look at the bash `scrt` build or the `scrt2` daemon — those are separate projects.

---

## What you need before you start

| Requirement | Notes |
|---|---|
| **A terminal** | On Windows: open WSL (Ubuntu). On macOS: Terminal or iTerm. On Linux: any terminal app. |
| **Docker installed** | Docker Desktop on Windows/macOS, or Docker Engine on Linux. Test with `docker --version`. |
| **A phone with a passkey app** | iCloud Keychain (iPhone), Google Password Manager (Android), 1Password, or any FIDO2 authenticator. You'll scan a QR code with it once during setup. |
| **curl** | Already installed everywhere. Test with `curl --version`. |

---

## Step 1 — Install

Paste this into your terminal and press Enter:

```sh
curl -fsSL https://install.llmsecrets.com | sh
```

What happens, in order:

1. The wrapper script downloads itself to `~/.local/bin/scrt4` (Linux/WSL) or `/usr/local/bin/scrt4` (macOS), so next time you can just type `scrt4` instead of the full curl line.
2. It pulls the latest hardened image from Docker Hub (`joshgottlieb/scrt4-hardened:latest`).
3. It creates a Docker container named `scrt4` and drops you into a bash shell inside it.
4. A welcome banner prints the most useful commands.

Your prompt should now look like `scrt@a1b2c3d4e5f6:~$` — that's the inside-the-container prompt.

---

## Step 2 — Register your passkey (one time only)

Inside the container, run:

```sh
scrt4 setup agent
```

The terminal will print a QR code and a URL like `https://auth.llmsecrets.com/auth.html?m=register&...`

1. Scan the QR code with your phone (open the camera app, point it at the QR, tap the link that pops up).
2. On your phone, tap **Register Passkey**.
3. Your phone will prompt you to use Face ID, Touch ID, or your screen lock — that's saving the passkey to your device.
4. Back in the terminal you'll see `Credential registered successfully!`

> ⚠️ **Important:** the passkey lives on your phone, not on your computer. It's the only way to unlock the vault. Treat it with the same care as a hardware wallet seed phrase — losing both the phone and the encrypted vault backup means the secrets are unrecoverable.

> **No passwords or TOTP codes.** scrt4 uses FIDO2/WebAuthn exclusively. The master key is derived from your authenticator's `hmac-secret` extension on every unlock — it is never stored in plaintext. As long as you have your authenticator, you can always re-derive the key.

---

## Step 3 — Unlock

Setup is one-time. After that, you unlock once per session (default 20 hours):

```sh
scrt4 unlock
```

Same thing happens — QR code, scan with phone, this time tap **Unlock**. You'll see `Session active. Expires in 19h 59m.`

From this point on, every `scrt4 add`, `scrt4 list`, `scrt4 run` works without touching your phone again until the session expires.

---

## Step 4 — Add your first secret

```sh
scrt4 add OPENAI_API_KEY=sk-proj-abc123...
```

Or add many at once interactively:

```sh
scrt4 add
```

If you have a `.env` file already, import it in one shot:

```sh
scrt4 import ~/path/to/.env
```

List the names of what you have stored (values are never shown):

```sh
scrt4 list
```

---

## Step 5 — Use a secret in a command

Wrap the command in `scrt4 run '...'` and reference the secret with `$env[NAME]`:

```sh
scrt4 run 'curl -H "Authorization: Bearer $env[OPENAI_API_KEY]" https://api.openai.com/v1/models'
```

scrt4 substitutes the real value into the subprocess only — your terminal still shows the placeholder, your shell history saves the placeholder, and any AI assistant pasted into the same window only sees the placeholder.

Use single quotes around the command so your shell doesn't try to expand `$env[NAME]` before scrt4 sees it.

---

## Step 6 — Move secrets to another machine

When you set up a new laptop or want to share a vault between machines, use Magic Wormhole. The transfer is end-to-end encrypted with a one-time code; no cloud, no relay storage.

**On the source machine** (where the secrets currently live):

```sh
scrt4 share --all
```

A wormhole code appears, looking something like `7-crossover-headline`. Underneath it the terminal will tell you exactly what to run on the other machine.

**On the destination machine** (after running setup + unlock there):

```sh
scrt4 receive --code 7-crossover-headline
```

The transfer happens in seconds. You'll see a list of every secret being received, then a prompt:

```
Import these secrets into your vault? [Y/n]
```

Press Enter (or Y). Done.

---

## Day-to-day usage

| Command | What it does |
|---|---|
| `scrt4` | Re-enter the container (run on the **host**, not inside) |
| `exit` | Leave the container (state is preserved) |
| `scrt4 status` | Check whether the session is active and how long it has left |
| `scrt4 list` | List all secret names (values never appear) |
| `scrt4 add KEY=value` | Add or update a single secret |
| `scrt4 run 'cmd $env[KEY]'` | Run a command with secret injection |
| `scrt4 view` | Open a GUI editor to edit secrets (works on machines with a display) |
| `scrt4 backup-vault` | Back up the encrypted vault to a tar.gz |
| `scrt4 backup-key` | Print the master key (requires authenticator tap) |
| `scrt4 backup-key --save DIR` | Save the master key as a password-encrypted file |
| `scrt4 backup-guide` | Show the full backup & recovery guide |
| `scrt4 logout` | Lock the session immediately (re-run unlock to come back) |
| `scrt4 menu` | Interactive menu (GUI on machines with a display, text help on headless) |
| `scrt4 help` | Full command list with examples |

---

## Backup & recovery

scrt4 uses FIDO2/WebAuthn — your hardware authenticator derives the master key on every unlock. There is no master password to forget. Recovery depends on what you've lost:

### You still have your authenticator (phone/YubiKey)

Nothing to recover. Just authenticate again:

```sh
scrt4 unlock        # tap your authenticator → session active
```

The same master key is derived every time. All your secrets are immediately accessible.

### Your authenticator is lost or broken

You need **both** of these:

1. **The encrypted vault** — created with `scrt4 backup-vault`
2. **The master key** — either written down from `scrt4 backup-key`, or saved as a password-encrypted file with `scrt4 backup-key --save DIR`

```sh
# Recover the master key from the password-encrypted backup:
scrt4 recover encrypted-master-key-instructions.json

# Then re-register a new authenticator:
scrt4 setup
```

Without both the vault and the master key, recovery is impossible by design.

### What to back up (do this once after setup)

```sh
scrt4 backup-vault --local /path/to/USB   # encrypted vault
scrt4 backup-key --save /path/to/USB      # password-encrypted master key
```

Store the USB in a safe. The vault backup is still encrypted — it's useless without the master key. The master key file is password-protected — it's useless without the password you set.

---

## Claude Code is preinstalled

The hardened image ships with Claude Code already installed and three shortcuts ready to go:

| Command | What it does |
|---|---|
| `claude` | Start Claude Code normally — every tool call asks for permission |
| `oc` | YOLO mode — `claude --dangerously-skip-permissions`. Use this when you trust the task and want speed. |
| `cc` | YOLO + resume the last session |

Your Claude Code login persists in `~/.claude` inside the container, so you only sign in once.

---

## What persists, what doesn't

| State | Persistence |
|---|---|
| ✅ **Survives across exits** | Encrypted vault (`~/.scrt4`), Claude Code login (`~/.claude`), shell history. You can `exit` the container, reboot your machine, come back tomorrow with `scrt4`, and everything is right where you left it. |
| ⚠ **Resets on session expire** | The unlock token (default 20 hours). After that, run `scrt4 unlock` again — phone tap, done. |
| ❌ **Wiped permanently** | `docker rm -f scrt4` destroys the container and its volumes. The vault is gone unless you backed it up first. Only run this when you genuinely want to start over. |

---

## How to upgrade

When a new release comes out:

```sh
docker rm -f scrt4
scrt4
```

The wrapper auto-pulls the latest image on first run, so this just works.

**Before you do this, back up the vault if you've added secrets you can't lose:**

```sh
scrt4 backup-vault
```

---

## Pin to v0.1.0 (for reproducibility)

If you want a frozen, never-changing image (CI environments, shared documentation, etc.):

```sh
SCRT4_IMAGE=joshgottlieb/scrt4-hardened:0.1.0 scrt4
```

---

## Troubleshooting

### "Permission denied" when running scrt4

A non-executable leftover from an old install. Run `sudo chmod +x /usr/local/bin/scrt4`, or just re-curl: `curl -fsSL https://install.llmsecrets.com | sh` — the wrapper detects and repairs this automatically.

### "scrt4: command not found"

Your shell hasn't picked up the new PATH. Open a new terminal window. If that doesn't help, run `source ~/.bashrc` (or `~/.zshrc` on macOS).

### Recreated the container but I'm seeing an old bug

Pre-v0.1.0 wrappers didn't auto-pull. If you're upgrading from an earlier build, force a fresh image once:

```sh
docker rmi joshgottlieb/scrt4-hardened:latest
curl -fsSL https://install.llmsecrets.com | sh
```

From v0.1.0 onward, `docker rm -f scrt4 && scrt4` is enough.

### QR code looks cut off in the terminal

Press `Ctrl+0` (Windows Terminal) or zoom out to make the font smaller. Or copy the URL printed below the QR and open it on your phone manually.

### "Cancelled. No secrets imported." after scrt4 receive

This bug existed before v0.1.0 — the import prompt failed silently in the headless container. v0.1.0 fixes it. If you're seeing it on a fresh install, you're on a stale cached image; force-pull as described above.

### Where do my secrets actually live?

Inside the container at `~/.scrt4`, encrypted with AES-256-GCM. Docker stores the underlying volume on your host but it's only meaningful when mounted into the container. Use `scrt4 backup-vault` for portable backups.

---

## What scrt4 actually guarantees

| An LLM agent CAN see | An LLM agent CANNOT see |
|---|---|
| Secret *names* like `PRIVATE_KEY` | Secret *values* like `0x7f3a...` |
| The *shape* of commands you write | The injected runtime values |
| Transaction hashes, tx receipts, success/failure messages | Private keys, mnemonics, API tokens, passwords |

The agent writes `scrt4 run 'forge script ... --private-key $env[PRIVATE_KEY]'` — the daemon resolves `$env[PRIVATE_KEY]` into the subprocess only, then forgets. The value never crosses back into the LLM context window.

---

## Links

- **Project:** [github.com/VestedJosh/scrt4](https://github.com/VestedJosh/scrt4)
- **This release:** [v0.1.0](https://github.com/VestedJosh/scrt4/releases/tag/v0.1.0)
- **Image:** `joshgottlieb/scrt4-hardened:0.1.0`
- **Install URL:** [install.llmsecrets.com](https://install.llmsecrets.com)
- **Release & publishing process:** [docs/RELEASE.md](RELEASE.md)
