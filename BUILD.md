# Building scrt4 from source

Building from source is currently the only supported way to install scrt4 from
this repository. It is also how you verify that what runs on your machine is
what is written here.

## What you need

| Requirement | Minimum | Notes |
|---|---|---|
| Rust toolchain | 1.75+ | `rustup` from [rustup.rs](https://rustup.rs) |
| A WebAuthn authenticator | — | See the README for supported devices |

**That is the whole list.** The daemon builds with nothing but a Rust
toolchain on every platform — no OpenSSL, no vcpkg, no system crypto
libraries. `webauthn-rs` is deliberately *not* a dependency: the WebAuthn
ceremony runs in the browser, and the daemon only ever handles the AES-GCM
wrapped PRF output.

The bash client (Linux, macOS, WSL) also needs:

| Tool | Why |
|---|---|
| `bash`, `jq` | the client is a bash script that reads the daemon's JSON replies with `jq` |
| `socat` **or** `python3` | to talk to the daemon's Unix socket (socat first, python3 otherwise) |
| Chrome (or another browser) | for the local passkey page (`setup --local`, `unlock --local`) |

Platform extras, only if you want the optional client-side pieces:

| Platform | Extra | For |
|---|---|---|
| Linux / macOS | `zenity` (Linux) | the `scrt4 view` GUI editor |
| Windows | PowerShell 5.1+ | the PowerShell client (ships with Windows) |

---

## Build the daemon

```bash
git clone https://github.com/llmsecrets/llm-secrets.git
cd llm-secrets/scrt4/daemon
cargo build --release
```

Two binaries land in `target/release/`:

| Binary | What it is |
|---|---|
| `scrt4-daemon` | The vault process. Owns the key, runs the auth flow, injects secrets. |
| `scrt4` | The Rust CLI front end. |

### Verify the build

```bash
cargo test
```

The suite runs without an authenticator: the WebAuthn ceremony happens in the
browser, so the daemon's tests exercise everything below the PRF boundary
directly.

---

## Install the OS layer

### Linux, macOS, WSL

The bash client is assembled from the core dispatcher:

```bash
cd llm-secrets/scrt4
bash scripts/build-scrt4.sh core-only ./scrt4
install -m 755 ./scrt4 ~/.local/bin/scrt4
install -m 755 daemon/target/release/scrt4-daemon ~/.local/bin/scrt4-daemon
```

`core-only` is the distribution with no modules — the one this repository
ships. Run the daemon under a systemd user unit or launchd agent so it starts
with your session; it listens on a Unix socket at `$XDG_RUNTIME_DIR/scrt4.sock`
(or `/tmp/scrt4-$UID.sock`).

### Windows

The PowerShell client lives in `scrt4/windows/`. Copy the module directory onto
your PowerShell module path and put the `.cmd` shim on `PATH`:

```powershell
$dest = "$env:LOCALAPPDATA\scrt4"
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item -Recurse scrt4\windows\scrt4      $dest
Copy-Item          scrt4\windows\scrt4-cli.ps1 $dest
Copy-Item          scrt4\windows\scrt4.cmd     $dest
Copy-Item          scrt4\daemon\target\release\scrt4-daemon.exe $dest
```

Then add `%LOCALAPPDATA%\scrt4` to `PATH` and open a new terminal.

> **Use `scrt4.cmd` as the entry point, not `scrt4.ps1`.** On `PATH`, PowerShell
> resolves a `.ps1` ahead of a `.cmd`, so a bare `.ps1` entry point runs under
> whatever execution policy is in force and fails on a Restricted machine with
> "running scripts is disabled". The `.cmd` shim re-invokes with
> `-ExecutionPolicy Bypass`, works identically in `cmd.exe` and PowerShell, and
> needs no policy change. This is why the implementation file is named
> `scrt4-cli.ps1` rather than `scrt4.ps1`.

The daemon communicates over a named pipe (`scrt4-<user>`) rather than a Unix
socket, and unlock runs through Windows Hello on `localhost:9474`.

---

## Run your local build (Linux, macOS, WSL)

After the build and install steps above, `~/.local/bin` holds `scrt4` (the bash client) and `scrt4-daemon`.
Make sure `~/.local/bin` is on your `PATH`.

### 1. Start the daemon

```bash
scrt4 daemon          # runs in the foreground; leave this terminal open
# or in the background:
scrt4-daemon &
```

Check it from another terminal:

```bash
scrt4 status          # {"success":true,"data":{"active":false,...}} = running, vault locked
```

"Daemon not reachable" means it is not running, or it is running with a different `XDG_RUNTIME_DIR`.
To start it with your login session on Linux, use a systemd user unit:

```ini
# ~/.config/systemd/user/scrt4-daemon.service
[Unit]
Description=scrt4 daemon

[Service]
ExecStart=%h/.local/bin/scrt4-daemon
Restart=on-failure

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload && systemctl --user enable --now scrt4-daemon
```

### 2. First run: create the vault, then add this device's passkey

```bash
scrt4 setup             # one time: scan the QR code and register your phone's passkey
scrt4 setup --local     # optional: add this device's passkey (Touch ID, Windows Hello, a YubiKey)
```

`setup --local` opens the daemon's approval page on `http://localhost:9474` in Chrome. To use it on a
machine you reach over SSH, forward the port and open the printed URL on your own computer:
`ssh -L 9474:127.0.0.1:9474 <host>`.
Set `SCRT4_NO_BROWSER=1` on that machine so scrt4 only prints the URL instead of also opening a browser
there (`export SCRT4_NO_BROWSER=1`, or put it in your shell profile).

### 3. Every day

```bash
scrt4 unlock --local    # unlock with this device's passkey (or: scrt4 unlock, with your phone)
scrt4 add API_KEY=...   # add a secret
scrt4 list              # names only, never values
scrt4 run 'curl -H "Authorization: Bearer $env[API_KEY]" https://example.com'
scrt4 lock              # end the session
```

Sensitive commands (`view`, `backup-key`, `rotate`, `setup --local`) ask for a fresh passkey approval
each time. `rotate` with a local passkey re-wraps that passkey's copy of the key, so it keeps working
afterwards. Your phone passkey needs `scrt4 setup` again after a rotate; `rotate` says so when that applies.

### 4. Rebuild after pulling changes

```bash
cd llm-secrets && git pull
(cd scrt4/daemon && cargo build --release)
bash scrt4/scripts/build-scrt4.sh core-only ~/.local/bin/scrt4
scrt4 lock                                   # restarting the daemon ends the session anyway
pkill -x scrt4-daemon                        # or: systemctl --user stop scrt4-daemon
install -m 755 scrt4/daemon/target/release/scrt4-daemon ~/.local/bin/scrt4-daemon
scrt4-daemon &                               # or: systemctl --user start scrt4-daemon
scrt4 unlock --local
```

### 5. Check what you are running

```bash
scrt4 --version         # a build from this repository reports a -community version
(cd scrt4/daemon && cargo test)
```

Working on scrt4 itself, or letting an agent do it? Read **[AGENTS.md](./AGENTS.md)** first: it explains how
to run a second, isolated daemon so tests never touch your real vault.

---

## Unsigned builds on Windows

A binary you compiled yourself is unsigned, and Windows will treat it as such.

- **SmartScreen** shows "Windows protected your PC". Choose *More info* →
  *Run anyway*.
- **Smart App Control**, if enabled, blocks it outright — there is no
  "run anyway". The symptom is "An Application Control policy has blocked this
  file", logged in Event Viewer under
  `Microsoft-Windows-CodeIntegrity/Operational` as ID 3033 or 3077.

Two workarounds while code-signing is in progress:

1. Build with `cargo build` instead of `cargo build --release`. Debug binaries
   are frequently allowed where release binaries are blocked.
2. Turn Smart App Control off: Windows Security → App & browser control →
   Smart App Control settings. **This is a one-way switch** — Windows will not
   let you re-enable it without reinstalling.

---

## Reproducing a build

`Cargo.lock` is committed, so `cargo build --release` resolves the exact
dependency versions used here. To check a binary against source:

```bash
cargo build --release
sha256sum target/release/scrt4-daemon
```

Rust builds are not yet bit-for-bit reproducible across toolchain versions, so
compare hashes only against a build made with the same `rustc --version` on the
same target triple.

---

## Building the old desktop app

The Electron app, the WSL daemon and the original CLI are no longer part of
this repository. Their source and build instructions are preserved on the
`archive/legacy-stack` branch. They are unmaintained and receive no security
updates — do not deploy them.
