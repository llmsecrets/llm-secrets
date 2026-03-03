# Scrt WSL2 Daemon

Secure secret management daemon for WSL2 with Windows Hello biometric authentication.

## Version 0.3.0

Features:

- **Windows Hello** — Biometric authentication bridged from Windows to WSL2
- **Session Management** — Configurable TTL (1-24 hours, default 2 hours)
- **Secret Injection** — `$env[NAME]` substitution in subprocess commands
- **Output Sanitization** — Leaked values replaced with `[REDACTED:NAME]`
- **Extend Session** — Reset timer without re-authenticating
- **GUI View** — View secrets in zenity dialog (invisible to AI agents)

## Quick Install (from source)

**Prerequisites:** Rust toolchain (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)

```bash
git clone https://github.com/llmsecrets/llm-secrets.git
cd llm-secrets/wsl-daemon
make install
```

This builds both binaries, installs them to `~/.local/bin`, sets up the systemd service, and starts the daemon.

Make sure `~/.local/bin` is in your PATH:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Add the above line to your `~/.bashrc` or `~/.zshrc` to make it permanent.

## Quick Install (from tarball)

```bash
curl -sL https://downloads.llmsecrets.com/scrt-wsl-0.3.0.tar.gz | tar xz
cd scrt-wsl-0.3.0
./install/install.sh
```

The install script auto-detects pre-built binaries in `bin/` or compiled binaries in `target/release/`.

## Dependencies

**Required:**
- `jq` — JSON parsing
- `socat` or `netcat-openbsd` — Unix socket communication

**Optional:**
- `zenity` — GUI features (`scrt view`)

Install on Ubuntu/Debian:
```bash
sudo apt install jq socat zenity
```

Install on Arch:
```bash
sudo pacman -S jq socat zenity
```

## Usage

```bash
scrt unlock [ttl]      # Authenticate with Windows Hello (default: 7200s)
scrt status            # Check session status
scrt list              # List secret names
scrt run <command>     # Run command with $env[NAME] substitution
scrt add KEY=val ...   # Add secrets to active session
scrt view              # View secrets in GUI (zenity, invisible to agents)
scrt extend [ttl]      # Reset session timer
scrt logout            # Lock session (aliases: lock, clear)
scrt check-hello       # Check Windows Hello availability
scrt migrate <key>     # Migrate secrets from old master key
scrt backup-key        # Show current master key (save securely!)
scrt help              # Show help
scrt --version         # Show version
```

## Session Management

Sessions automatically expire after the configured TTL. To extend without re-authenticating:

```bash
# Reset timer to current TTL
scrt extend

# Reset timer with new 4-hour TTL
scrt extend 14400
```

## Examples

```bash
# Authenticate (2 hour session)
scrt unlock

# 8 hour session
scrt unlock 28800

# List secret names
scrt list

# Run a command with secrets injected
scrt run 'curl -H "Authorization: Bearer $env[API_KEY]" https://api.example.com'

# Add a secret
scrt add API_KEY=sk-123

# View all secrets in GUI
scrt view
```

## Security Model

- Secrets encrypted at rest with AES-256-CBC
- Windows Hello biometric required to unlock
- Secrets exist only in daemon memory after unlock
- Automatic session expiry (configurable TTL)
- Output sanitization prevents secret leakage
- Unix socket restricted to current user (0600)
- `scrt view` displays in GUI dialog — invisible to AI agents

## Uninstall

```bash
make uninstall
```

Or manually:

```bash
systemctl --user stop scrt-daemon
systemctl --user disable scrt-daemon
rm ~/.local/bin/scrt ~/.local/bin/scrt-daemon ~/.local/bin/scrt-client
rm ~/.config/systemd/user/scrt-daemon.service
systemctl --user daemon-reload
```

## Building from Source

```bash
# Build only (no install)
make build

# Run tests
make test

# Clean build artifacts
make clean
```

## Security Notice

This package has been scanned for secrets before distribution.
Source code is included in `src/` for transparency and auditability.

To verify the build:
```bash
make build
```
