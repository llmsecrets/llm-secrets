# Scrt WSL2 Daemon

Secure secret management daemon for WSL2 with Windows Hello biometric authentication.

## Version 0.2.0 (Stable)

This is a stable release with full session management controls:

- **Session Duration** — Configurable TTL (1-24 hours, default 2 hours)
- **Extend Session** — Reset timer without re-authenticating
- **Set Duration** — Change TTL and reset timer on the fly
- **Refresh Session** — Lock and re-authenticate via Windows Hello

## Installation

```bash
# Build
cargo build --release

# Install
cp target/release/scrt-daemon ~/.local/bin/
cp bin/scrt ~/.local/bin/
chmod +x ~/.local/bin/scrt

# Enable systemd service
systemctl --user enable scrt-daemon
systemctl --user start scrt-daemon
```

## Usage

```bash
scrt unlock [ttl]      # Authenticate with Windows Hello (ttl in seconds)
scrt status            # Check session status
scrt extend [ttl]      # Reset session timer (no re-auth required)
scrt list              # List secret names
scrt run <command>     # Run command with secret injection
scrt view              # View secrets in GUI (invisible to agents)
scrt edit              # Edit secrets in GUI
scrt add [KEY=val]     # Add secrets
scrt gui               # Open GUI dashboard
scrt logout            # Lock session
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

Or use `scrt gui` and select:
- **Extend Session** — Quick reset
- **Set Duration** — Pick 1-24 hours
- **Refresh Session** — Full re-auth via Windows Hello

## Security Model

- Secrets encrypted at rest with AES-256-CBC
- Windows Hello biometric required to unlock
- Secrets exist only in daemon memory after unlock
- Automatic session expiry (configurable TTL)
- Output sanitization prevents secret leakage
- Unix socket restricted to current user

---

## Security Notice

This package has been scanned for secrets before distribution.
Source code is included in `src/` for transparency and auditability.

To verify the build:
```bash
cd src && cargo build --release
```

SHA256 checksums are published alongside the download.
