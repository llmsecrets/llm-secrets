# install.llmsecrets.com

Source of truth for the content served at https://install.llmsecrets.com.

## Files

- **`scrt4-docker.sh`** — v0.1.0 one-command Docker wrapper. Creates a named
  container `scrt4` from `:latest` on first run, reattaches on every subsequent
  run. Vault, Claude Code auth, and shell history persist in the container's own
  filesystem. No named volumes, no bind mounts, no Docker-Desktop-plus-WSL
  engine mismatch.
- **`scrt4-v2-docker.sh`** — v0.2 modular one-command Docker wrapper. Same
  behaviour as the v0.1.0 wrapper but pulls
  `joshgottlieb/scrt4-hardened:v0.2-modular` instead of `:latest`. Served at
  `https://install.llmsecrets.com/v2`.
- **`sync-scrt4-install.sh`** — the systemd-timer-driven script that runs on
  the GCP host every 60s. Pulls main, copies the live content into
  `/var/www/install/`.
- **`deploy-setup.sh`** — one-shot bootstrap script for a fresh server. Creates
  the deploy key, clones the repo, installs the sync script, and wires up the
  systemd timer. Idempotent — safe to re-run.
- **`Caddyfile.install-block`** — the Caddy vhost block deployed to
  `/etc/caddy/Caddyfile` on the GCP server. Kept in version control for
  reference.

## Hosting architecture

```
GitHub push to main
        │
        ▼
┌──────────────────────────────────────────┐
│  GCP: prod-repo-app-instance-v001        │
│                                          │
│  /etc/systemd/system/                    │
│    scrt4-install-sync.timer (every 60s)  │
│      → scrt4-install-sync.service        │
│        → /usr/local/bin/sync-scrt4-install│
│          - git fetch + reset main        │
│          - copy install/*.sh to webroot  │
│                                          │
│  /var/www/install/  ← served by Caddy    │
│                                          │
│  Caddy vhost: install.llmsecrets.com     │
│    - TLS via Let's Encrypt (auto)        │
│    - root → /var/www/install/            │
│    - / rewritten to /scrt4-docker.sh     │
└──────────────────────────────────────────┘
        ▲
        │  https (auto TLS)
        │
    curl | sh
```

- **DNS**: GoDaddy A record `install.llmsecrets.com` → `136.107.239.113`.
- **Auth for git pull**: read-only deploy key (SSH) registered on the repo.
  Key pair lives at `/root/.ssh/scrt4_deploy{,.pub}` on the server.
- **Sync cadence**: 60s. A push to main is live within ~90s (timer + sync).
- **Why not `reverse_proxy` to raw.githubusercontent.com**: repo is private,
  raw returns 404 without authentication.

## URL map

| URL | Serves |
|---|---|
| `/` | `scrt4-docker.sh` — v0.1.0 stable (primary onboarding path) |
| `/v2` | `scrt4-v2-docker.sh` — v0.2 modular |
| `/scrt4-docker.sh` | `scrt4-docker.sh` |
| `/scrt4-v2-docker.sh` | `scrt4-v2-docker.sh` |
| `/install.sh` | Rust installer (if present in repo root on main) |

## Usage

```bash
# v0.1.0 stable (recommended for most users):
curl -fsSL https://install.llmsecrets.com | sh

# v0.2 modular architecture:
curl -fsSL https://install.llmsecrets.com/v2 | sh

# Install the wrapper as a permanent host command:
sudo curl -fsSL https://install.llmsecrets.com -o /usr/local/bin/scrt4
sudo chmod +x /usr/local/bin/scrt4
scrt4
```

## Server bootstrap (one-time)

On a fresh server, as root:

```bash
# Copy deploy-setup.sh to the server
sudo bash deploy-setup.sh

# Copy the public key it prints and add it as a read-only deploy key
# at https://github.com/VestedJosh/scrt4/settings/keys
# Then re-run deploy-setup.sh — it's idempotent.
sudo bash deploy-setup.sh
```

Append the `Caddyfile.install-block` contents to `/etc/caddy/Caddyfile` and
`sudo systemctl reload caddy`. Caddy will obtain the Let's Encrypt cert on
first request.

## CI

`.github/workflows/install-smoke-test.yml` shellchecks the wrapper on every
PR and verifies the live URL returns the updated content after every push to
main (waits up to ~5 minutes for the sync timer to fire and the content to
propagate).
