# Release Topology

How source → build → host → install flows fit together. This is the
map to stare at when something isn't showing up where you expect.

Sister documents:
- `docs/RELEASE.md` — the hardened Docker image flow (main-only).
- `docs/ARCHITECTURE-V0.2.md` — what the binaries actually do.
- `install/server-setup-release-user.sh` — one-time CI → server setup.

---

## 1. Editions at a glance

There are **two parallel distributions**, each with its own branch, build
pipeline, and host path. Don't mix them up.

| | Hardened edition | Community edition (native-default) |
|---|---|---|
| Ships to | Docker Hub: `joshgottlieb/scrt4-hardened` | `install.llmsecrets.com/releases/<tag>/` |
| Source branch | `main` | `public/llmsecrets-sanitized` |
| Build workflow | `.github/workflows/docker-publish.yml` | `.github/workflows/release.yml` |
| Trigger | push to main (path-filtered) or `v*.*.*` tag | `v*.*.*` tag push |
| Artifacts | Docker image (multi-arch) | `scrt4-daemon-<os>-<arch>` × 4 + `scrt4` bash CLI + `SHA256SUMS` |
| Install | `curl install.llmsecrets.com \| sh` (Docker wrapper) | `curl install.llmsecrets.com/native \| sh` |
| Auth | Docker Hub anon pull | Public (sha256-verified, served by Caddy) |
| Distribution | Single `native-default` distribution + all opt-in modules available | Same CLI logic; `hardened` distribution of modules (no network-effectful commands) |

The **hardened** path is the trusted-computing-base edition — runs in a
container, no network modules. The **community** path is the "power
user" edition — full native install, opt-in modules, FIDO2-backed.

---

## 2. Source layout → artifact

```
scrt4 repo (private)
├── daemon/
│   ├── bin/
│   │   ├── scrt4-core              ← TCB + dispatcher                 →  (1)
│   │   ├── scrt4-modules/<name>.sh ← module sources                   →  (1) and (3)
│   │   └── scrt4                   ← v0.1 monolith (hardened only)    →  (2)
│   └── src/                        ← Rust daemon (all editions)       →  (2) and (4)
├── scripts/build-scrt4.sh          ← assembles (1) from core + modules per manifest
├── modules.manifest                ← [hardened|native-default|core-only] sections
├── install/
│   ├── scrt4-native.sh             ← /native installer                →  (3)
│   ├── scrt4-docker.sh             ← / (v0.1 Docker wrapper)          →  (3)
│   ├── scrt4-v2-docker.sh          ← /v2 (v0.2 Docker wrapper)        →  (3)
│   ├── scrt4-zenity-macos.sh       ← /zenity-macos (osascript shim)   →  (3)
│   ├── scrt4-uninstall.sh          ← /uninstall                       →  (3)
│   ├── sync-scrt4-install.sh       ← server-side 60s sync driver      →  (5)
│   ├── server-setup-release-user.sh← one-time setup for CI SSH deploy
│   ├── Caddyfile.install-block     ← the install.llmsecrets.com vhost
│   ├── modules-whitelist.json      ← approved module names             →  (3) as modules.json
│   └── deploy-setup.sh             ← one-time git deploy-key setup for (5)
└── .github/workflows/
    ├── release.yml                 ← tag → binaries + GitHub Release + scp to host
    ├── docker-publish.yml          ← main → Docker Hub image
    ├── install-smoke-test.yml      ← PR → shellcheck + post-merge live-URL verify
    └── guard-publish-triggers.yml  ← tripwire — blocks non-main publish triggers

   (1) Assembled scrt4 bash CLI (native-default, opt-in slices, etc.)
   (2) Hardened Docker image
   (3) Published as curl-installable scripts on install.llmsecrets.com
   (4) Rust daemon binary — 4 × (os × arch)
   (5) Sync timer keeps /var/www/install/ scripts in lockstep with branch (60s cadence)
```

---

## 3. Host: install.llmsecrets.com

All paths are Caddy routes on `prod-repo-app-instance-v001` (us-east4-c).
The vhost snippet lives at `install/Caddyfile.install-block` in this repo;
`install/sync-scrt4-install.sh` keeps it propagated.

| URL | Served file on disk | Source in repo | Update path |
|---|---|---|---|
| `/`                    | `/var/www/install/scrt4-docker.sh`        | `install/scrt4-docker.sh`        | Sync timer (60s) |
| `/v2`                  | `/var/www/install/scrt4-v2-docker.sh`     | `install/scrt4-v2-docker.sh`     | Sync timer (60s) |
| `/native`              | `/var/www/install/scrt4-native.sh`        | `install/scrt4-native.sh`        | Sync timer (60s) |
| `/zenity-macos`        | `/var/www/install/scrt4-zenity-macos.sh`  | `install/scrt4-zenity-macos.sh`  | Sync timer (60s) |
| `/uninstall`           | `/var/www/install/scrt4-uninstall.sh`     | `install/scrt4-uninstall.sh`     | Sync timer (60s) |
| `/modules.json`        | `/var/www/install/modules.json`           | generated from `install/modules-whitelist.json` + per-module `sha256sum` | Sync timer (60s) |
| `/modules/<name>.sh`   | `/var/www/install/modules/<name>.sh`      | `daemon/bin/scrt4-modules/<name>.sh` (whitelisted entries only) | Sync timer (60s) |
| `/releases/latest.txt` | `/var/www/install/releases/latest.txt`    | n/a (written at tag time)        | `release.yml` on tag push |
| `/releases/<tag>/scrt4-daemon-<os>-<arch>` | `/var/www/install/releases/<tag>/…` | Built from `daemon/src/` | `release.yml` on tag push |
| `/releases/<tag>/scrt4` | `/var/www/install/releases/<tag>/scrt4`  | Built from `scrt4-core` + native-default modules via `scripts/build-scrt4.sh` | `release.yml` on tag push |
| `/releases/<tag>/SHA256SUMS` | `/var/www/install/releases/<tag>/SHA256SUMS` | `sha256sum out/*` in CI | `release.yml` on tag push |

The auth relay sits on the same host under a different vhost:

| URL | Served file on disk | Source in repo | Update path |
|---|---|---|---|
| `auth.llmsecrets.com/auth.html`  | `/home/jgott/scrt4-relay/public/auth.html`  | `auth-relay/public/auth.html`  | `deploy-relay.yml` on push |
| `auth.llmsecrets.com/index.html` | `/home/jgott/scrt4-relay/public/index.html` | `auth-relay/public/index.html` | `deploy-relay.yml` on push |
| `auth.llmsecrets.com/sw.js`      | `/home/jgott/scrt4-relay/public/sw.js`      | `auth-relay/public/sw.js`      | `deploy-relay.yml` on push |

**Three update mechanisms:**
- **Sync timer (60s)**: scripts + module files + modules.json. A merge to
  `public/llmsecrets-sanitized` is served within 60 seconds. Drives (3)
  in the source map above.
- **Tag push (release.yml)**: release binaries + latest.txt. Fires when
  a `v*.*.*` tag is pushed. Drives (4) — binaries — plus a fresh copy of
  the assembled bash CLI.
- **Relay push (deploy-relay.yml)**: auth-relay/public/*.* static files.
  Fires on any push to `main` / `public/llmsecrets-sanitized` that touches
  `auth-relay/**`, so the WebAuthn page can iterate independently of tags.

---

## 4. Sync timer — `scrt4-install-sync.timer`

On the server:
- Unit: `/etc/systemd/system/scrt4-install-sync.timer` (cadence: 60s)
- Service: `/etc/systemd/system/scrt4-install-sync.service`
- Script: `/usr/local/bin/sync-scrt4-install` (copy of `install/sync-scrt4-install.sh`)
- Checkout: `/var/lib/scrt4-install/` (git clone of the repo via deploy key)
- Branch: `public/llmsecrets-sanitized`

```
  [public/llmsecrets-sanitized] ─ push ─►  github
                                             ▲
                                     60 s    │ fetch + reset --hard
                                             │
     [/var/lib/scrt4-install]  ◄──── sync ───┤
                │
                │ install -m 644 www-data:www-data
                ▼
      [/var/www/install/*.sh]  ◄─ served ─► install.llmsecrets.com/*
```

The sync script:
1. `git fetch --quiet origin public/llmsecrets-sanitized`
2. `git reset --quiet --hard origin/public/llmsecrets-sanitized`
3. `install`s each installer script (`scrt4-docker.sh`, `scrt4-v2-docker.sh`,
   `scrt4-native.sh`, `scrt4-zenity-macos.sh`, `scrt4-uninstall.sh`) into
   `/var/www/install/`
4. Iterates `install/modules-whitelist.json`, copies each approved module
   file out of `daemon/bin/scrt4-modules/` to `/var/www/install/modules/`,
   `sha256sum`s each, and writes the combined manifest to
   `/var/www/install/modules.json`
5. Prunes stale `modules/*.sh` files no longer on the whitelist

**Important:** the sync timer does NOT touch `/var/www/install/releases/`.
That's the exclusive domain of the tag-push release pipeline in section 5.

---

## 5. Release pipeline — `.github/workflows/release.yml`

Trigger: `git push origin v*.*.*` (or `workflow_dispatch` with an existing tag).

```
  git tag v0.2.1-community + git push --tags
            │
            ▼
  ┌─────────────────────── release.yml ───────────────────────┐
  │                                                           │
  │  build-daemon (matrix, 4 jobs)     build-cli (1 job)      │
  │  ├─ linux-x86_64    cargo build    └─ scripts/build-scrt4.sh
  │  ├─ linux-aarch64   (cross)           native-default → scrt4
  │  ├─ darwin-x86_64   macos-13          SCRT4_VERSION stamped from tag
  │  └─ darwin-aarch64  macos-latest                          │
  │         │                   │                             │
  │         └──────────┬────────┘                             │
  │                    ▼                                      │
  │                 publish (1 job)                           │
  │           ├─ sha256sum → SHA256SUMS                       │
  │           ├─ softprops/action-gh-release → GitHub Release │
  │           └─ scp to scrt4-release@prod-repo-app-...       │
  │                  ├─ /var/www/install/releases/<tag>/      │
  │                  │   ├─ scrt4-daemon-linux-x86_64         │
  │                  │   ├─ scrt4-daemon-linux-aarch64        │
  │                  │   ├─ scrt4-daemon-darwin-x86_64        │
  │                  │   ├─ scrt4-daemon-darwin-aarch64       │
  │                  │   ├─ scrt4                             │
  │                  │   └─ SHA256SUMS                        │
  │                  └─ mv latest.txt.new → latest.txt        │
  │                                                           │
  └───────────────────────────────────────────────────────────┘
```

### GitHub Actions secrets

Set once in repo Settings → Secrets → Actions:

| Secret | Purpose |
|---|---|
| `SCRT4_RELEASE_SSH_KEY`    | Private ed25519 for `scrt4-release` user on prod |
| `SCRT4_RELEASE_SSH_HOST`   | IP or FQDN of prod-repo-app-instance-v001 |
| `SCRT4_RELEASE_SSH_USER`   | `scrt4-release` |
| `SCRT4_RELEASE_SSH_KNOWN_HOSTS` | Output of `ssh-keyscan <host>` — pins the SSH host key |

If any of these are unset, the deploy step prints a warning and exits 0
(soft-fail) so the GitHub Release is still cut even without llmsecrets.com
push. Re-run `release.yml` with `workflow_dispatch` after setting the
secrets to deploy retroactively.

### Server-side setup

`install/server-setup-release-user.sh` (run once on prod-repo-app-instance-v001):
- Creates the `scrt4-release` user
- Generates an ed25519 keypair at `/home/scrt4-release/.ssh/id_ed25519`
- Installs an SSH force-command wrapper so `scrt4-release` can ONLY scp
  into `/var/www/install/releases/` or `/home/jgott/scrt4-relay/public/`
  and perform the two atomic-rename ops the pipelines actually use
  (no arbitrary shell commands allowed)
- Prepares `/var/www/install/releases/` with `2775 scrt4-release:www-data`
- Flips `/home/jgott/scrt4-relay/public/` to `2775 jgott:www-data` (setgid)
  so `scrt4-release` (a member of `www-data`) can drop new `auth.html` via
  the relay workflow without taking ownership of Josh's interactive dir
- Prints the pubkey, privkey, and known_hosts lines for copy-paste

### Version stamping

`scripts/build-scrt4.sh` honors `SCRT4_VERSION=<tag>` — it rewrites the
`VERSION="..."` line in `scrt4-core` at build time. CI passes
`SCRT4_VERSION=${{ github.ref_name }}` so `scrt4 help` / `scrt4 --version`
on an installed binary prints e.g. `0.2.1-community`, not `0.2.0-dev`.

---

## 5b. Relay pipeline — `.github/workflows/deploy-relay.yml`

Trigger: push to `main` / `public/llmsecrets-sanitized` that touches
`auth-relay/**`, or manual `workflow_dispatch`.

```
  edit auth-relay/public/auth.html + git push
            │
            ▼
  ┌─────────────── deploy-relay.yml ───────────────┐
  │                                                │
  │  for each file in auth-relay/public/*          │
  │    scp  <f>  remote:/home/jgott/scrt4-relay/   │
  │              public/<f>.new                    │
  │    ssh  mv   <f>.new → <f>  (atomic)           │
  │                                                │
  │  curl auth.llmsecrets.com/auth.html | grep     │
  │       detectPlatform  (smoke test)             │
  └────────────────────────────────────────────────┘
```

Uses the same `SCRT4_RELEASE_SSH_*` secrets as the binary release. The
auth-relay flow is intentionally detached from `v*.*.*` tags — a picker
UX tweak or copy change ships within seconds of `git push` without
cutting a full release.

Same soft-fail behavior: if secrets are unset the step warns and exits 0.

---

## 6. Install curl commands

### Community edition — native installer

```bash
# Core + native-default (encrypt-folder + import-env + cloud-crypt), no extra modules
curl -fsSL https://install.llmsecrets.com/native | sh

# Opt-in to whitelisted modules (repeatable)
curl -fsSL https://install.llmsecrets.com/native | sh -s -- --module github
curl -fsSL https://install.llmsecrets.com/native | sh -s -- --module github --module stripe

# Env-var alternative (comma-separated)
curl -fsSL https://install.llmsecrets.com/native | SCRT4_MODULES=github,stripe sh

# Pin a specific release (bypasses latest.txt)
curl -fsSL https://install.llmsecrets.com/native | SCRT4_VERSION=v0.2.1-community sh

# Install binaries only, skip systemd/launchd service setup
curl -fsSL https://install.llmsecrets.com/native | SCRT4_SKIP_SERVICE=1 sh

# Point at a local test mirror (forks / dev)
curl -fsSL https://install.llmsecrets.com/native | \
    SCRT4_RELEASE_BASE_URL=https://my-mirror.example.com/releases \
    SCRT4_MANIFEST_URL=https://my-mirror.example.com/modules.json \
    SCRT4_MODULES_BASE_URL=https://my-mirror.example.com/modules sh
```

**What the installer does:**
1. Detects OS + arch (linux/darwin × x86_64/aarch64)
2. Installs `jq`, `qrencode`, and (Linux desktop only) `zenity` via
   apt/dnf/yum/pacman/apk/brew — adapts the error message if Homebrew is
   missing on Darwin
3. Resolves `$VERSION` — either explicit `SCRT4_VERSION` or fetches
   `/releases/latest.txt`
4. Downloads `scrt4-daemon-<os>-<arch>`, `scrt4`, and `SHA256SUMS`
5. SHA256-verifies both binaries against the checksum file
6. If `--module NAME` was passed: fetches the whitelist, sha-pins each
   requested module, fetches each `/modules/<name>.sh`, splices them into
   the core CLI at the hook marker, `bash -n` syntax-checks the result
7. Installs binaries to `/usr/local/bin` (if writable) or `~/.local/bin`
8. On macOS: installs the `zenity` osascript shim (`/zenity-macos`) and a
   launchd agent
9. On Linux: installs a `systemctl --user` unit that auto-starts the daemon
10. Writes an install manifest to
    `$XDG_CONFIG_HOME/scrt4/install-manifest` listing every file it wrote.
    The uninstaller reads this and deletes only listed paths — prevents
    the "dev cargo build got nuked" footgun.

### Hardened edition — Docker wrapper

```bash
# v0.1 monolith (default route, /)
curl -fsSL https://install.llmsecrets.com/     | sh

# v0.2 modular (route /v2)
curl -fsSL https://install.llmsecrets.com/v2   | sh
```

Both wrappers `docker run` the `joshgottlieb/scrt4-hardened:latest` image
and drop a `scrt4` shim into `~/.local/bin/scrt4` that forwards every
invocation through `docker exec`.

---

## 7. Uninstall curl commands

```bash
# Interactive — prompts before removing the container and before any vault action
curl -fsSL https://install.llmsecrets.com/uninstall | sh

# Non-interactive — binaries + services + Docker container, KEEPS the encrypted vault
curl -fsSL https://install.llmsecrets.com/uninstall | sh -s -- --yes

# Non-interactive — also DELETES ~/.scrt4 (irreversible; no recovery without backup)
curl -fsSL https://install.llmsecrets.com/uninstall | sh -s -- --yes --purge

# Scoped variants
curl -fsSL https://install.llmsecrets.com/uninstall | sh -s -- --yes --docker-only
curl -fsSL https://install.llmsecrets.com/uninstall | sh -s -- --yes --native-only
```

**What the uninstaller does:**
1. Warns if it's running inside a scrt4 source checkout (dev-machine footgun)
2. `pkill`s matching `scrt4-daemon`, `scrt4 unlock`, `scrt4 view` so
   blocked FIDO2 prompts don't hold open fd's to the binary
3. Disables + removes the systemd unit (Linux) or launchd plist (Mac)
4. **Manifest path:** reads `$XDG_CONFIG_HOME/scrt4/install-manifest`
   and deletes only paths listed there. This is the safe default.
5. **Heuristic path** (pre-manifest installs): strictly checks the
   binary's content signature before deleting, and refuses to remove
   `scrt4-daemon` unless `--yes` or `SCRT4_INSTALL_DIR` was explicitly set
6. Removes the runtime socket
7. Removes Docker container (prompted) and Docker wrappers (content-check)
8. Keeps the encrypted vault at `~/.scrt4` **unless** `--purge` is passed
   with explicit `DELETE`-typed confirmation

---

## 8. Cutting a release — end-to-end playbook

```bash
# 1. Land all changes to public/llmsecrets-sanitized
git checkout public/llmsecrets-sanitized
git pull --ff-only
# ... merges ...

# 2. Wait (up to 60 s) — sync timer picks up any install/*.sh changes.
#    Verify the new installer is live:
curl -fsSL https://install.llmsecrets.com/native | head -20

# 3. Tag + push. release.yml takes it from here.
git tag -a v0.2.1-community -m "v0.2.1: bash 3.2 compat + darwin binaries"
git push origin v0.2.1-community

# 4. Watch the run
gh run watch --exit-status

# 5. Verify live
curl -fsSL https://install.llmsecrets.com/releases/latest.txt      # → v0.2.1-community
curl -fsSL -o /tmp/daemon https://install.llmsecrets.com/releases/v0.2.1-community/scrt4-daemon-linux-x86_64
curl -fsSL    https://install.llmsecrets.com/releases/v0.2.1-community/SHA256SUMS
```

If the GHA deploy step soft-failed because secrets aren't set:
1. Run `install/server-setup-release-user.sh` on prod (as root)
2. Paste the four secret values into repo Settings → Secrets → Actions
3. `gh workflow run release.yml -f tag=v0.2.1-community` to re-deploy
