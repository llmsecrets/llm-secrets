# Releasing scrt4-community

End-to-end release automation for scrt4-community. One command, one version
bump, three hosts (GitHub Releases, install.llmsecrets.com, llmsecrets.com).

## TL;DR

```bash
scrt4 unlock
./scripts/release.sh 0.2.15
```

That's the happy path. The rest of this doc explains what that command does,
what can go wrong, and which pieces you might want to run by hand.

## What `release.sh` does

1. **Pre-flight.** Refuses to run unless:
   - current branch is `public/llmsecrets-sanitized`
   - working tree is clean
   - `scrt4 status` shows an unlocked session (secret injection for `gh` and
     `gcloud` auth needs it)
   - the target tag doesn't already exist locally or on the remote
   - `gh`, `gcloud`, `rsync`, `curl`, `python3`, `sha256sum`, and (if the
     site step runs) `vercel` are all on `PATH`
2. **Bump + rebuild.** Edits `VERSION="…"` in `daemon/bin/scrt4-core`, then
   re-runs `scripts/build-scrt4.sh` to regenerate `daemon/bin/scrt4`.
3. **Installer hash.** Computes `sha256sum install/scrt4-native.sh` and writes
   `install/scrt4-native.sh.sha256` (committed alongside the bump).
4. **Commit + tag + push.** One commit, one annotated tag `v<version>-community`,
   push both to `origin`.
5. **CI watch.** Polls `gh run list --workflow=release.yml` until the run for
   the new tag appears, then `gh run watch --exit-status`. Fails loud if CI fails.
6. **Pull artifacts.** Downloads `scrt4`, the three daemon binaries, and
   `SHA256SUMS` into a local stage dir. Copies `install/scrt4-native.sh` and
   its `.sha256` in alongside.
7. **Two-hosts-one-hash.** Uploads `scrt4-native.sh` + `scrt4-native.sh.sha256`
   back to the GitHub Release with `gh release upload --clobber`. That's the
   second host; install.llmsecrets.com is the first.
8. **Install host.** `gcloud compute scp` the release dir into `/tmp/` on the
   VM, then `ssh` + `sudo install` into `/var/www/install/releases/$TAG/`, then
   atomically rewrite `latest.txt` (write `.new`, `mv` over old).
9. **Verify.** Curls three endpoints in sequence and asserts the bytes are
   current: `releases/latest.txt`, `releases/$TAG/SHA256SUMS`, `native.sha256`.
   The last one lives behind the systemd sync timer (~60s), so it polls
   up to 24×5s before failing.
10. **`/downloads` update.** Rewrites the version tag and `scrt4` hash in
    `llmsecrets-site/downloads/index.html` via Python regex, runs
    `vercel deploy --prod` in that dir (through `scrt4 run`, so the token stays
    injected). Skippable with `--no-site`.
11. **Community mirror.** `rsync`s the sanitized source tree into
    `llm-secrets-community/scrt4/`, commits, and pushes. Skippable with
    `--no-mirror`.

## Why local, not CI

- CI doesn't have `scrt4` (no hardware authenticator in a runner).
- The install-host deploy step in `.github/workflows/release.yml` exits 0 with a
  warning when the SSH secrets (`SCRT4_RELEASE_SSH_KEY`, `_HOST`, `_USER`,
  `_KNOWN_HOSTS`) are unset — which they currently are. Until those are
  populated, CI publishes the GitHub Release and this script takes it from there.
- The Vercel deploy for `/downloads` is on `v3-deploy`, which is CLI-only (no
  git link). It has to be pushed from a machine that can authenticate.

If the CI SSH secrets get wired up later, step 8 of this script is redundant —
delete it and rely on CI. The rest still needs to run locally.

## Flags and env overrides

| Flag | Effect |
|------|--------|
| `--dry-run` | Everything except commits, pushes, uploads, and server mutations |
| `--no-site` | Skip `/downloads` edit + Vercel deploy |
| `--no-mirror` | Skip the `llm-secrets-community` sync |

| Env var | Default | Purpose |
|---------|---------|---------|
| `SCRT4_SITE_DIR` | `/mnt/c/Users/jgott/OneDrive/Desktop/llmsecrets-site` | llmsecrets.com local checkout |
| `SCRT4_MIRROR_DIR` | `/mnt/c/Users/jgott/OneDrive/Desktop/llm-secrets-community` | community mirror local checkout |
| `SCRT4_GCP_INSTANCE` | `prod-repo-app-instance-v001` | install host VM |
| `SCRT4_GCP_ZONE` | `us-east4-c` | GCE zone |
| `SCRT4_VERCEL_BIN` | `/home/jgott/.npm-global/bin/vercel` | Vercel CLI path (PATH inside `scrt4 run` is minimal) |

## The two-hosts-one-hash check

Users who don't blindly pipe `curl | sh` can verify the installer against two
independent origins. Both must return the same hash:

```bash
curl -fsSL https://install.llmsecrets.com/native.sha256
curl -fsSL https://github.com/VestedJosh/scrt4/releases/latest/download/scrt4-native.sh.sha256
```

The file is committed at `install/scrt4-native.sh.sha256`, synced to the install
host by `install/sync-scrt4-install.sh` (systemd timer, every 60s), and
uploaded to the GitHub Release by step 7 of this script. Caddy rewrites
`/native.sha256` → `/scrt4-native.sh.sha256` (see
`install/Caddyfile.install-block`).

The `/downloads` page shows the hash inside a `<div id="script-sha256">` slot;
the release script updates that slot in lockstep with the other version bumps,
so the published hash always matches the hash on both hosts.

## When something goes wrong

**CI fails.** `gh run view` the run that the script was watching, fix the
underlying issue, then delete the tag both locally and on the remote and re-run:

```bash
git tag -d v0.2.15-community
git push origin :refs/tags/v0.2.15-community
./scripts/release.sh 0.2.15
```

**Install host SCP fails.** Check `CLOUDSDK_CONFIG` points at the Windows
gcloud config (the script falls back to `/mnt/c/Users/jgott/AppData/Roaming/gcloud`
if unset). Run the gcloud commands by hand to get a clearer error.

**`/native.sha256` endpoint 404s after deploy.** Either the Caddy rewrite for
`/native.sha256` isn't applied on the VM, or the systemd sync timer hasn't run
yet. The script retries for 2 minutes. Beyond that, ssh in and check:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl status scrt4-install-sync.timer
ls -la /var/www/install/scrt4-native.sh.sha256
```

**Vercel deploy hangs or reports "deploying your home directory".** The `cd`
has to live inside the `scrt4 run '...'` string — not before it. The parent
shell's working directory doesn't carry into the subprocess.

**Community mirror push rejected.** Someone pushed to `scrt4-community` branch
in the meantime. Rebase or reset the local mirror checkout; the script only
publishes a fresh snapshot, nothing there is authored by humans.

## One-off first-time setup

If you're running `release.sh` for the first time on a new machine, make sure:

- `scrt4` is installed and a session is unlocked (`scrt4 unlock`).
- `gh` is authenticated as someone who can push tags to `VestedJosh/scrt4` and
  upload assets to releases.
- `gcloud` has a config dir the script can read (WSL default:
  `/mnt/c/Users/jgott/AppData/Roaming/gcloud`) and the account can reach the
  VM via `gcloud compute ssh`.
- The two local checkouts (site + mirror) exist and are on the branch the
  script expects (`main` for both).
- `vercel login` has been run in the site dir and the `.vercel/project.json`
  has the v3-deploy IDs (see
  `~/.claude/projects/-mnt-c-Users-jgott-OneDrive-Desktop-scrt4/memory/reference_vercel_v3deploy_link.md`).

## Manual fallback (if you can't run the script)

Each step maps to a manual command. In rough order:

```bash
# 1–4
vim daemon/bin/scrt4-core              # bump VERSION
./scripts/build-scrt4.sh               # rebuild daemon/bin/scrt4
sha256sum install/scrt4-native.sh | awk '{print $1}' > install/scrt4-native.sh.sha256
git add -A && git commit -m "release: v$V-community"
git tag -a "v$V-community" -m "v$V-community"
git push origin public/llmsecrets-sanitized "v$V-community"

# 5
gh run watch --exit-status $(gh run list --workflow=release.yml -b public/llmsecrets-sanitized -L1 --json databaseId -q '.[0].databaseId')

# 6–7
mkdir /tmp/rel && cd /tmp/rel
gh release download "v$V-community" -p '*'
cp path/to/scrt4/install/scrt4-native.sh .
cp path/to/scrt4/install/scrt4-native.sh.sha256 .
gh release upload "v$V-community" scrt4-native.sh scrt4-native.sh.sha256 --clobber

# 8
CLOUDSDK_CONFIG=/mnt/c/Users/jgott/AppData/Roaming/gcloud gcloud compute scp --zone us-east4-c --recurse /tmp/rel prod-repo-app-instance-v001:/tmp/rel-staging
# … then ssh in, sudo install into /var/www/install/releases/v$V-community/, flip latest.txt

# 9
curl -fsSL https://install.llmsecrets.com/releases/latest.txt
curl -fsSL "https://install.llmsecrets.com/releases/v$V-community/SHA256SUMS"
curl -fsSL https://install.llmsecrets.com/native.sha256

# 10–11 — edit the site, vercel deploy, rsync the mirror, commit, push
```
