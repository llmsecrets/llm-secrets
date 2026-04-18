#!/usr/bin/env bash
# scripts/release.sh — end-to-end scrt4-community release orchestrator.
#
# Automates what used to be a manual multi-step dance:
#
#   1. Pre-flight (branch, clean tree, unlocked scrt4 session, tag free)
#   2. Bump VERSION in scrt4-core, rebuild daemon/bin/scrt4 artifact
#   3. Compute SHA256 of install/scrt4-native.sh, commit the .sha256 file
#   4. Commit the version bump, tag v<VERSION>-community, push
#   5. Watch GitHub Actions release.yml until the GH Release publishes
#   6. Download artifacts from the GH Release into a stage dir
#   7. Upload scrt4-native.sh + its .sha256 back to the GH Release
#      (so the install script + its hash are attested on two hosts)
#   8. scp artifacts to the install host; atomically flip latest.txt
#   9. Verify the install host and /native.sha256 end-to-end
#  10. Optionally update llmsecrets.com/downloads (tag + scrt4 hash) + Vercel deploy
#  11. Optionally mirror scrt4/ subtree into the llmsecrets/llm-secrets community repo
#
# Secrets come from a live scrt4 session — no SSH keys or tokens live in this
# script. Requires: scrt4, gh, gcloud (CLOUDSDK_CONFIG), rsync, curl, python3,
# sha256sum, vercel CLI (if updating /downloads).
#
# Usage:
#   ./scripts/release.sh 0.2.15           # canonical form
#   ./scripts/release.sh v0.2.15          # leading v is fine
#   ./scripts/release.sh 0.2.15 --dry-run # everything except commits/pushes/uploads
#   ./scripts/release.sh 0.2.15 --no-site # skip /downloads update
#   ./scripts/release.sh 0.2.15 --no-mirror # skip llmsecrets/llm-secrets sync

set -euo pipefail

# ── Args ────────────────────────────────────────────────────────────────

VERSION_ARG=""
DRY_RUN=0
DO_SITE=1
DO_MIRROR=1
for arg in "$@"; do
    case "$arg" in
        --dry-run)   DRY_RUN=1 ;;
        --no-site)   DO_SITE=0 ;;
        --no-mirror) DO_MIRROR=0 ;;
        -h|--help)
            sed -n '3,27p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        -*)
            echo "unknown flag: $arg" >&2; exit 2 ;;
        *)
            if [[ -z "$VERSION_ARG" ]]; then VERSION_ARG="$arg"
            else echo "unexpected extra arg: $arg" >&2; exit 2
            fi ;;
    esac
done

[[ -n "$VERSION_ARG" ]] || { echo "usage: $0 <version>   (e.g. 0.2.15)" >&2; exit 2; }

VERSION="${VERSION_ARG#v}"
case "$VERSION" in
    *-community) ;;
    *) VERSION="${VERSION}-community" ;;
esac
TAG="v$VERSION"

# ── Paths ───────────────────────────────────────────────────────────────

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

SITE_DIR="${SCRT4_SITE_DIR:-/mnt/c/Users/jgott/OneDrive/Desktop/llmsecrets-site}"
MIRROR_DIR="${SCRT4_MIRROR_DIR:-/mnt/c/Users/jgott/OneDrive/Desktop/llm-secrets-community}"
GCP_INSTANCE="${SCRT4_GCP_INSTANCE:-prod-repo-app-instance-v001}"
GCP_ZONE="${SCRT4_GCP_ZONE:-us-east4-c}"
GCP_CONFIG_DEFAULT="/mnt/c/Users/jgott/AppData/Roaming/gcloud"
VERCEL_BIN="${SCRT4_VERCEL_BIN:-/home/jgott/.npm-global/bin/vercel}"

# ── Pretty output ───────────────────────────────────────────────────────

c_blue()  { printf '\033[0;36m%s\033[0m\n' "$*"; }
c_green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
c_yellow(){ printf '\033[0;33m%s\033[0m\n' "$*"; }
c_red()   { printf '\033[0;31m%s\033[0m\n' "$*" >&2; }
step()    { printf '\n\033[1;36m━━ %s ━━\033[0m\n' "$*"; }
die()     { c_red "error: $*"; exit 1; }

# Every step that mutates shared state gets gated on DRY_RUN.
if_real()    { [[ "$DRY_RUN" -eq 0 ]] && "$@" || c_yellow "(dry-run) would run: $*"; }

# ── 1. Pre-flight ───────────────────────────────────────────────────────

step "Pre-flight"

BRANCH=$(git rev-parse --abbrev-ref HEAD)
[[ "$BRANCH" == "public/llmsecrets-sanitized" ]] || \
    die "must be on branch public/llmsecrets-sanitized (currently $BRANCH)"

# Clean tree (allow .claude/ as untracked noise).
DIRTY=$(git status --porcelain | grep -v '^?? \.claude/' || true)
[[ -z "$DIRTY" ]] || die "working tree has uncommitted changes:
$DIRTY"

# scrt4 session must be active — we inject secrets via scrt4 run below.
scrt4 status >/dev/null 2>&1 || die "scrt4 session locked — run: scrt4 unlock"

# Tag must not exist.
git rev-parse "$TAG" >/dev/null 2>&1 && die "tag $TAG already exists locally"
if git ls-remote --tags origin "refs/tags/$TAG" | grep -q "$TAG"; then
    die "tag $TAG already exists on origin"
fi

# Required binaries.
for tool in gh gcloud rsync curl python3 sha256sum; do
    command -v "$tool" >/dev/null || die "missing dependency: $tool"
done

# gh + gcloud auth sanity.
gh auth status >/dev/null 2>&1 || die "gh not authenticated — run: gh auth login"

export CLOUDSDK_CONFIG="${CLOUDSDK_CONFIG:-$GCP_CONFIG_DEFAULT}"
gcloud auth list --format='value(account)' 2>/dev/null | grep -q '.' || \
    die "gcloud not authenticated — set CLOUDSDK_CONFIG or run: gcloud auth login"

c_green "✓ pre-flight OK — will release $TAG"

# ── 2. Bump VERSION and rebuild binary ──────────────────────────────────

step "Bump VERSION and rebuild binary"

CURRENT_VERSION=$(grep '^VERSION=' daemon/bin/scrt4-core | cut -d'"' -f2)

if [[ "$CURRENT_VERSION" != "$VERSION" ]]; then
    c_blue "VERSION: $CURRENT_VERSION → $VERSION"
    if_real sed -i 's/^VERSION=".*"/VERSION="'"$VERSION"'"/' daemon/bin/scrt4-core
else
    c_blue "VERSION already $VERSION, no bump needed"
fi

# Rebuild daemon/bin/scrt4 so the tracked artifact tracks scrt4-core at $TAG.
if_real bash scripts/build-scrt4.sh native-default daemon/bin/scrt4 >/dev/null
c_green "✓ daemon/bin/scrt4 rebuilt"

# ── 3. Compute install/scrt4-native.sh.sha256 ───────────────────────────

step "Compute install/scrt4-native.sh.sha256"

SHA_SCRIPT=$(sha256sum install/scrt4-native.sh | awk '{print $1}')
if_real sh -c "printf '%s  scrt4-native.sh\n' '$SHA_SCRIPT' > install/scrt4-native.sh.sha256"
c_blue "scrt4-native.sh sha256 = $SHA_SCRIPT"

# ── 4. Commit, tag, push ────────────────────────────────────────────────

step "Commit, tag, push"

if_real git add daemon/bin/scrt4-core daemon/bin/scrt4 install/scrt4-native.sh.sha256 2>/dev/null || true

# Only commit if something is staged.
if [[ "$DRY_RUN" -eq 0 ]] && ! git diff --cached --quiet; then
    git commit -m "release: $TAG"
elif [[ "$DRY_RUN" -eq 0 ]]; then
    c_blue "no staged changes — commit skipped"
fi

# Build auto release notes from commits since the last tag.
PREV_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [[ -n "$PREV_TAG" ]]; then
    NOTES=$(git log --format='- %s' "$PREV_TAG..HEAD" | head -30)
else
    NOTES=$(git log --format='- %s' -n 20)
fi

if_real git tag -a "$TAG" -m "$TAG" -m "$NOTES"
if_real git push origin "$BRANCH"
if_real git push origin "$TAG"
c_green "✓ tag $TAG pushed (CI will fire)"

# ── 5. Wait for CI release build ────────────────────────────────────────

step "Wait for CI release build"

if [[ "$DRY_RUN" -eq 1 ]]; then
    c_yellow "(dry-run) would poll gh run list + gh run watch for release.yml"
else
    # Give GH a few seconds to register the workflow run.
    for _ in {1..30}; do
        sleep 2
        RUN_ID=$(gh run list --workflow=release.yml --limit 3 \
            --json databaseId,headBranch,event,status \
            -q ".[] | select(.event == \"push\" and .status != \"completed\") | .databaseId" \
            | head -1)
        [[ -n "${RUN_ID:-}" ]] && break
    done
    [[ -n "${RUN_ID:-}" ]] || die "could not find in-progress release.yml run"
    c_blue "watching run: $RUN_ID"
    gh run watch "$RUN_ID" --exit-status || die "CI release build failed"
    c_green "✓ CI build completed"
fi

# ── 6. Download release artifacts ───────────────────────────────────────

step "Download release artifacts"

STAGE="/tmp/scrt4-release-$$-${TAG}"
mkdir -p "$STAGE"

if [[ "$DRY_RUN" -eq 1 ]]; then
    c_yellow "(dry-run) would download GH release into $STAGE"
else
    gh release download "$TAG" --repo VestedJosh/scrt4 --dir "$STAGE" --clobber
    # Stage the install script + its hash alongside the CI artifacts.
    cp install/scrt4-native.sh "$STAGE/scrt4-native.sh"
    cp install/scrt4-native.sh.sha256 "$STAGE/scrt4-native.sh.sha256"
    c_blue "staged:"
    ls -la "$STAGE"
fi

# ── 7. Attach install script + hash to GH Release ───────────────────────

step "Attach install script + hash to GH Release"

if_real gh release upload "$TAG" \
    "$STAGE/scrt4-native.sh" \
    "$STAGE/scrt4-native.sh.sha256" \
    --repo VestedJosh/scrt4 --clobber
c_green "✓ scrt4-native.sh + .sha256 uploaded to GH release"

# ── 8. Upload to install.llmsecrets.com + flip latest.txt ───────────────

step "Upload to install.llmsecrets.com"

if [[ "$DRY_RUN" -eq 1 ]]; then
    c_yellow "(dry-run) would gcloud scp artifacts to $GCP_INSTANCE"
else
    REMOTE_STAGE="/tmp/scrt4-release-$TAG-$$"
    gcloud compute scp \
        "$STAGE/scrt4" \
        "$STAGE/scrt4-daemon-linux-x86_64" \
        "$STAGE/scrt4-daemon-linux-aarch64" \
        "$STAGE/scrt4-daemon-darwin-aarch64" \
        "$STAGE/SHA256SUMS" \
        "$GCP_INSTANCE:$REMOTE_STAGE/" --zone="$GCP_ZONE" >/dev/null

    # Single ssh with a here-doc-ish payload. TAG is substituted locally.
    gcloud compute ssh "$GCP_INSTANCE" --zone="$GCP_ZONE" --command="
set -euo pipefail
TAG='$TAG'
REL_ROOT=/var/www/install/releases
REL_DIR=\"\$REL_ROOT/\$TAG\"
sudo mkdir -p \"\$REL_DIR\"
sudo mv '$REMOTE_STAGE'/scrt4 '$REMOTE_STAGE'/scrt4-daemon-linux-x86_64 '$REMOTE_STAGE'/scrt4-daemon-linux-aarch64 '$REMOTE_STAGE'/scrt4-daemon-darwin-aarch64 '$REMOTE_STAGE'/SHA256SUMS \"\$REL_DIR/\"
sudo chown -R root:root \"\$REL_DIR\"
sudo chmod 644 \"\$REL_DIR\"/*
echo '$TAG' | sudo tee \"\$REL_ROOT/latest.txt.new\" > /dev/null
sudo mv \"\$REL_ROOT/latest.txt.new\" \"\$REL_ROOT/latest.txt\"
rmdir '$REMOTE_STAGE' 2>/dev/null || true
" >/dev/null
    c_green "✓ install host serving $TAG"
fi

# ── 9. Verify end-to-end ────────────────────────────────────────────────

step "Verify end-to-end"

if [[ "$DRY_RUN" -eq 1 ]]; then
    c_yellow "(dry-run) would curl latest.txt, SHA256SUMS, /native.sha256"
else
    SERVED=$(curl -fsSL https://install.llmsecrets.com/releases/latest.txt | tr -d '[:space:]')
    [[ "$SERVED" == "$TAG" ]] || die "served tag mismatch: got '$SERVED', expected '$TAG'"
    curl -fsSL "https://install.llmsecrets.com/releases/$TAG/SHA256SUMS" >/dev/null || \
        die "SHA256SUMS not served at $TAG"
    c_green "✓ latest.txt = $TAG, SHA256SUMS reachable"

    # The install script hash is served by the systemd sync timer on the VM
    # (every 60s) — wait up to 2m for it to pick up the committed .sha256.
    for i in {1..24}; do
        LIVE_HASH=$(curl -fsSL "https://install.llmsecrets.com/native.sha256" 2>/dev/null | awk '{print $1}')
        [[ "$LIVE_HASH" == "$SHA_SCRIPT" ]] && break
        sleep 5
    done
    if [[ "${LIVE_HASH:-}" == "$SHA_SCRIPT" ]]; then
        c_green "✓ /native.sha256 matches committed hash ($SHA_SCRIPT)"
    else
        c_yellow "warning: /native.sha256 still shows '${LIVE_HASH:-<empty>}' (expected $SHA_SCRIPT)."
        c_yellow "  The install-sync timer on $GCP_INSTANCE may need a manual nudge:"
        c_yellow "    sudo systemctl start scrt4-install-sync.service"
    fi
fi

# ── 10. Update /downloads and redeploy Vercel ──────────────────────────

if [[ "$DO_SITE" -eq 1 ]]; then
    step "Update /downloads"

    if [[ ! -d "$SITE_DIR" ]]; then
        c_yellow "warning: $SITE_DIR missing; skipping /downloads update"
    elif [[ "$DRY_RUN" -eq 1 ]]; then
        c_yellow "(dry-run) would edit $SITE_DIR/downloads/index.html and redeploy Vercel"
    else
        NEW_SCRT4_HASH=$(awk '$2=="scrt4"||$2=="*scrt4" {print $1; exit}' "$STAGE/SHA256SUMS")
        python3 - "$SITE_DIR/downloads/index.html" "$TAG" "$NEW_SCRT4_HASH" "$SHA_SCRIPT" <<'PY'
import re, sys
path, new_tag, new_scrt4_hash, new_script_hash = sys.argv[1:5]
with open(path) as f: s = f.read()
# Replace any vX.Y.Z-community with new tag.
s = re.sub(r'v\d+\.\d+\.\d+-community', new_tag, s)
# Replace the first 64-hex followed by "  scrt4<" with new scrt4 hash.
s = re.sub(r'[0-9a-f]{64}(  scrt4<)', new_scrt4_hash + r'\1', s, count=1)
# Replace any scrt4-native.sh hash marker lines (if the page exposes one).
s = re.sub(
    r'(id="script-sha256"[^>]*>)[0-9a-f]{0,64}(<)',
    r'\g<1>' + new_script_hash + r'\g<2>',
    s,
)
with open(path, 'w') as f: f.write(s)
PY
        cd "$SITE_DIR"
        if git diff --quiet; then
            c_blue "no changes to /downloads index.html"
        else
            git add downloads/index.html
            git commit -m "downloads: $TAG release"
            scrt4 run "$VERCEL_BIN deploy --prod --cwd '$SITE_DIR' --token \$env[VERCEL_TOKEN] --yes" \
                > /tmp/scrt4-vercel.out 2> /tmp/scrt4-vercel.err || true
            DEPLOY_URL=$(grep -oE 'https://[A-Za-z0-9.-]+\.vercel\.app' /tmp/scrt4-vercel.out | tail -1 || true)
            c_green "✓ /downloads redeployed${DEPLOY_URL:+ — $DEPLOY_URL}"
        fi
        cd "$ROOT"
    fi
fi

# ── 11. Sync scrt4-community mirror (llmsecrets/llm-secrets) ───────────

if [[ "$DO_MIRROR" -eq 1 ]]; then
    step "Sync scrt4-community mirror"

    if [[ ! -d "$MIRROR_DIR" ]]; then
        c_yellow "warning: $MIRROR_DIR missing; skipping mirror sync"
    elif [[ "$DRY_RUN" -eq 1 ]]; then
        c_yellow "(dry-run) would rsync + commit + push scrt4-community"
    else
        rsync -a --delete \
            --exclude='.git/' --exclude='.claude/' \
            --exclude='target/' --exclude='node_modules/' \
            --exclude='*.log' \
            "$ROOT/" "$MIRROR_DIR/scrt4/"
        cd "$MIRROR_DIR"
        if [[ -n "$(git status --porcelain)" ]]; then
            git add scrt4/
            git commit -m "sync(scrt4): $TAG"
            git push origin scrt4-community
            c_green "✓ scrt4-community mirror synced"
        else
            c_blue "mirror already up-to-date"
        fi
        cd "$ROOT"
    fi
fi

# ── 12. Done ────────────────────────────────────────────────────────────

step "Done"
c_green "✓ $TAG shipped end-to-end"
printf '\nSelf-check:\n'
echo "  curl -fsSL https://install.llmsecrets.com/releases/latest.txt"
echo "  curl -fsSL https://install.llmsecrets.com/native.sha256"
echo "  gh release view $TAG --repo VestedJosh/scrt4"
echo "  https://llmsecrets.com/downloads"
