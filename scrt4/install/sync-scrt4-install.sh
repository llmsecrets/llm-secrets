#!/bin/bash
# sync-scrt4-install — pulls latest main and copies install artifacts to
# /var/www/install so install.llmsecrets.com serves the newest content.
#
# Managed by systemd timer scrt4-install-sync.timer (every 60s).
# Canonical source lives in the scrt4 repo: install/sync-scrt4-install.sh
set -euo pipefail

CHECKOUT_DIR="/var/lib/scrt4-install"
WEB_DIR="/var/www/install"

mkdir -p "$WEB_DIR"

git -C "$CHECKOUT_DIR" fetch --quiet origin public/llmsecrets-sanitized
git -C "$CHECKOUT_DIR" reset --quiet --hard origin/public/llmsecrets-sanitized

# Always sync the Docker wrappers (primary install paths).
install -m 644 -o www-data -g www-data \
    "$CHECKOUT_DIR/install/scrt4-docker.sh" \
    "$WEB_DIR/scrt4-docker.sh"

install -m 644 -o www-data -g www-data \
    "$CHECKOUT_DIR/install/scrt4-v2-docker.sh" \
    "$WEB_DIR/scrt4-v2-docker.sh"

# Native installer (no Docker, pulls signed release artifacts).
install -m 644 -o www-data -g www-data \
    "$CHECKOUT_DIR/install/scrt4-native.sh" \
    "$WEB_DIR/scrt4-native.sh"

# Checksum file for the native installer — enables two-hosts-one-hash
# verification: the same bytes and the same hash are also attached to every
# GitHub release, so `curl install.llmsecrets.com/native.sha256` and
# `curl github.com/.../releases/<tag>/scrt4-native.sh.sha256` must match.
# Served at /native.sha256 via a Caddy rewrite.
if [ -f "$CHECKOUT_DIR/install/scrt4-native.sh.sha256" ]; then
    install -m 644 -o www-data -g www-data \
        "$CHECKOUT_DIR/install/scrt4-native.sh.sha256" \
        "$WEB_DIR/scrt4-native.sh.sha256"
fi

# macOS zenity shim (osascript-backed). Served at /zenity-macos; the native
# installer drops it at $INSTALL_DIR/zenity on Darwin hosts.
install -m 644 -o www-data -g www-data \
    "$CHECKOUT_DIR/install/scrt4-zenity-macos.sh" \
    "$WEB_DIR/scrt4-zenity-macos.sh"

# Uninstaller — removes Docker wrappers, native binaries, systemd/launchd
# services, and (with --purge) the encrypted vault. Served at /uninstall.
install -m 644 -o www-data -g www-data \
    "$CHECKOUT_DIR/install/scrt4-uninstall.sh" \
    "$WEB_DIR/scrt4-uninstall.sh"

# ── Module whitelist + per-module distribution ────────────────────────
#
# The native installer's `--module NAME` flag reads modules.json to verify
# each requested module is approved, then downloads the matching .sh from
# /modules/<name>.sh and sha256-verifies it before splicing it into the
# core scrt4 binary. Source of truth is install/modules-whitelist.json in
# the repo; we fan that out here into a served manifest + individual files.

WHITELIST_SRC="$CHECKOUT_DIR/install/modules-whitelist.json"
MODULES_SRC="$CHECKOUT_DIR/daemon/bin/scrt4-modules"
MODULES_WEB="$WEB_DIR/modules"

mkdir -p "$MODULES_WEB"

if [ ! -f "$WHITELIST_SRC" ]; then
    echo "sync-scrt4-install: WARN — $WHITELIST_SRC missing, skipping modules sync" >&2
elif ! command -v jq >/dev/null 2>&1; then
    echo "sync-scrt4-install: ERROR — jq not installed, cannot build modules.json" >&2
    exit 1
else
    # Track entries as JSON objects we can merge into modules.json at the end.
    MANIFEST_ENTRIES="[]"

    # Extract the approved-module list. jq -r + one-per-line keeps this sh-friendly.
    APPROVED="$(jq -r '.approved[]' "$WHITELIST_SRC")"

    for name in $APPROVED; do
        src="$MODULES_SRC/${name}.sh"
        if [ ! -f "$src" ]; then
            echo "sync-scrt4-install: WARN — approved module missing file: $name ($src)" >&2
            continue
        fi

        install -m 644 -o www-data -g www-data "$src" "$MODULES_WEB/${name}.sh"
        sha="$(sha256sum "$src" | awk '{print $1}')"
        MANIFEST_ENTRIES="$(jq -c --arg n "$name" --arg s "$sha" \
            '. + [{name: $n, sha256: $s}]' <<<"$MANIFEST_ENTRIES")"
    done

    # Prune stale module files from the served tree (modules removed from
    # the whitelist should not linger on disk — serving them would defeat
    # the point of the allowlist).
    for f in "$MODULES_WEB"/*.sh; do
        [ -e "$f" ] || continue
        name="$(basename "$f" .sh)"
        if ! printf '%s\n' "$APPROVED" | grep -qx "$name"; then
            echo "sync-scrt4-install: removing stale module $name" >&2
            rm -f "$f"
        fi
    done

    # Write the served manifest. Shape is { version, generated_at, modules: { NAME: { sha256 } } }.
    MANIFEST_TMP="$(mktemp)"
    jq -n --argjson entries "$MANIFEST_ENTRIES" '{
        version: 1,
        generated_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
        modules: ($entries | map({key: .name, value: {sha256: .sha256}}) | from_entries)
    }' > "$MANIFEST_TMP"
    install -m 644 -o www-data -g www-data "$MANIFEST_TMP" "$WEB_DIR/modules.json"
    rm -f "$MANIFEST_TMP"
fi

# install.sh lives at the repo root on some branches but may not be on main.
# Copy it if present, leave any existing file in place otherwise.
if [ -f "$CHECKOUT_DIR/install.sh" ]; then
    install -m 644 -o www-data -g www-data \
        "$CHECKOUT_DIR/install.sh" \
        "$WEB_DIR/install.sh"
fi
