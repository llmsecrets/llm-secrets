#!/usr/bin/env bash
# build-scrt4.sh — assemble a v0.2 scrt4 binary from core + manifest modules.
#
# Usage:
#   scripts/build-scrt4.sh DISTRIBUTION OUTPUT_PATH
#
# Examples:
#   scripts/build-scrt4.sh hardened   /tmp/scrt4-hardened-v2
#   scripts/build-scrt4.sh core-only  /tmp/scrt4-core-only
#
# Env:
#   SCRT4_VERSION=v0.2.1-community    Overwrite the `VERSION="..."` line in
#                                     scrt4-core so the assembled binary
#                                     reports the release tag instead of the
#                                     in-repo `-dev` placeholder. CI passes
#                                     this from the triggering git tag.
#
# Reads modules.manifest at the repo root, finds the [DISTRIBUTION] section,
# loads each module file from daemon/bin/scrt4-modules/<name>.sh, validates
# the module headers, computes a topological sort by `requires:`, and
# concatenates daemon/bin/scrt4-core + the sorted module bodies into a
# single self-contained bash script at OUTPUT_PATH.
#
# This script does NOT touch daemon/bin/scrt4 — the v0.1.0 monolith is
# preserved on every branch including this one.

set -euo pipefail

# ── Paths ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_FILE="$REPO_ROOT/daemon/bin/scrt4-core"
MODULES_DIR="$REPO_ROOT/daemon/bin/scrt4-modules"
MANIFEST_FILE="$REPO_ROOT/modules.manifest"
HOOK_MARKER='## SCRT4_MODULE_SOURCE_HOOK ##'

# ── Args ─────────────────────────────────────────────────────────────

if [ $# -lt 2 ]; then
    cat <<EOF
Usage: $0 DISTRIBUTION OUTPUT_PATH

DISTRIBUTION is one of the [section] entries in modules.manifest:
$(awk '/^\[/ { gsub(/[\[\]]/, ""); printf "  - %s\n", $0 }' "$MANIFEST_FILE" 2>/dev/null || echo "  (manifest unreadable)")

OUTPUT_PATH is where to write the assembled scrt4 binary.

Example:
  $0 hardened   /tmp/scrt4-hardened-v2
  $0 core-only  /tmp/scrt4-core-only
EOF
    exit 1
fi

DIST="$1"
OUTPUT="$2"

# ── Sanity checks ────────────────────────────────────────────────────

if [ ! -f "$CORE_FILE" ]; then
    echo "build-scrt4: core file not found: $CORE_FILE" >&2
    exit 2
fi
if [ ! -f "$MANIFEST_FILE" ]; then
    echo "build-scrt4: manifest not found: $MANIFEST_FILE" >&2
    exit 2
fi
if ! grep -qF "$HOOK_MARKER" "$CORE_FILE"; then
    echo "build-scrt4: hook marker '$HOOK_MARKER' not found in $CORE_FILE" >&2
    echo "build-scrt4: cannot determine where to inject module source" >&2
    exit 2
fi

# ── Read manifest section ────────────────────────────────────────────

# Extract module names listed under [DIST] in the manifest. Lines starting
# with # are comments; blank lines are ignored.
read_section() {
    local section="$1"
    awk -v section="$section" '
        BEGIN { in_section = 0 }
        /^\[/ {
            gsub(/[\[\]]/, "")
            in_section = ($0 == section)
            next
        }
        in_section && !/^[[:space:]]*$/ && !/^[[:space:]]*#/ {
            sub(/[[:space:]]*#.*$/, "")
            sub(/^[[:space:]]+/, "")
            sub(/[[:space:]]+$/, "")
            if (length($0) > 0) print
        }
    ' "$MANIFEST_FILE"
}

mapfile -t MODULES < <(read_section "$DIST")

# Validate the section was found at all (vs found-but-empty, which is
# legitimate for [core-only]).
if ! grep -q "^\[$DIST\]" "$MANIFEST_FILE"; then
    echo "build-scrt4: distribution '$DIST' not found in $MANIFEST_FILE" >&2
    exit 3
fi

echo "build-scrt4: distribution=$DIST modules=${#MODULES[@]}" >&2

# ── Validate each module file + parse headers ────────────────────────

# For each module, check the file exists, parse its header, and store
# metadata. We don't yet implement topological sort by `requires:` — for
# v0.2 scaffold the module order is simply the order they appear in the
# manifest. Real topological sort lands in a follow-up.

declare -a VALIDATED_MODULES=()

for mod in "${MODULES[@]}"; do
    mod_file="$MODULES_DIR/${mod}.sh"
    if [ ! -f "$mod_file" ]; then
        echo "build-scrt4: WARN — module file missing, skipping: $mod_file" >&2
        continue
    fi

    # Header sanity check: the first 20 lines should contain a
    # `scrt4-module: <name>` line whose name matches the file name.
    declared_name=$(awk 'NR<=20 && /^# scrt4-module:/ { print $3; exit }' "$mod_file" || true)
    if [ -z "$declared_name" ]; then
        echo "build-scrt4: ERROR — $mod_file is missing 'scrt4-module: NAME' header" >&2
        exit 4
    fi
    if [ "$declared_name" != "$mod" ]; then
        echo "build-scrt4: ERROR — $mod_file declares 'scrt4-module: $declared_name' but manifest entry is '$mod'" >&2
        exit 4
    fi

    # API version check: header must declare `api: 1` (the only API
    # version this build script currently understands).
    declared_api=$(awk 'NR<=20 && /^# api:/ { print $3; exit }' "$mod_file" || true)
    if [ -z "$declared_api" ]; then
        echo "build-scrt4: ERROR — $mod_file is missing 'api: N' header" >&2
        exit 4
    fi
    if [ "$declared_api" != "1" ]; then
        echo "build-scrt4: ERROR — $mod_file declares api: $declared_api, build script understands api: 1" >&2
        exit 4
    fi

    # TCB header: must be present. `true` or `false`. Modules with `tcb: true`
    # require a security-review label on the PR — we don't enforce that here,
    # but we print a loud warning so it cannot land silently.
    declared_tcb=$(awk 'NR<=20 && /^# tcb:/ { print $3; exit }' "$mod_file" || true)
    if [ -z "$declared_tcb" ]; then
        echo "build-scrt4: ERROR — $mod_file is missing 'tcb: true|false' header" >&2
        exit 4
    fi
    if [ "$declared_tcb" = "true" ]; then
        printf 'build-scrt4: WARN — module %s declares tcb: true. This module is in the trusted computing base — make sure it is in docs/TCB.md and has a security review.\n' "$mod" >&2
    elif [ "$declared_tcb" != "false" ]; then
        echo "build-scrt4: ERROR — $mod_file has invalid tcb value: $declared_tcb (expected true|false)" >&2
        exit 4
    fi

    VALIDATED_MODULES+=("$mod")
done

# ── Assemble output ──────────────────────────────────────────────────

OUTPUT_DIR="$(dirname "$OUTPUT")"
mkdir -p "$OUTPUT_DIR"

# Use awk to copy core up to the hook marker, inject all module bodies,
# then copy the rest of core. Keeps the shebang + main_dispatch invocation
# in the right places.
{
    awk -v hook="$HOOK_MARKER" -v inject_marker="__SCRT4_INJECT_HERE__" '
        BEGIN { injected = 0 }
        $0 == hook && !injected {
            print
            print inject_marker
            injected = 1
            next
        }
        { print }
    ' "$CORE_FILE" | while IFS= read -r line; do
        if [ "$line" = "__SCRT4_INJECT_HERE__" ]; then
            for mod in "${VALIDATED_MODULES[@]}"; do
                echo
                echo "# ── module: $mod ──────────────────────────────────────────"
                echo
                cat "$MODULES_DIR/${mod}.sh"
                echo
            done
        else
            echo "$line"
        fi
    done
} > "$OUTPUT"

chmod +x "$OUTPUT"

# ── Stamp VERSION from SCRT4_VERSION env (if set) ───────────────────
# Release tags land here as SCRT4_VERSION=v0.2.1-community (or similar).
# We strip the leading `v` so the runtime VERSION string matches the
# "0.2.1-community" convention scrt4-core already uses.
if [ -n "${SCRT4_VERSION:-}" ]; then
    stamped="${SCRT4_VERSION#v}"
    # Portable sed -i (BSD needs an empty backup suffix). Build runs on
    # ubuntu-latest where GNU sed is fine, but this keeps the script
    # usable from a local Mac for testing.
    if sed --version >/dev/null 2>&1; then
        sed -i "s/^VERSION=\"[^\"]*\"/VERSION=\"${stamped}\"/" "$OUTPUT"
    else
        sed -i '' "s/^VERSION=\"[^\"]*\"/VERSION=\"${stamped}\"/" "$OUTPUT"
    fi
    echo "build-scrt4: stamped VERSION=${stamped}" >&2
fi

# ── Final report ─────────────────────────────────────────────────────

echo "build-scrt4: wrote $(wc -l < "$OUTPUT") lines to $OUTPUT" >&2
if [ "${#VALIDATED_MODULES[@]}" -gt 0 ]; then
    echo "build-scrt4: included modules:" >&2
    for mod in "${VALIDATED_MODULES[@]}"; do
        echo "  - $mod" >&2
    done
else
    echo "build-scrt4: no modules included (core-only build)" >&2
fi

# Quick syntax check on the result so a broken module fails the build.
if ! bash -n "$OUTPUT"; then
    echo "build-scrt4: ERROR — assembled script has bash syntax errors" >&2
    exit 5
fi

echo "build-scrt4: bash -n passed; build OK" >&2
