#!/usr/bin/env bash
# test_wa_gate_before_backup_key.sh — TCB invariant for CLI callers of the
# daemon's backup_key RPC.
#
# The daemon's handle_backup_key requires a fresh WebAuthn verification
# (consume_wa_verification). That verification is set by _wa_gate →
# unlock_local_complete, not by the handler itself. CLI callers that
# send backup_key without first running _wa_gate always fail with
# "WebAuthn verification required for backup key access", even inside
# an active session. This has bitten encrypt-folder, decrypt-folder,
# and the menu wizard at least once.
#
# This test is a pure static check: for every shell file under
# daemon/bin/ that sends {"method":"backup_key"}, verify that _wa_gate
# (or an allowlisted helper that wraps it) appears within the 20
# preceding non-blank lines, scoped to the same function.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${SCRIPT_DIR}/../bin"
[ -d "$BIN_DIR" ] || { echo "FAIL: $BIN_DIR not found"; exit 1; }

# Window size: how many lines above a backup_key call we scan for _wa_gate.
# 20 is generous — real fixes put the gate 2-4 lines above.
WINDOW=20

# Allowlist of wrapper helpers that themselves call _wa_gate. If a caller
# invokes one of these instead of _wa_gate directly, that's fine. Add to
# this list when new helpers are introduced (e.g. a future _get_master_key).
ALLOWLISTED_WRAPPERS=(
    "_wa_gate"
)

PASS=0
FAIL=0
OFFENDERS=()

check_file() {
    local file="$1"
    local rel="${file#${BIN_DIR}/}"

    # All line numbers that contain a backup_key RPC send.
    local line_nos
    line_nos=$(grep -n '"method":"backup_key"' "$file" | cut -d: -f1 || true)
    [ -z "$line_nos" ] && return 0

    while IFS= read -r lineno; do
        [ -z "$lineno" ] && continue
        local start=$(( lineno - WINDOW ))
        [ "$start" -lt 1 ] && start=1

        # Extract the window above the call. Stop at function boundary so we
        # don't accidentally credit a _wa_gate that belongs to an earlier fn.
        local window
        window=$(sed -n "${start},${lineno}p" "$file")

        # Crude function-scope trim: keep only lines after the last `() {`
        # or `function NAME` in the window. Good enough for this codebase.
        local scoped
        scoped=$(echo "$window" | awk '
            /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*\(\)[[:space:]]*\{/ { buf=""; next }
            /^[[:space:]]*function[[:space:]]+[A-Za-z_]/ { buf=""; next }
            { buf = buf $0 "\n" }
            END { printf "%s", buf }
        ')

        local gated=0
        for wrapper in "${ALLOWLISTED_WRAPPERS[@]}"; do
            if echo "$scoped" | grep -qE "(^|[^A-Za-z0-9_])${wrapper}([^A-Za-z0-9_]|$)"; then
                gated=1
                break
            fi
        done

        if [ "$gated" = "1" ]; then
            PASS=$((PASS+1))
            echo "  PASS: ${rel}:${lineno} — _wa_gate present within ${WINDOW} lines"
        else
            FAIL=$((FAIL+1))
            OFFENDERS+=("${rel}:${lineno}")
            echo "  FAIL: ${rel}:${lineno} — backup_key call with NO _wa_gate in preceding ${WINDOW} lines"
        fi
    done <<< "$line_nos"
}

echo "=== _wa_gate-before-backup_key invariant ==="

# Shell files only. Skip Rust (server-side) and tests. We scope to the
# three known shell surfaces: the monolithic scrt4 binary, scrt4-core, and
# every module under scrt4-modules/. `file` magic-detection misreports
# modules with embedded heredocs (encrypt-folder.sh has python3 heredocs),
# so we use paths, not heuristics.
CANDIDATES=()
[ -f "$BIN_DIR/scrt4" ]      && CANDIDATES+=("$BIN_DIR/scrt4")
[ -f "$BIN_DIR/scrt4-core" ] && CANDIDATES+=("$BIN_DIR/scrt4-core")
if [ -d "$BIN_DIR/scrt4-modules" ]; then
    while IFS= read -r -d '' f; do
        CANDIDATES+=("$f")
    done < <(find "$BIN_DIR/scrt4-modules" -type f -name '*.sh' -print0)
fi

for file in "${CANDIDATES[@]}"; do
    check_file "$file"
done

echo
echo "=== Summary ==="
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"

if [ "$FAIL" -gt 0 ]; then
    echo
    echo "Offenders:"
    for o in "${OFFENDERS[@]}"; do
        echo "  - $o"
    done
    echo
    echo "Fix: add '_wa_gate || return 1' (or call an allowlisted wrapper)"
    echo "     immediately before the send_request '{\"method\":\"backup_key\"}' call."
    echo "     The daemon's handle_backup_key rejects requests without a fresh"
    echo "     WebAuthn verification, even inside an active session."
    exit 1
fi

echo "OK — all backup_key call sites are properly gated."
