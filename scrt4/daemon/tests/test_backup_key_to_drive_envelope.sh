#!/usr/bin/env bash
# test_backup_key_to_drive_envelope.sh — verify the SCRT4ENC envelope
# wrap/unwrap logic used by `scrt4 backup-key --to-drive` and
# `scrt4 recover --from-drive` round-trips a master.key file
# byte-for-byte.
#
# Isolates the pure file-format logic from the Drive I/O so this
# test can run offline. Extracts the embedded Python scripts from
# scrt4-core and runs them head-to-tail against a fixture.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE="${SCRIPT_DIR}/../bin/scrt4-core"
[ -f "$CORE" ] || { echo "FAIL: scrt4-core not found"; exit 1; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Fixture master.key — the real daemon writes v2 files in this shape.
cat > "$TMPDIR/master.key" <<'EOF'
{
  "version": 2,
  "salt": "d0lwBC6EDUuZAUGNCQcVb3XYe6w2xdWUZdT1Zxnv7bE=",
  "nonce": "G+c0IIWiNSnGXcKj",
  "ciphertext": "sSYixXVwT1b6w3JIwmsNUmpCZS0CfY2xNLj+3NS7rIjiYexbM0Qk0vAjA78cJdbj",
  "auth_method": "WebAuthnPrf",
  "webauthn_credential_id": "Y3JlZGVudGlhbF9pZF9leGFtcGxl"
}
EOF

# Extract the wrap script from scrt4-core. Can't use a simple awk
# range for the function body because embedded Python closing braces
# match ^}$. Instead: enter the function on its signature, enter the
# heredoc on `<< 'PYEOF'`, print lines, stop on the matching `PYEOF`.
WRAP_PY="$TMPDIR/wrap.py"
awk '
    /^cmd_backup_key_to_drive\(\) \{/ { in_func=1; next }
    in_func && /<< .PYEOF./          { in_py=1;  next }
    in_func && in_py && /^PYEOF$/    { exit }
    in_func && in_py                 { print }
' "$CORE" > "$WRAP_PY"

UNWRAP_PY="$TMPDIR/unwrap.py"
awk '
    /^cmd_recover_from_drive\(\) \{/ { in_func=1; next }
    in_func && /<< .PYEOF./          { in_py=1;  next }
    in_func && in_py && /^PYEOF$/    { exit }
    in_func && in_py                 { print }
' "$CORE" > "$UNWRAP_PY"

PASS=0
FAIL=0
check() {
    if [ "$2" = "0" ]; then
        PASS=$((PASS+1)); echo "  PASS: $1"
    else
        FAIL=$((FAIL+1)); echo "  FAIL: $1"
    fi
}

[ -s "$WRAP_PY" ];   check "wrap script extracted from scrt4-core" $?
[ -s "$UNWRAP_PY" ]; check "unwrap script extracted from scrt4-core" $?

echo
echo "=== wrap ==="
BUNDLE="$TMPDIR/bundle.scrt4"
WRAP_OUT=$(python3 "$WRAP_PY" "$TMPDIR/master.key" "$BUNDLE" 2>&1)
echo "$WRAP_OUT" | jq -e '.ok' >/dev/null 2>&1
check "wrap returns ok" $?

[ -f "$BUNDLE" ]; check "bundle file written" $?

# Magic check: SCRT4ENC\0 == 53 43 52 54 34 45 4e 43 00
MAGIC_HEX=$(head -c 9 "$BUNDLE" | od -An -tx1 | tr -d ' \n')
[ "$MAGIC_HEX" = "5343525434454e4300" ]
check "bundle starts with SCRT4ENC magic" $?

# Version byte
VER_HEX=$(dd if="$BUNDLE" bs=1 skip=9 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
[ "$VER_HEX" = "01" ]
check "bundle version byte = 0x01" $?

echo
echo "=== cloud-crypt gate accepts the bundle ==="
# Source the cloud-crypt module's assert function and run it on the bundle.
CC_SHIM=$(mktemp)
cat > "$CC_SHIM" <<'SHIM'
RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
_register_command() { :; }
ensure_unlocked() { return 0; }
SHIM
# shellcheck disable=SC1090
source "$CC_SHIM"
# shellcheck disable=SC1090
source "${SCRIPT_DIR}/../bin/scrt4-modules/cloud-crypt.sh"

if _scrt4_cc_assert_ciphertext "$BUNDLE" 2>/dev/null; then
    check "cloud-crypt TCB gate accepts the bundle" 0
else
    check "cloud-crypt TCB gate accepts the bundle" 1
fi

echo
echo "=== unwrap ==="
RECOVERED="$TMPDIR/recovered-master.key"
UNWRAP_OUT=$(python3 "$UNWRAP_PY" "$BUNDLE" "$RECOVERED" 2>&1)
echo "$UNWRAP_OUT" | jq -e '.ok' >/dev/null 2>&1
check "unwrap returns ok" $?

[ -f "$RECOVERED" ]; check "recovered master.key written" $?

# The recovered JSON must preserve the fields that unlock cares about.
ORIG_SALT=$(jq -r '.salt' "$TMPDIR/master.key")
REC_SALT=$(jq -r '.salt' "$RECOVERED")
[ "$ORIG_SALT" = "$REC_SALT" ]; check "salt preserved" $?

ORIG_NONCE=$(jq -r '.nonce' "$TMPDIR/master.key")
REC_NONCE=$(jq -r '.nonce' "$RECOVERED")
[ "$ORIG_NONCE" = "$REC_NONCE" ]; check "nonce preserved" $?

ORIG_CT=$(jq -r '.ciphertext' "$TMPDIR/master.key")
REC_CT=$(jq -r '.ciphertext' "$RECOVERED")
[ "$ORIG_CT" = "$REC_CT" ]; check "ciphertext preserved (byte-for-byte)" $?

ORIG_CID=$(jq -r '.webauthn_credential_id' "$TMPDIR/master.key")
REC_CID=$(jq -r '.webauthn_credential_id' "$RECOVERED")
[ "$ORIG_CID" = "$REC_CID" ]; check "credential_id preserved" $?

ORIG_AM=$(jq -r '.auth_method' "$TMPDIR/master.key")
REC_AM=$(jq -r '.auth_method' "$RECOVERED")
[ "$ORIG_AM" = "$REC_AM" ]; check "auth_method preserved" $?

echo
echo "=== negative cases ==="

# Non-SCRT4ENC file → unwrap must fail cleanly.
echo "not a bundle" > "$TMPDIR/garbage.txt"
BAD_OUT=$(python3 "$UNWRAP_PY" "$TMPDIR/garbage.txt" "$TMPDIR/bad.key" 2>&1)
echo "$BAD_OUT" | jq -e '.error' >/dev/null 2>&1
check "unwrap rejects non-SCRT4ENC file" $?

# Wrong-kind envelope → unwrap must fail cleanly.
# Hand-craft a SCRT4ENC bundle with kind="folder-archive" (the encrypt-folder
# default) and confirm unwrap refuses it.
python3 - "$TMPDIR/wrong-kind.scrt4" <<'PY'
import json, struct, sys
dst = sys.argv[1]
header = json.dumps({'kind': 'folder-archive', 'nonce': 'x', 'salt': 'y'}).encode()
with open(dst, 'wb') as f:
    f.write(b'SCRT4ENC\x00')
    f.write(b'\x01')
    f.write(struct.pack('>I', len(header)))
    f.write(header)
    f.write(b'fake-body')
PY
BAD_OUT2=$(python3 "$UNWRAP_PY" "$TMPDIR/wrong-kind.scrt4" "$TMPDIR/bad2.key" 2>&1)
echo "$BAD_OUT2" | jq -e '.error | test("master-key-export"; "i")' >/dev/null 2>&1
check "unwrap rejects wrong-kind envelope" $?

echo
echo "=== scrt4-core wiring ==="
grep -q "cmd_backup_key_to_drive" "$CORE"
check "cmd_backup_key_to_drive defined" $?
grep -q "cmd_recover_from_drive" "$CORE"
check "cmd_recover_from_drive defined" $?
grep -q -- "--to-drive" "$CORE"
check "cmd_backup_key routes --to-drive" $?
grep -q -- "--from-drive" "$CORE"
check "cmd_recover routes --from-drive" $?
grep -q "CLOUD KEY ESCROW" "$CORE"
check "backup-guide documents cloud escrow" $?

echo
echo "=== Result ==="
echo "PASS: $PASS   FAIL: $FAIL"
[ "$FAIL" = "0" ]
