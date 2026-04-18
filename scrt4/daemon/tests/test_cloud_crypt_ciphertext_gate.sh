#!/usr/bin/env bash
# test_cloud_crypt_ciphertext_gate.sh — verify the cloud-crypt module's
# TCB invariant: it refuses to upload any file that is not AES-GCM
# ciphertext (i.e. does not start with the SCRT4ENC\0 magic).
#
# This is a pure-function test on _scrt4_cc_assert_ciphertext. We source
# the module with enough shims that the function is defined, then call
# it against crafted inputs. No network, no daemon.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULE="${SCRIPT_DIR}/../bin/scrt4-modules/cloud-crypt.sh"
[ -f "$MODULE" ] || { echo "FAIL: cloud-crypt.sh not found at $MODULE"; exit 1; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Fixtures:
#   ciphertext.scrt4  — begins with SCRT4ENC\0, followed by junk body
#   plaintext.txt     — innocuous plaintext
#   bogus.scrt4       — correct extension but wrong magic
#   tiny.scrt4        — shorter than 9 bytes
printf 'SCRT4ENC\x00payload-does-not-matter-here' > "$TMPDIR/ciphertext.scrt4"
printf 'hello world this is plaintext\n'          > "$TMPDIR/plaintext.txt"
printf 'SCRT3ENC\x00fake'                          > "$TMPDIR/bogus.scrt4"
printf 'SCRT'                                      > "$TMPDIR/tiny.scrt4"

PASS=0
FAIL=0
check() {
    if [ "$2" = "0" ]; then
        PASS=$((PASS+1)); echo "  PASS: $1"
    else
        FAIL=$((FAIL+1)); echo "  FAIL: $1"
    fi
}

# Shim the functions/vars the module expects at source-time.
CC_SHIM=$(mktemp)
cat > "$CC_SHIM" <<'SHIM'
RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
_register_command() { :; }
ensure_unlocked() { return 0; }
SHIM
# shellcheck disable=SC1090
source "$CC_SHIM"
# shellcheck disable=SC1090
source "$MODULE"

echo "=== ciphertext-only gate ==="

# 1. Valid ciphertext — must pass.
if _scrt4_cc_assert_ciphertext "$TMPDIR/ciphertext.scrt4" 2>/dev/null; then
    check "accepts valid SCRT4ENC ciphertext" 0
else
    check "accepts valid SCRT4ENC ciphertext" 1
fi

# 2. Plaintext — must fail.
if _scrt4_cc_assert_ciphertext "$TMPDIR/plaintext.txt" 2>/dev/null; then
    check "rejects plaintext file" 1
else
    check "rejects plaintext file" 0
fi

# 3. Wrong magic, correct extension — must fail.
if _scrt4_cc_assert_ciphertext "$TMPDIR/bogus.scrt4" 2>/dev/null; then
    check "rejects wrong-magic file (defense-in-depth)" 1
else
    check "rejects wrong-magic file (defense-in-depth)" 0
fi

# 4. Too-short file — must fail.
if _scrt4_cc_assert_ciphertext "$TMPDIR/tiny.scrt4" 2>/dev/null; then
    check "rejects too-short file" 1
else
    check "rejects too-short file" 0
fi

# 5. Missing file — must fail.
if _scrt4_cc_assert_ciphertext "$TMPDIR/does-not-exist.scrt4" 2>/dev/null; then
    check "rejects missing file" 1
else
    check "rejects missing file" 0
fi

# 6. Error message for plaintext mentions the mitigation.
stderr_out=$(_scrt4_cc_assert_ciphertext "$TMPDIR/plaintext.txt" 2>&1 >/dev/null || true)
if echo "$stderr_out" | grep -q "encrypt-folder"; then
    check "stderr points caller at encrypt-folder" 0
else
    check "stderr points caller at encrypt-folder" 1
fi

echo
echo "=== upload_one rejects plaintext without touching network ==="

# _scrt4_cc_upload_one calls _scrt4_cc_assert_ciphertext first and
# should return a JSON error WITHOUT ever attempting curl. We don't
# shim curl — if assertion fails, curl is not reached.
rc=0
out=$(_scrt4_cc_upload_one "fake-token" "fake-folder" "$TMPDIR/plaintext.txt" 2>/dev/null) || rc=$?
if [ "$rc" != "0" ] && echo "$out" | jq -e '.ok == false' >/dev/null 2>&1; then
    check "upload_one refuses plaintext (rc!=0, ok:false)" 0
else
    check "upload_one refuses plaintext (rc!=0, ok:false)" 1
fi

# The error payload should name the invariant, not leak a random curl error.
if echo "$out" | jq -e '.error | test("ciphertext|SCRT4ENC"; "i")' >/dev/null 2>&1; then
    check "upload_one error references the invariant" 0
else
    check "upload_one error references the invariant" 1
fi

echo
echo "=== module header declares the invariant ==="

grep -q "TCB invariant (ciphertext-only)" "$MODULE"
check "module header declares the invariant" $?

grep -q "^# TCB: cloud-crypt ciphertext-only gate" "$MODULE"
check "assert function carries a # TCB: annotation" $?

echo
echo "=== docs/TCB.md cross-references the invariant ==="
TCB_DOC="${SCRIPT_DIR}/../../docs/TCB.md"
[ -f "$TCB_DOC" ]; check "TCB.md present" $?
grep -q "_scrt4_cc_assert_ciphertext" "$TCB_DOC"
check "TCB.md names the assert function" $?
grep -q "Cloud-crypt plaintext-free" "$TCB_DOC"
check "TCB.md lists the invariant" $?

echo
echo "=== Result ==="
echo "PASS: $PASS   FAIL: $FAIL"
[ "$FAIL" = "0" ]
