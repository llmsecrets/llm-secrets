#!/usr/bin/env bash
# recover-master-key.sh — recover a scrt4 master key from a backup file,
# without scrt4, without a daemon, without your authenticator.
#
# Usage: ./recover-master-key.sh [encrypted-master-key-instructions.json]
#
# Format (see README.md): PBKDF2-HMAC-SHA256 over the recovery password with
# the stored Salt and Iterations -> 32-byte key; AES-256-CBC + PKCS#7 with the
# stored IV. The salt lives in the JSON, NOT in an OpenSSL "Salted__" header,
# so the decrypt must pass -nosalt with explicit -K and -iv.
set -euo pipefail

BACKUP="${1:-encrypted-master-key-instructions.json}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ -f "$BACKUP" ] || die "backup file not found: $BACKUP

Usage: $0 [encrypted-master-key-instructions.json]
Create one with:  scrt4 unlock && scrt4 backup-key --save ~/Desktop"

command -v openssl >/dev/null || die "openssl not found — install it and retry"

# A recovery script must not depend on tools that may not be installed on the
# machine you are recovering onto. The backup format is flat JSON with string
# values, so sed handles it — jq and python are only used when present.
#
# `python3` deliberately is NOT probed with `command -v` alone: on Windows it
# resolves to the Microsoft Store alias stub, which exits non-zero with an
# install advert instead of running anything. Probe by execution.
PY=""
for c in python3 python py; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import json' >/dev/null 2>&1; then
        PY="$c"; break
    fi
done

# Strip a UTF-8 BOM; PowerShell's Out-File -Encoding utf8 writes one.
strip_bom() { sed '1s/^\xEF\xBB\xBF//'; }

read_field() {
    local key="$1"
    if command -v jq >/dev/null 2>&1; then
        strip_bom < "$BACKUP" | jq -r --arg k "$key" '.[$k] // empty'
    elif [ -n "$PY" ]; then
        "$PY" -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8-sig")).get(sys.argv[2],""))' \
            "$BACKUP" "$key"
    else
        # "Key": "value"  -> value.  Flat, quoted, one per line.
        strip_bom < "$BACKUP" \
            | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" \
            | head -1
    fi
}

read_iterations() {
    local n=""
    if command -v jq >/dev/null 2>&1; then
        n="$(strip_bom < "$BACKUP" | jq -r '.DecryptionInstructions.Iterations // empty')"
    elif [ -n "$PY" ]; then
        n="$("$PY" -c 'import json,sys; d=json.load(open(sys.argv[1],encoding="utf-8-sig")); print((d.get("DecryptionInstructions") or {}).get("Iterations",""))' "$BACKUP")"
    else
        n="$(strip_bom < "$BACKUP" \
            | sed -n 's/.*"Iterations"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)"
    fi
    case "$n" in ''|*[!0-9]*) echo 100000 ;; *) echo "$n" ;; esac
}

SALT_B64="$(read_field Salt)"
IV_B64="$(read_field IV)"
CT_B64="$(read_field EncryptedMasterKey)"
CREATED="$(read_field CreatedAt)"
VERSION="$(read_field Version)"
ITERS="$(read_iterations)"

[ -n "$SALT_B64" ] && [ -n "$IV_B64" ] && [ -n "$CT_B64" ] \
    || die "backup file is missing Salt, IV or EncryptedMasterKey — is this a scrt4 backup?
v1/v3 LLM Secrets backups use a different format; see README.md."

echo "=== scrt4 master key recovery ==="
echo "  Backup created: ${CREATED:-unknown}"
echo "  Format version: ${VERSION:-1.0}"
echo "  PBKDF2 iterations: $ITERS"
echo

# Read the password without echoing it, from the terminal rather than stdin so
# the script still works when piped.
if [ -n "${SCRT4_TEST_PASSWORD:-}" ]; then
    PASSWORD="$SCRT4_TEST_PASSWORD"
    echo "(using SCRT4_TEST_PASSWORD from environment)"
else
    printf 'Recovery password: '
    stty -echo 2>/dev/null || true
    IFS= read -r PASSWORD < /dev/tty
    stty echo 2>/dev/null || true
    printf '\n'
fi
[ -n "$PASSWORD" ] || die "no password entered"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# base64 -d is GNU; -D is BSD/macOS. Try both.
b64d() { base64 -d 2>/dev/null || base64 -D; }

printf '%s' "$SALT_B64" | b64d > "$WORK/salt.bin"
printf '%s' "$IV_B64"   | b64d > "$WORK/iv.bin"
printf '%s' "$CT_B64"   | b64d > "$WORK/ct.bin"

SALT_HEX="$(od -An -tx1 -v < "$WORK/salt.bin" | tr -d ' \n')"
IV_HEX="$(od -An -tx1 -v < "$WORK/iv.bin" | tr -d ' \n')"

# Derive the 32-byte key. openssl kdf is 3.0+; fall back to python3 for 1.1.1.
if openssl kdf -help >/dev/null 2>&1; then
    KEY_HEX="$(openssl kdf -keylen 32 -kdfopt digest:SHA256 \
        -kdfopt "pass:$PASSWORD" -kdfopt "hexsalt:$SALT_HEX" \
        -kdfopt "iter:$ITERS" -binary PBKDF2 | od -An -tx1 -v | tr -d ' \n')"
elif [ -n "$PY" ]; then
    KEY_HEX="$(SCRT4_PW="$PASSWORD" "$PY" -c '
import hashlib, os, sys
pw = os.environ["SCRT4_PW"].encode()
salt = bytes.fromhex(sys.argv[1])
print(hashlib.pbkdf2_hmac("sha256", pw, salt, int(sys.argv[2]), 32).hex())
' "$SALT_HEX" "$ITERS")"
else
    die 'need openssl 3.0+ (for "openssl kdf") or python to derive the key'
fi

if ! openssl enc -d -aes-256-cbc -nosalt \
        -K "$KEY_HEX" -iv "$IV_HEX" \
        -in "$WORK/ct.bin" -out "$WORK/key.txt" 2>/dev/null; then
    die "decryption failed — check the recovery password.

The password is the one you typed when running \`scrt4 backup-key --save\`,
not your vault PIN and not your authenticator PIN."
fi

MASTER_KEY="$(cat "$WORK/key.txt")"
[ -n "$MASTER_KEY" ] || die "decryption produced an empty key — the backup may be corrupt"

echo
echo "=== RECOVERED MASTER KEY ==="
echo "$MASTER_KEY"
echo
echo "Next: on the target machine run"
echo "    scrt4 setup          # enroll a new authenticator"
echo "    scrt4 restore-key    # paste the key above"
echo
echo "This key is the entire vault. Clear your scrollback when you are done."
