#!/usr/bin/env bash
# recover-master-key.sh
# Recovers your master key from an encrypted backup file using your recovery password
#
# Usage: ./recover-master-key.sh [encrypted-master-key-instructions.json]
# Also works with v1.0 master-key.backup files from LLM Secrets (Windows)
#
# Requirements: python3, openssl, jq

set -euo pipefail

BACKUP_FILE="${1:-encrypted-master-key-instructions.json}"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "ERROR: Backup file not found: $BACKUP_FILE" >&2
    echo "Usage: $0 <backup-file.json>" >&2
    exit 1
fi

echo "=== LLM Secrets — Master Key Recovery ==="
echo ""

CREATED=$(jq -r '.CreatedAt // "unknown"' "$BACKUP_FILE")
VERSION=$(jq -r '.Version // "1.0"' "$BACKUP_FILE")
echo "  Backup created: $CREATED"
echo "  Format version: $VERSION"
echo ""

read -s -p "Enter recovery password: " PASSWORD
echo
echo ""
echo "Decrypting..."

MASTER_KEY=$(printf '%s' "$PASSWORD" | python3 -c "
import json, sys, hashlib, base64, subprocess

password = sys.stdin.read()
backup_file = sys.argv[1]

with open(backup_file, encoding='utf-8-sig') as f:
    backup = json.load(f)

salt = base64.b64decode(backup['Salt'])
iv = base64.b64decode(backup['IV'])
encrypted = base64.b64decode(backup['EncryptedMasterKey'])
iters = backup.get('DecryptionInstructions', {}).get('Iterations', 100000)

derived_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iters, dklen=32)

result = subprocess.run(
    ['openssl', 'enc', '-aes-256-cbc', '-d',
     '-K', derived_key.hex(), '-iv', iv.hex(), '-nosalt'],
    input=encrypted, capture_output=True)

if result.returncode != 0:
    sys.exit(1)

print(result.stdout.decode().rstrip(chr(0)))
" "$BACKUP_FILE" 2>/dev/null) || {
    echo ""
    echo "ERROR: Decryption failed. Check your recovery password." >&2
    exit 1
}

if [ -z "$MASTER_KEY" ]; then
    echo "ERROR: Decryption produced empty result." >&2
    exit 1
fi

echo ""
echo "SUCCESS! Your master key:"
echo ""
echo "  $MASTER_KEY"
echo ""
echo "  Key length: ${#MASTER_KEY} characters"
echo ""
echo "=== What to do next ==="
echo "  Option 1: scrt2 migrate \"$MASTER_KEY\""
echo "  Option 2: ./decrypt-env-file.sh -k \"$MASTER_KEY\" -f .env.encrypted.v5"
echo ""
