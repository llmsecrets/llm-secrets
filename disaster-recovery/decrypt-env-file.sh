#!/usr/bin/env bash
# decrypt-env-file.sh
# Decrypts .env.encrypted using your master key (without needing the app)
#
# Usage: ./decrypt-env-file.sh -k "your44charkey==" -f ".env.encrypted.v5"
#
# Requirements: python3, openssl

set -euo pipefail

MASTER_KEY=""
ENCRYPTED_FILE=""
OUTPUT_FILE=".env"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -k|--key)     MASTER_KEY="$2"; shift 2 ;;
        -f|--file)    ENCRYPTED_FILE="$2"; shift 2 ;;
        -o|--output)  OUTPUT_FILE="$2"; shift 2 ;;
        *)
            echo "Usage: $0 -k <master-key> -f <encrypted-file> [-o <output-file>]" >&2
            exit 1
            ;;
    esac
done

if [ -z "$MASTER_KEY" ]; then
    read -s -p "Enter your 44-character master key: " MASTER_KEY
    echo
fi

if [ -z "$ENCRYPTED_FILE" ]; then
    echo "ERROR: No encrypted file specified. Use -f <file>" >&2
    exit 1
fi

if [ ! -f "$ENCRYPTED_FILE" ]; then
    echo "ERROR: Encrypted file not found: $ENCRYPTED_FILE" >&2
    exit 1
fi

KEY_LEN=${#MASTER_KEY}
if [ "$KEY_LEN" -ne 44 ]; then
    echo "ERROR: Invalid master key. Expected 44 characters, got $KEY_LEN" >&2
    exit 1
fi

echo "=== LLM Secrets — Decrypt .env File ==="
echo ""
echo "  Encrypted file: $ENCRYPTED_FILE"
echo "  Output file: $OUTPUT_FILE"
echo ""
echo "Decrypting..."

printf '%s' "$MASTER_KEY" | python3 -c "
import json, sys, base64, subprocess

master_key_b64 = sys.stdin.read()
encrypted_file = sys.argv[1]
output_file = sys.argv[2]

# Read encrypted file (JSON format with 'Data' field)
with open(encrypted_file, encoding='utf-8-sig') as f:
    encrypted_data = json.load(f)

key_bytes = base64.b64decode(master_key_b64)
data = base64.b64decode(encrypted_data['Data'])

# IV is first 16 bytes, ciphertext is the rest
iv = data[:16]
ciphertext = data[16:]

result = subprocess.run(
    ['openssl', 'enc', '-aes-256-cbc', '-d',
     '-K', key_bytes.hex(), '-iv', iv.hex(), '-nosalt'],
    input=ciphertext, capture_output=True)

if result.returncode != 0:
    print('Decryption failed. The master key may be incorrect.', file=sys.stderr)
    sys.exit(1)

plaintext = result.stdout.decode('utf-8')
with open(output_file, 'w') as f:
    f.write(plaintext)

print(f'SUCCESS! Decrypted to: {output_file}')
print(f'Lines: {len(plaintext.splitlines())}')
" "$ENCRYPTED_FILE" "$OUTPUT_FILE"

echo ""
echo "WARNING: Delete $OUTPUT_FILE after use — it contains plaintext secrets!"
echo ""
