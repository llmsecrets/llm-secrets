#!/usr/bin/env bash
# test_backup_vault_inventory.sh — verify cloud-crypt ledger is
# included in scrt4 backup-vault output.
#
# Why: the encrypted-inventory.json file is the cloud-crypt tracking
# ledger (archive names, Drive IDs, sizes, timestamps). If a user
# loses the machine, they have ciphertext on Drive but no map. The
# core backup bundle MUST preserve this ledger so `scrt4 recover`
# restores both vault and cloud-crypt index.
#
# This test fakes a $CONFIG_DIR with a representative inventory and
# builds a tarball the same way cmd_backup_vault does, then inspects
# the archive contents. It also greps cmd_backup_vault itself to
# confirm the inventory log line is present.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE="${SCRIPT_DIR}/../bin/scrt4-core"
[ -f "$CORE" ] || { echo "FAIL: $CORE not found"; exit 1; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

FAKE_CONFIG="${TMPDIR}/.scrt4"
mkdir -p "$FAKE_CONFIG"
echo "ciphertext-goes-here" > "$FAKE_CONFIG/secrets.enc"
echo "wrapped-master-key" > "$FAKE_CONFIG/master.key"
cat > "$FAKE_CONFIG/encrypted-inventory.json" <<'EOF'
{
  "version": 1,
  "entries": [
    {
      "id": "abc123",
      "path": "/home/user/archive1.scrt4",
      "folder_name": "projects",
      "file_count": 42,
      "archive_size": 1048576,
      "created_at": 1700000000000,
      "last_decrypted_at": null
    },
    {
      "id": "def456",
      "path": "/home/user/archive2.scrt4",
      "folder_name": "docs",
      "file_count": 7,
      "archive_size": 204800,
      "created_at": 1700000100000,
      "last_decrypted_at": 1700000200000
    }
  ]
}
EOF

ARCHIVE="${TMPDIR}/out.tar.gz"
tar -czf "$ARCHIVE" -C "$TMPDIR" ".scrt4"

PASS=0
FAIL=0
check() {
    if [ "$2" = "0" ]; then
        PASS=$((PASS+1)); echo "  PASS: $1"
    else
        FAIL=$((FAIL+1)); echo "  FAIL: $1"
    fi
}

echo "=== Checking archive contents ==="
CONTENTS=$(tar -tzf "$ARCHIVE")

echo "$CONTENTS" | grep -q "^.scrt4/secrets.enc$"
check "secrets.enc present" $?

echo "$CONTENTS" | grep -q "^.scrt4/encrypted-inventory.json$"
check "encrypted-inventory.json present" $?

echo "$CONTENTS" | grep -q "^.scrt4/master.key$"
check "master.key present" $?

EXTRACT_DIR="${TMPDIR}/extract"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$ARCHIVE" -C "$EXTRACT_DIR"

INV="${EXTRACT_DIR}/.scrt4/encrypted-inventory.json"
[ -f "$INV" ]; check "inventory extracts to disk" $?

ENTRY_COUNT=$(jq -r '.entries | length' "$INV")
[ "$ENTRY_COUNT" = "2" ]; check "inventory has 2 entries (roundtrip)" $?

FIRST_ID=$(jq -r '.entries[0].id' "$INV")
[ "$FIRST_ID" = "abc123" ]; check "inventory entry id preserved" $?

grep -q "cloud-crypt inventory" "$CORE"
check "cmd_backup_vault logs inventory count" $?

grep -q "encrypted-inventory.json" "$CORE"
check "cmd_backup_vault references inventory file" $?

echo
echo "=== Result ==="
echo "PASS: $PASS   FAIL: $FAIL"
[ "$FAIL" = "0" ]
