# shellcheck shell=bash
# scrt4-module: encrypt-folder
# version: 1
# api: 1
# tcb: false
# deps: python3-cryptography
# commands: encrypt-folder, decrypt-folder
# requires:
#
# Encrypt or decrypt an entire folder using the daemon's master key.
# The archive format is exactly the v0.1.0 monolith's SCRT4ENC format,
# byte-for-byte compatible:
#
#   bytes 0..9    "SCRT4ENC\0"  (9-byte magic)
#   byte  9       version=1
#   bytes 10..14  >I  header length (big-endian u32)
#   bytes 14..    JSON header (folder_name, file_count, nonce, salt, ...)
#   remaining     AES-256-GCM ciphertext of tar.gz of selected files
#
# tcb: false. The crypto is AES-256-GCM under the daemon's master key,
# so a bug here cannot leak the key — at worst it produces a corrupted
# archive that the decryptor refuses (AES-GCM authentication catches
# tampering). The Python crypto is preserved verbatim from the v0.1.0
# monolith.
#
# v0.2 SCOPE: encrypt-folder + decrypt-folder live in this module.
# list-encrypted and cleanup-encrypted were reclassified as Core on
# 2026-04-13 (see docs/ARCHITECTURE-V0.2.md) because they read/write
# daemon-side inventory state, and now live as cmd_list_encrypted /
# cmd_cleanup_encrypted in scrt4-core. This module just notifies
# the daemon when an archive is created so the inventory stays in
# sync — see the register_encrypted RPC call in _encrypt_post_register.

scrt4_module_encrypt_folder_register() {
    _register_command encrypt-folder    scrt4_module_encrypt_folder_encrypt
    _register_command decrypt-folder    scrt4_module_encrypt_folder_decrypt
    _register_command backup-folder     scrt4_module_encrypt_folder_encrypt   # alias
    _register_command recover-folder    scrt4_module_encrypt_folder_decrypt   # alias
}

# _encrypt_post_register PATH FOLDER_NAME FILE_COUNT ARCHIVE_SIZE
#
# Called from scrt4_module_encrypt_folder_encrypt after the daemon
# successfully writes the archive. Notifies the daemon to record the
# new archive in the encrypted-folder inventory so
# `scrt4 list-encrypted` / `scrt4 cleanup-encrypted` can track it.
# Failures here are logged but not fatal — the archive was already
# written and is usable even if the inventory update is skipped.
_encrypt_post_register() {
    local archive_path="$1"
    local folder_name="$2"
    local file_count="$3"
    local archive_size="$4"
    local req
    req=$(jq -nc \
        --arg p "$archive_path" \
        --arg fn "$folder_name" \
        --argjson fc "$file_count" \
        --argjson sz "$archive_size" \
        '{method:"register_encrypted",params:{path:$p,folder_name:$fn,file_count:$fc,archive_size:$sz}}')
    local resp
    resp=$(send_request "$req" 2>/dev/null || true)
    local ok
    ok=$(echo "$resp" | jq -r '.success // false' 2>/dev/null || echo false)
    if [ "$ok" != "true" ]; then
        echo -e "${YELLOW}Note: failed to register archive in inventory (non-fatal): $(echo "$resp" | jq -r '.error // "unknown"' 2>/dev/null)${NC}" >&2
    fi
}

# File type whitelists — preserved from v0.1.0 monolith.
_EF_INCLUDE_EXTS=".txt .md .pdf .doc .docx .csv .json .yaml .yml .xml .toml .ini .cfg .conf .log .py .js .ts .rs .go .java .c .cpp .h .sh .bash .ps1 .rb .php .sol .abi .pem .key .crt .cer .p12 .pfx .gpg .asc .env .sql .sqlite .db .tar .gz .zip .png .jpg .jpeg .svg .ico .webp"
_EF_EXCLUDE_DIRS="node_modules target .git __pycache__ .venv dist build"
_EF_EXCLUDE_EXTS=".exe .dll .so .dylib .bin .mp4 .mov .avi .mp3 .wav .iso .vmdk .qcow2 .scrt4"
_EF_DEFAULT_MAX_SIZE=$((500 * 1024 * 1024))   # 500MB

scrt4_module_encrypt_folder_encrypt() {
    local folder_path=""
    local max_size="$_EF_DEFAULT_MAX_SIZE"
    local include_all=false
    local output_dir=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --max-size)
                local size_str="${2:-}"
                if [ -z "$size_str" ]; then
                    echo -e "${RED}--max-size requires a value (e.g., 500M, 1G)${NC}" >&2
                    return 1
                fi
                max_size=$(python3 -c "
import sys, re
s = sys.argv[1].upper()
m = re.match(r'^(\d+(?:\.\d+)?)\s*([KMGT]?)B?$', s)
if not m:
    print('-1'); sys.exit(0)
val = float(m.group(1))
unit = m.group(2)
mult = {'': 1, 'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4}
print(int(val * mult.get(unit, 1)))
" "$size_str")
                if [ "$max_size" -le 0 ] 2>/dev/null; then
                    echo -e "${RED}Invalid size: ${size_str}${NC}" >&2
                    return 1
                fi
                shift 2
                ;;
            --include-all) include_all=true; shift ;;
            --output)
                output_dir="${2:-}"
                shift 2
                ;;
            -*)
                echo -e "${RED}Unknown option: $1${NC}" >&2
                return 1
                ;;
            *) folder_path="$1"; shift ;;
        esac
    done

    if [ -z "$folder_path" ]; then
        echo -e "${RED}Usage: scrt4 encrypt-folder <path> [--max-size SIZE] [--include-all] [--output DIR]${NC}" >&2
        return 1
    fi

    folder_path=$(realpath "$folder_path" 2>/dev/null || echo "$folder_path")
    if [ ! -d "$folder_path" ]; then
        echo -e "${RED}Not a directory: ${folder_path}${NC}" >&2
        return 1
    fi

    local folder_name
    folder_name=$(basename "$folder_path")
    if [ -z "$output_dir" ]; then
        output_dir=$(dirname "$folder_path")
    fi
    local output_file="${output_dir}/${folder_name}.scrt4"

    if [ -f "$output_file" ]; then
        echo -e "${YELLOW}Output file already exists: ${output_file}${NC}"
        echo -n "Overwrite? [y/N] "
        read -r confirm
        [[ "$confirm" =~ ^[Yy] ]] || { echo "Cancelled."; return 0; }
    fi

    ensure_unlocked || return 1
    _wa_gate || return 1

    local key_response
    key_response=$(send_request '{"method":"backup_key"}')
    local key_ok
    key_ok=$(echo "$key_response" | jq -r '.success // false')
    if [ "$key_ok" != "true" ]; then
        echo -e "${RED}Failed to get master key: $(echo "$key_response" | jq -r '.error')${NC}" >&2
        return 1
    fi
    local master_key
    master_key=$(echo "$key_response" | jq -r '.data.key')

    echo -e "${CYAN}Encrypting folder: ${folder_name}${NC}"

    local result
    result=$(python3 -c "
import os, sys, json, base64, struct, gzip, tarfile, io, time

folder_path = sys.argv[1]
master_key_b64 = sys.argv[2]
max_size = int(sys.argv[3])
include_all = sys.argv[4] == 'true'
output_file = sys.argv[5]
version_str = sys.argv[6]

master_key = base64.b64decode(master_key_b64)
if len(master_key) != 32:
    print(json.dumps({'error': f'Invalid master key length: {len(master_key)}'}))
    sys.exit(0)

INCLUDE_EXTS = set('${_EF_INCLUDE_EXTS}'.split())
EXCLUDE_DIRS = set('${_EF_EXCLUDE_DIRS}'.split())
EXCLUDE_EXTS = set('${_EF_EXCLUDE_EXTS}'.split())

def should_include(rel_path, is_dir=False):
    if is_dir:
        return os.path.basename(rel_path) not in EXCLUDE_DIRS
    if include_all:
        ext = os.path.splitext(rel_path)[1].lower()
        return ext not in EXCLUDE_EXTS
    ext = os.path.splitext(rel_path)[1].lower()
    if not ext:
        return True
    return ext in INCLUDE_EXTS

files = []
skipped = []
total_size = 0
for root, dirs, filenames in os.walk(folder_path):
    dirs[:] = [d for d in dirs if should_include(d, is_dir=True)]
    for fname in filenames:
        full_path = os.path.join(root, fname)
        rel_path = os.path.relpath(full_path, folder_path)
        if should_include(rel_path):
            try:
                fsize = os.path.getsize(full_path)
                total_size += fsize
                files.append((full_path, rel_path, fsize))
            except OSError:
                skipped.append(rel_path)
        else:
            skipped.append(rel_path)

if not files:
    print(json.dumps({'error': 'No files matched. Use --include-all to widen.'}))
    sys.exit(0)
if total_size > max_size:
    print(json.dumps({'error': f'Folder size {total_size} exceeds limit {max_size}'}))
    sys.exit(0)

for s in skipped[:5]:
    print(f'SKIP: {s}', file=sys.stderr)
if len(skipped) > 5:
    print(f'SKIP: ... and {len(skipped) - 5} more', file=sys.stderr)

tar_buffer = io.BytesIO()
with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
    for full_path, rel_path, _ in files:
        tar.add(full_path, arcname=os.path.join(os.path.basename(folder_path), rel_path))
tar_data = tar_buffer.getvalue()

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
nonce = os.urandom(12)
salt = os.urandom(16)
aesgcm = AESGCM(master_key)
ciphertext = aesgcm.encrypt(nonce, tar_data, None)

header = json.dumps({
    'folder_name': os.path.basename(folder_path),
    'file_count': len(files),
    'original_size': total_size,
    'created': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'scrt4_version': version_str,
    'nonce': base64.b64encode(nonce).decode(),
    'salt': base64.b64encode(salt).decode(),
}, separators=(',', ':')).encode('utf-8')

with open(output_file, 'wb') as f:
    f.write(b'SCRT4ENC\x00')
    f.write(b'\x01')
    f.write(struct.pack('>I', len(header)))
    f.write(header)
    f.write(ciphertext)

print(json.dumps({
    'success': True,
    'file_count': len(files),
    'skipped_count': len(skipped),
    'original_size': total_size,
    'archive_size': os.path.getsize(output_file),
    'output': output_file,
}))
" "$folder_path" "$master_key" "$max_size" "$include_all" "$output_file" "$VERSION" 2>&1)

    master_key=""

    local json_line=""
    while IFS= read -r line; do
        if [[ "$line" == SKIP:* ]]; then
            echo -e "  ${YELLOW}${line}${NC}"
        elif [[ "$line" == "{"* ]]; then
            json_line="$line"
        fi
    done <<< "$result"

    if [ -z "$json_line" ]; then
        echo -e "${RED}Encryption failed (no Python output).${NC}" >&2
        return 1
    fi
    local err
    err=$(echo "$json_line" | jq -r '.error // empty')
    if [ -n "$err" ]; then
        echo -e "${RED}${err}${NC}" >&2
        return 1
    fi

    local file_count original archive out
    file_count=$(echo "$json_line" | jq -r '.file_count')
    original=$(echo "$json_line" | jq -r '.original_size')
    archive=$(echo "$json_line" | jq -r '.archive_size')
    out=$(echo "$json_line" | jq -r '.output')

    echo -e "${GREEN}Encrypted ${file_count} files (${original} → ${archive} bytes)${NC}"
    echo -e "${GREEN}Output: ${out}${NC}"

    # Notify the daemon-side inventory so `scrt4 list-encrypted` picks
    # this up. Non-fatal on failure — the archive is already written.
    _encrypt_post_register "$out" "$(basename "$folder_path")" "$file_count" "$archive"
}

scrt4_module_encrypt_folder_decrypt() {
    local archive_path=""
    local output_dir=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --output)
                output_dir="${2:-}"
                shift 2
                ;;
            -*)
                echo -e "${RED}Unknown option: $1${NC}" >&2
                return 1
                ;;
            *) archive_path="$1"; shift ;;
        esac
    done

    if [ -z "$archive_path" ]; then
        echo -e "${RED}Usage: scrt4 decrypt-folder <archive.scrt4> [--output DIR]${NC}" >&2
        return 1
    fi
    archive_path=$(realpath "$archive_path" 2>/dev/null || echo "$archive_path")
    if [ ! -f "$archive_path" ]; then
        echo -e "${RED}File not found: ${archive_path}${NC}" >&2
        return 1
    fi
    if [ -z "$output_dir" ]; then
        output_dir=$(dirname "$archive_path")
    fi

    ensure_unlocked || return 1
    _wa_gate || return 1

    local key_response
    key_response=$(send_request '{"method":"backup_key"}')
    local key_ok
    key_ok=$(echo "$key_response" | jq -r '.success // false')
    if [ "$key_ok" != "true" ]; then
        echo -e "${RED}Failed to get master key: $(echo "$key_response" | jq -r '.error')${NC}" >&2
        return 1
    fi
    local master_key
    master_key=$(echo "$key_response" | jq -r '.data.key')

    echo -e "${CYAN}Decrypting archive...${NC}"

    local result
    result=$(python3 -c "
import os, sys, json, base64, struct, gzip, tarfile, io

archive_path = sys.argv[1]
master_key_b64 = sys.argv[2]
output_dir = sys.argv[3]

master_key = base64.b64decode(master_key_b64)
if len(master_key) != 32:
    print(json.dumps({'error': f'Invalid master key length: {len(master_key)}'}))
    sys.exit(0)

with open(archive_path, 'rb') as f:
    if f.read(9) != b'SCRT4ENC\x00':
        print(json.dumps({'error': 'Not a .scrt4 archive (bad magic)'}))
        sys.exit(0)
    if f.read(1) != b'\x01':
        print(json.dumps({'error': 'Unsupported archive version'}))
        sys.exit(0)
    header_len = struct.unpack('>I', f.read(4))[0]
    if header_len > 1024 * 1024:
        print(json.dumps({'error': 'Header too large'}))
        sys.exit(0)
    header_bytes = f.read(header_len)
    ciphertext = f.read()

header = json.loads(header_bytes.decode('utf-8'))
nonce = base64.b64decode(header['nonce'])

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
try:
    aesgcm = AESGCM(master_key)
    tar_data = aesgcm.decrypt(nonce, ciphertext, None)
except Exception:
    print(json.dumps({'error': 'Decryption failed (wrong key or tampered)'}))
    sys.exit(0)

tar_buffer = io.BytesIO(tar_data)
with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
    for member in tar.getmembers():
        if member.name.startswith('/') or '..' in member.name:
            print(json.dumps({'error': f'Unsafe path in archive: {member.name}'}))
            sys.exit(0)
    tar.extractall(path=output_dir)
    extracted = [m.name for m in tar.getmembers() if m.isfile()]

print(json.dumps({
    'success': True,
    'folder_name': header.get('folder_name', 'unknown'),
    'file_count': len(extracted),
    'output_path': os.path.join(output_dir, header.get('folder_name', '')),
}))
" "$archive_path" "$master_key" "$output_dir" 2>&1)

    master_key=""

    local json_line=""
    while IFS= read -r line; do
        if [[ "$line" == "{"* ]]; then
            json_line="$line"
        fi
    done <<< "$result"

    if [ -z "$json_line" ]; then
        echo -e "${RED}Decryption failed (no Python output).${NC}" >&2
        echo "$result" >&2
        return 1
    fi
    local err
    err=$(echo "$json_line" | jq -r '.error // empty')
    if [ -n "$err" ]; then
        echo -e "${RED}${err}${NC}" >&2
        return 1
    fi
    local file_count out
    file_count=$(echo "$json_line" | jq -r '.file_count')
    out=$(echo "$json_line" | jq -r '.output_path')
    echo -e "${GREEN}Decrypted ${file_count} files → ${out}${NC}"

    # Update the inventory's last_decrypted_at for this archive
    # (silent no-op if the archive was never registered). Non-fatal.
    local mark_req
    mark_req=$(jq -nc --arg p "$archive_path" '{method:"mark_decrypted",params:{path:$p}}')
    send_request "$mark_req" >/dev/null 2>&1 || true
}
