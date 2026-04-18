# shellcheck shell=bash
# scrt4-module: menu
# version: 1
# api: 1
# tcb: false
# deps: zenity
# commands: menu
# requires:
#
# Zenity GUI launcher for hardened (and optionally dev) distributions.
# Dynamically discovers registered commands via _resolve_command so the
# menu adapts to whichever modules are present in the current build.
# Falls back to cmd_help on headless/container environments.
#
# Ported from the v0.1.0 monolith cmd_menu (lines 3927-4217).

scrt4_module_menu_register() {
    _register_command menu scrt4_module_menu_cmd
}

# ── helpers ─────────────────────────────────────────────────────────

# _menu_has CMD — returns 0 if CMD is registered, 1 otherwise.
_menu_has() { _resolve_command "$1" >/dev/null 2>&1; }

# _menu_dispatch CMD [ARGS...] — resolve and call a registered command.
_menu_dispatch() {
    local cmd="$1"; shift
    local handler
    handler=$(_resolve_command "$cmd") || return 1
    "$handler" "$@"
}

# ── main entry ──────────────────────────────────────────────────────

scrt4_module_menu_cmd() {
    # No GUI → fall back to text help.
    if ! _has_gui; then
        if command -v zenity >/dev/null 2>&1; then
            echo -e "${YELLOW}No display available (DISPLAY/WAYLAND_DISPLAY unset).${NC}" >&2
        else
            echo -e "${YELLOW}zenity not installed.${NC}" >&2
        fi
        echo -e "${YELLOW}Falling back to text help.${NC}" >&2
        _menu_dispatch help
        return 0
    fi

    while true; do
        # ── live status line ──
        local status_line="Inactive"
        local status_color="#f59e0b"
        local response
        response=$(send_request '{"method":"status"}' 2>/dev/null)
        local active
        active=$(echo "$response" | jq -r '.data.active // false' 2>/dev/null)
        if [ "$active" = "true" ]; then
            local remaining
            remaining=$(echo "$response" | jq -r '.data.remaining // 0' 2>/dev/null)
            local hours=$((remaining / 3600))
            local mins=$(( (remaining % 3600) / 60 ))
            status_line="Active  \u00b7  ${hours}h ${mins}m remaining"
            status_color="#22c55e"
        fi

        local secret_count="?"
        local list_response
        list_response=$(send_request '{"method":"list"}' 2>/dev/null)
        local list_ok
        list_ok=$(echo "$list_response" | jq -r '.success // false' 2>/dev/null)
        if [ "$list_ok" = "true" ]; then
            secret_count=$(echo "$list_response" | jq -r '.data.names | length' 2>/dev/null)
        fi

        # ── build menu items dynamically ──
        # Each pair is: "command-key" "description"
        local -a items=()

        # Core commands (always present)
        items+=("unlock"     "Authenticate via browser (localhost)")
        items+=("status"     "Check session status")
        items+=("list"       "List secret names")
        items+=("view"       "View secret values (GUI)")
        items+=("add"        "Add secrets (GUI notepad)")

        _menu_has import && \
        items+=("import"     "Import from .env file (file picker)")

        items+=("share"      "Send secrets via Magic Wormhole")
        items+=("receive"    "Receive secrets via Magic Wormhole")

        _menu_has wallet && {
        items+=("wallet"         "Wallet dashboard (balances, tokens, activity)")
        items+=("wallet setup"   "Configure wallet dashboard")
        }

        items+=("run ..."    "Run command with secrets")

        _menu_has encrypt-folder && {
        items+=("encrypt-folder" "Encrypt a folder into .scrt4 archive")
        items+=("decrypt-folder" "Decrypt a .scrt4 archive")
        }

        items+=("backup-vault"        "Backup vault to Google Drive")
        items+=("backup-vault --local" "Backup vault locally")
        items+=("extend"              "Reset session timer")
        items+=("backup-key"          "Show master key (disaster recovery)")
        items+=("backup-key --save"   "Save encrypted master key backup")
        items+=("recover"             "Recover master key from backup file")
        items+=("backup-guide"        "Backup & recovery guide (notepad)")
        items+=("rotate"              "Rotate vault (re-encrypt with new master key)")
        items+=("setup"               "Register new WebAuthn credential")

        _menu_has wa-state && {
        items+=("wa-state"         "Check WebAuthn 2FA state")
        items+=("wa-off"           "Turn off 2FA for view")
        items+=("wa-on"            "Turn on 2FA for view")
        items+=("wa-off --unlock"  "Turn off 2FA for unlock")
        items+=("wa-on --unlock"   "Turn on 2FA for unlock")
        }

        _menu_has list-encrypted && \
        items+=("list-encrypted"    "List encrypted folder archives")

        _menu_has cleanup-encrypted && \
        items+=("cleanup-encrypted" "Remove stale archive records")

        items+=("logout"     "Clear session")

        # ── show zenity list ──
        local choice
        choice=$(zenity --list \
            --title="scrt4" \
            --text="<span font='22' weight='bold'>scrt4</span>   <span font='11' color='#94a3b8'>v${VERSION}</span>\n\n<span font='11' weight='bold' color='${status_color}'>\u25cf</span>  <span font='12' color='#64748b'>${status_line}</span>  <span font='12' color='#cbd5e1'>\u00b7</span>  <span font='12' color='#64748b'>${secret_count} secrets</span>\n<span font='10' color='#94a3b8'>Start typing to search</span>\n" \
            --column="Command" --column="Description" \
            --print-column=1 \
            "${items[@]}" \
            --ok-label="  Run  " \
            --cancel-label="  Close  " \
            --width=520 --height=580 2>/dev/null) || break

        [ -z "$choice" ] && break

        # ── handle selection ──
        case "$choice" in
            "run ...")
                local cmd
                cmd=$(zenity --entry \
                    --title="scrt4 \u2014 Run" \
                    --text="<span font='14' weight='bold'>Run command with secrets</span>\n\n<span font='11' color='#64748b'>Use \$env[NAME] for secret injection</span>\n" \
                    --entry-text='echo "$env[SECRET_NAME]"' \
                    --ok-label="  Execute  " \
                    --width=500 2>/dev/null) || continue
                [ -z "$cmd" ] && continue
                echo -e "${CYAN}Running: ${cmd}${NC}"
                _menu_dispatch run "$cmd"
                ;;

            "backup-vault --local")
                local dest
                dest=$(zenity --file-selection \
                    --title="Choose backup destination" \
                    --directory 2>/dev/null) || continue
                [ -z "$dest" ] && continue
                _menu_dispatch backup-vault --local "$dest"
                ;;

            "backup-key --save")
                _menu_backup_key_save_wizard
                ;;

            "wallet setup")
                _menu_dispatch wallet setup
                ;;

            "wa-off --unlock")
                _menu_dispatch wa-off --unlock
                ;;

            "wa-on --unlock")
                _menu_dispatch wa-on --unlock
                ;;

            *)
                echo -e "${CYAN}scrt4 ${choice}${NC}"
                case "$choice" in
                    unlock)     _menu_dispatch unlock ;;
                    status)
                        local status_out
                        status_out=$(_menu_dispatch status 2>&1)
                        zenity --info --title="scrt4 \u2014 Status" \
                            --text="$status_out" --width=400 2>/dev/null || true
                        ;;
                    list)
                        local list_out
                        list_out=$(_menu_dispatch list 2>&1)
                        if [ -z "$list_out" ]; then
                            zenity --info --title="scrt4 \u2014 Secret Names" \
                                --text="No secrets stored.\n\nAdd with: scrt4 add KEY=value" \
                                --width=350 2>/dev/null
                        else
                            zenity --text-info --title="scrt4 \u2014 Secret Names" \
                                --width=500 --height=400 --font="monospace" \
                                <<< "$list_out" 2>/dev/null || true
                        fi
                        ;;
                    view)               _menu_dispatch view ;;
                    add)                _menu_dispatch add ;;
                    import)             _menu_dispatch import ;;
                    share)              _menu_dispatch share ;;
                    receive)
                        local recv_code=""
                        recv_code=$(zenity --entry \
                            --title="scrt4 \u2014 Receive" \
                            --text="<span font='14' weight='bold'>Enter the wormhole code</span>\n\n<span font='11' color='#64748b'>The sender will show you a code like: 7-crossover-headline</span>\n" \
                            --ok-label="  Receive  " \
                            --cancel-label="  Cancel  " \
                            --width=450 2>/dev/null) || continue
                        if [ -n "$recv_code" ]; then
                            _menu_dispatch receive --code "$recv_code"
                        else
                            _menu_dispatch receive
                        fi
                        ;;
                    wallet)             _menu_dispatch wallet ;;
                    encrypt-folder)
                        local ef_folder
                        ef_folder=$(zenity --file-selection --directory \
                            --title="Select Folder to Encrypt" \
                            2>/dev/null) || continue
                        [ -n "$ef_folder" ] && _menu_dispatch encrypt-folder "$ef_folder"
                        ;;
                    decrypt-folder)
                        local df_file
                        df_file=$(zenity --file-selection \
                            --title="Select .scrt4 Archive" \
                            --file-filter="scrt4 archives|*.scrt4" \
                            2>/dev/null) || continue
                        [ -n "$df_file" ] && _menu_dispatch decrypt-folder "$df_file"
                        ;;
                    backup-vault)       _menu_dispatch backup-vault ;;
                    extend)             _menu_dispatch extend ;;
                    backup-key)         _menu_dispatch backup-key ;;
                    recover)
                        # GUI file picker for recovery file, then dispatch
                        local rec_file
                        rec_file=$(zenity --file-selection \
                            --title="Select Master Key Backup File" \
                            --file-filter="JSON files|*.json" \
                            2>/dev/null) || continue
                        [ -n "$rec_file" ] && _menu_dispatch recover "$rec_file"
                        ;;
                    backup-guide)       _menu_dispatch backup-guide ;;
                    rotate)             _menu_dispatch rotate ;;
                    setup)              _menu_dispatch setup ;;
                    wa-state)           _menu_dispatch wa-state ;;
                    wa-off)             _menu_dispatch wa-off ;;
                    wa-on)              _menu_dispatch wa-on ;;
                    list-encrypted)
                        local enc_out
                        enc_out=$(_menu_dispatch list-encrypted 2>&1)
                        if [ -z "$enc_out" ]; then
                            zenity --info --title="scrt4 \u2014 Encrypted Archives" \
                                --text="No encrypted folder archives tracked." \
                                --width=350 2>/dev/null
                        else
                            zenity --text-info --title="scrt4 \u2014 Encrypted Archives" \
                                --width=550 --height=400 --font="monospace" \
                                <<< "$enc_out" 2>/dev/null || true
                        fi
                        ;;
                    cleanup-encrypted)  _menu_dispatch cleanup-encrypted ;;
                    logout)             _menu_dispatch logout ;;
                esac
                ;;
        esac
    done
}

# ── backup-key --save wizard ────────────────────────────────────────
# Ported from v0.1.0 monolith. Handles the full GUI flow:
#   1. Pick destination directory
#   2. Retrieve master key from daemon
#   3. Prompt for recovery password (with confirmation)
#   4. Encrypt and save

_menu_backup_key_save_wizard() {
    local save_dest
    save_dest=$(zenity --file-selection \
        --title="scrt4 \u2014 Choose Backup Destination" \
        --directory 2>/dev/null) || return 0
    [ -z "$save_dest" ] && return 0

    _wa_gate || return 0

    # Retrieve master key from daemon
    echo -e "${CYAN}Retrieving master key from daemon...${NC}"
    local bk_response
    bk_response=$(send_request '{"method":"backup_key"}')
    local bk_success
    bk_success=$(echo "$bk_response" | jq -r '.success // false')
    if [ "$bk_success" != "true" ]; then
        local bk_error
        bk_error=$(echo "$bk_response" | jq -r '.error // "Unknown error"')
        zenity --error --title="scrt4" \
            --text="Failed to retrieve master key:\n${bk_error}" \
            --width=400 2>/dev/null
        return 0
    fi
    local bk_key
    bk_key=$(echo "$bk_response" | jq -r '.data.key')

    # Prompt for recovery password
    local pw_result
    pw_result=$(zenity --forms \
        --title="scrt4 \u2014 Encrypt Master Key" \
        --text="<span font='14' weight='bold'>Choose a recovery password</span>\n\n<span font='11' color='#64748b'>You will need this password to recover your master key later.\nMinimum 8 characters. Store it separately from the backup file.</span>\n" \
        --add-password="Recovery password" \
        --add-password="Confirm password" \
        --ok-label="  Encrypt & Save  " \
        --cancel-label="  Cancel  " \
        --width=460 2>/dev/null) || return 0
    [ -z "$pw_result" ] && return 0

    local pw1 pw2
    pw1=$(echo "$pw_result" | cut -d'|' -f1)
    pw2=$(echo "$pw_result" | cut -d'|' -f2)

    if [ "$pw1" != "$pw2" ]; then
        zenity --error --title="scrt4" \
            --text="Passwords do not match. No file was created." \
            --width=350 2>/dev/null
        return 0
    fi
    if [ ${#pw1} -lt 8 ]; then
        zenity --error --title="scrt4" \
            --text="Password must be at least 8 characters." \
            --width=350 2>/dev/null
        return 0
    fi

    # Encrypt master key with PBKDF2 + AES-256-CBC
    local bk_out_file="${save_dest}/encrypted-master-key-instructions.json"
    local bk_encrypt_script
    bk_encrypt_script=$(mktemp)
    cat > "$bk_encrypt_script" << 'BKPYEOF'
import json, os, sys, hashlib, base64, subprocess, datetime
lines = sys.stdin.read().split('\n', 1)
master_key, password = lines[0], lines[1]
out_file = sys.argv[1]
salt = os.urandom(16)
iv = os.urandom(16)
derived_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
proc = subprocess.run(['openssl', 'enc', '-aes-256-cbc',
    '-K', derived_key.hex(), '-iv', iv.hex(), '-nosalt'],
    input=master_key.encode(), capture_output=True)
if proc.returncode != 0:
    print('Encryption failed', file=sys.stderr); sys.exit(1)
backup = {
    'Type': 'MasterKeyBackup', 'Version': '2.0',
    'CreatedAt': datetime.datetime.now().astimezone().isoformat(),
    'SecurityMode': 'webauthn-prf',
    'Salt': base64.b64encode(salt).decode(),
    'IV': base64.b64encode(iv).decode(),
    'EncryptedMasterKey': base64.b64encode(proc.stdout).decode(),
    'DecryptionInstructions': {
        'Algorithm': 'AES-256-CBC', 'KeyDerivation': 'PBKDF2-SHA256',
        'Iterations': 100000, 'KeyLength': 32,
        'HowToDecrypt': [
            '1. Run: scrt4 recover encrypted-master-key-instructions.json',
            '2. Enter your recovery password when prompted',
            '3. Your master key will be displayed',
        ],
        'InlineRecoveryScript': (
            '#!/usr/bin/env python3\n'
            'import json, sys, hashlib, base64, subprocess, getpass\n'
            'with open(sys.argv[1], encoding="utf-8-sig") as f: backup = json.load(f)\n'
            'pw = getpass.getpass("Recovery password: ")\n'
            'salt = base64.b64decode(backup["Salt"])\n'
            'iv = base64.b64decode(backup["IV"])\n'
            'enc = base64.b64decode(backup["EncryptedMasterKey"])\n'
            'iters = backup.get("DecryptionInstructions", {}).get("Iterations", 100000)\n'
            'dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters, dklen=32)\n'
            'r = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-d",\n'
            '    "-K", dk.hex(), "-iv", iv.hex(), "-nosalt"],\n'
            '    input=enc, capture_output=True)\n'
            'if r.returncode != 0: print("Failed.", file=sys.stderr); sys.exit(1)\n'
            'key = r.stdout.decode().rstrip(chr(0))\n'
            'print(f"Master Key: {key} ({len(key)} chars)")\n')
    }
}
with open(out_file, 'w') as f:
    json.dump(backup, f, indent=2)
print('OK')
BKPYEOF
    local bk_result
    bk_result=$(printf '%s\n%s' "$bk_key" "$pw1" | python3 "$bk_encrypt_script" "$bk_out_file")
    local bk_rc=$?
    rm -f "$bk_encrypt_script"

    if [ $bk_rc -ne 0 ] || [ "$bk_result" != "OK" ]; then
        zenity --error --title="scrt4" \
            --text="Encryption failed." --width=300 2>/dev/null
        return 0
    fi

    zenity --info --title="scrt4" \
        --text="<span font='14' weight='bold'>Encrypted master key saved!</span>\n\n<span font='11'><b>Backup:</b>  ${bk_out_file}\n<b>Encrypted:</b>  Yes (AES-256-CBC, password-protected)\n<b>Raw key:</b>  NOT stored in these files</span>\n\n<span font='11' color='#f59e0b'>Remember your recovery password \u2014 it cannot be reset!</span>" \
        --ok-label="  Done  " \
        --width=520 2>/dev/null
}
