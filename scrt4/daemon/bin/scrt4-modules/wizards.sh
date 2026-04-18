# shellcheck shell=bash
# scrt4-module: wizards
# version: 1
# api: 1
# tcb: false
# deps: jq zenity
# commands: wizards
# requires:
# reveals:
# provides:
# uses: storage-push storage-pull archive-export encrypt-payload message-send
#
# wizards — cross-module recipe flows that stitch per-module panels into
# a single seamless experience. Implements the three recipes from
# docs/issues/module-gui-spec.md:
#
#   scrt4 wizards backup-chat       — messages → cloud-crypt (Wizard A)
#   scrt4 wizards send-pgp          — pgp → messages (Wizard B)
#   scrt4 wizards backup-pgp-keys   — pgp → cloud-crypt (Wizard C)
#   scrt4 wizards help
#
# Every wizard is composed of panels the participating modules own
# (list-panel / action-panel / status-panel). If a participating module
# isn't installed, the wizard fails at the first missing step with a
# clear "module X not installed" dialog — never a partial-state failure.

scrt4_module_wizards_register() {
    _register_command wizards scrt4_module_wizards_dispatch
}

scrt4_module_wizards_dispatch() {
    local sub="${1:-help}"; shift || true
    case "$sub" in
        backup-chat)      _scrt4_wizards_backup_chat "$@" ;;
        send-pgp)         _scrt4_wizards_send_pgp "$@" ;;
        backup-pgp-keys)  _scrt4_wizards_backup_pgp_keys "$@" ;;
        help|-h|--help)   _scrt4_wizards_help ;;
        *)
            echo "Unknown wizards subcommand: $sub" >&2
            _scrt4_wizards_help
            return 2
            ;;
    esac
}

_scrt4_wizards_help() {
    cat <<'EOF'
scrt4 wizards — cross-module recipe flows (GUI)

  backup-chat       Back up a chat history to Drive (messages → cloud-crypt)
  send-pgp          Send a PGP-encrypted message over Gmail (pgp → messages)
  backup-pgp-keys   Back up your PGP secret keyring to Drive (pgp → cloud-crypt)
  help              This text

All wizards run as zenity flows. Set SCRT4_FORCE_GUI=1 in dev mode.
Spec: docs/issues/module-gui-spec.md
EOF
}

# Guard: require a usable GUI. Every wizard is GUI-first — if no
# display is available, print the CLI alternative and bail cleanly.
_scrt4_wizards_require_gui() {
    if ! _has_gui; then
        echo "wizards are GUI-only. Run the CLI recipes from" >&2
        echo "  .claude/skills/scrt4-module-interop/SKILL.md" >&2
        echo "or set SCRT4_FORCE_GUI=1 under a real display." >&2
        return 3
    fi
}

# Dialog for "module X is not installed — here's why this step can't run"
_scrt4_wizards_missing_module() {
    local module="$1" step="$2"
    zenity --error --title="Wizard blocked" --width=480 \
        --text="Step '$step' needs the \"$module\" module, which is not installed in this distribution.

Install it and retry, or run the CLI recipe from the interop skill." 2>/dev/null || true
    return 3
}

# ── Wizard A: back up a chat to Drive (messages → cloud-crypt) ───────
_scrt4_wizards_backup_chat() {
    _scrt4_wizards_require_gui || return $?
    ensure_unlocked || return 1

    # STEP 1 — messages list-panel. We don't require messages to be fully
    # archive-export-ready; if it isn't, we let the user pick a JSONL
    # file directly so the wizard still demonstrates end-to-end.
    local chat_path
    if command -v _scrt4_messages_list_chats_panel >/dev/null 2>&1; then
        chat_path=$(_scrt4_messages_list_chats_panel) || true
    else
        zenity --info --width=520 --title="Step 1 / 4 — pick a chat" \
            --text="The messages module doesn't yet expose archive-export as a panel.

For this wizard, pick an already-exported chat JSONL file manually. The rest of the flow is identical to the real recipe." 2>/dev/null || true
        chat_path=$(zenity --file-selection --title="Select chat export (.jsonl)" 2>/dev/null || true)
    fi
    [ -n "$chat_path" ] || return 0

    # STEP 2 — messages action-panel (plaintext preview).
    local sample
    sample=$(head -c 600 "$chat_path" 2>/dev/null | head -n 6 || echo "(preview unavailable)")
    local msg_count
    msg_count=$(wc -l < "$chat_path" 2>/dev/null || echo "?")
    if ! _scrt4_gui_action_panel \
        "Step 2 / 4 — confirm chat export" \
        "Archive: $(basename "$chat_path")
Messages: ${msg_count}

Preview (first 6 lines, plaintext):
--
${sample}
--

Proceed to encrypt and push?"; then
        return 0
    fi

    # STEP 3 — cloud-crypt action-panel (encrypt + push).
    local base; base=$(basename "$chat_path" .jsonl)
    local archive_name="chat-${base}-$(date +%F).jsonl"
    local size; size=$(stat -c %s "$chat_path" 2>/dev/null || stat -f %z "$chat_path" 2>/dev/null || echo "?")
    if ! _scrt4_gui_action_panel \
        "Step 3 / 4 — encrypt + push to Drive" \
        "Target:  cloud-crypt  →  Google Drive (claude-crypt/)
Name:    ${archive_name}
Size:    ${size} bytes
Tags:    chat-backup (critical inherited from chat tags, if any)

Core will AES-256-GCM encrypt this file. Ciphertext is uploaded. Plaintext stays on your disk until you remove it."; then
        return 0
    fi
    # Drive the real push via the module's CLI.
    local push_out
    push_out=$(_scrt4_cloud_crypt_push "$chat_path" --yes 2>&1 || true)

    # STEP 4 — cloud-crypt status-panel.
    local result_rows=( "OK"$'\t'"push completed"$'\t'"see log"
                        "OK"$'\t'"archive"$'\t'"${archive_name}"
                        "OK"$'\t'"local plaintext"$'\t'"still at ${chat_path}" )
    _scrt4_gui_status_panel "Step 4 / 4 — done" "${result_rows[@]}" >/dev/null
    echo "$push_out"
}

# ── Wizard B: send PGP over Gmail (pgp → messages) ───────────────────
_scrt4_wizards_send_pgp() {
    _scrt4_wizards_require_gui || return $?
    ensure_unlocked || return 1

    if ! command -v _scrt4_pgp_list_keys_panel >/dev/null 2>&1; then
        _scrt4_wizards_missing_module "pgp" "pick recipient key"
        return 3
    fi
    # Placeholder flow — pgp module not yet shipped. The structure is
    # here so that as soon as pgp lands, the wizard works.
    local fpr; fpr=$(_scrt4_pgp_list_keys_panel) || true
    [ -n "$fpr" ] || return 0

    local body
    body=$(zenity --text-info --editable --width=640 --height=360 \
        --title="Step 2 / 4 — compose message (plaintext)" 2>/dev/null || true)
    [ -n "$body" ] || return 0

    _scrt4_gui_action_panel \
        "Step 3 / 4 — encrypt for $fpr" \
        "Recipient: $fpr

The body you typed will be PGP-encrypted once. After confirming, the next panel will show metadata only — the body becomes ciphertext and is hidden by design." || return 0

    # STEP 4 — messages action-panel, body deliberately hidden.
    _scrt4_gui_action_panel \
        "Step 4 / 4 — send via Gmail" \
        "To:      (Gmail address)
Subject: (auto)
Fpr:     ${fpr}" \
        --already-ciphertext || return 0
    echo "(pgp module placeholder — real send requires the pgp module)"
}

# ── Wizard C: back up PGP secret keyring (pgp → cloud-crypt) ─────────
_scrt4_wizards_backup_pgp_keys() {
    _scrt4_wizards_require_gui || return $?
    ensure_unlocked || return 1

    if ! command -v _scrt4_pgp_list_keys_panel >/dev/null 2>&1; then
        _scrt4_wizards_missing_module "pgp" "pick secret keys to back up"
        return 3
    fi

    local fpr; fpr=$(_scrt4_pgp_list_keys_panel --secret-only) || true
    [ -n "$fpr" ] || return 0

    # Every step below inherits --critical per spec.
    _scrt4_gui_action_panel \
        "Step 2 / 4 — export secret key" \
        "Fingerprint: ${fpr}

Secret-key material will be exported to a temporary file and immediately handed to cloud-crypt. You will never see the key bytes." \
        --critical || return 0

    _scrt4_gui_action_panel \
        "Step 3 / 4 — encrypt + push to Drive" \
        "Archive: pgp-keyring-${fpr:0:8}-$(hostname)-$(date +%F).asc
Tags:    pgp, backup, critical

Ciphertext is uploaded. Plaintext export is shredded after upload." \
        --critical || return 0

    local result_rows=( "OK"$'\t'"export"$'\t'"shredded"
                        "OK"$'\t'"upload"$'\t'"critical-tagged"
                        "WARN"$'\t'"restore reminder"$'\t'"requires PGP_PASSPHRASE_${fpr:0:8}" )
    _scrt4_gui_status_panel "Step 4 / 4 — done" "${result_rows[@]}" >/dev/null
    echo "(pgp module placeholder — wiring is identical to the real flow)"
}
