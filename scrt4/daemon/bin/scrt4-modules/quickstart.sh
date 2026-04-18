# shellcheck shell=bash
# scrt4-module: quickstart
# version: 1
# api: 1
# tcb: false
# deps:
# commands: quickstart
# requires:
# reveals:
#
# First-run walkthrough. No secrets required — this module only reads
# vault *names* (via list) and prints guidance. Nothing is revealed,
# nothing is mutated.
#
# Commands:
#   scrt4 quickstart                Interactive walkthrough (or `check` if non-interactive)
#   scrt4 quickstart check          Read-only readiness snapshot
#   scrt4 quickstart templates      Print `scrt4 add` commands for common modules
#   scrt4 quickstart help
#
# tcb: false — does not call reveal, never handles secret values.

scrt4_module_quickstart_register() {
    _register_command quickstart scrt4_module_quickstart_dispatch
}

scrt4_module_quickstart_dispatch() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        ""|run)            scrt4_module_quickstart_run "$@" ;;
        check)             scrt4_module_quickstart_check "$@" ;;
        templates|tpl)     scrt4_module_quickstart_templates "$@" ;;
        help|-h|--help)    scrt4_module_quickstart_help ;;
        *)
            echo -e "${RED}Unknown quickstart subcommand: ${sub}${NC}" >&2
            scrt4_module_quickstart_help
            return 1
            ;;
    esac
}

scrt4_module_quickstart_help() {
    cat <<'EOF'
scrt4 quickstart — first-run walkthrough and readiness snapshot

USAGE:
    scrt4 quickstart              Interactive walkthrough (falls back to `check`)
    scrt4 quickstart check        Readiness snapshot — read-only
    scrt4 quickstart templates    Print `scrt4 add` templates for common modules

This module never reveals any secret; it only reads the *names* in the
vault (via `list`) so it can show you which recommended secrets you
already have and which you still need to add.

    SAFETY:
    Does not call reveal. Does not mutate. Safe to re-run.
EOF
}

# =====================================================================
# Helpers
# =====================================================================

_scrt4_qs_vault_names() {
    send_request '{"method":"list"}' 2>/dev/null \
        | jq -r '.data.names[]?' 2>/dev/null | sort
}

_scrt4_qs_have() {
    local name="$1" names="$2"
    printf '%s\n' "$names" | grep -Fxq "$name"
}

_scrt4_qs_print_check_row() {
    local name="$1" have=$2 purpose="$3"
    if [ "$have" = "1" ]; then
        echo -e "  ${GREEN}OK${NC}      ${name}  — ${purpose}"
    else
        echo -e "  ${YELLOW}MISSING${NC} ${name}  — ${purpose}"
    fi
}

# =====================================================================
# check — readiness snapshot
# =====================================================================

scrt4_module_quickstart_check() {
    ensure_unlocked || return 1
    echo -e "${CYAN}scrt4 quickstart — readiness check${NC}"
    echo ""

    local names
    names=$(_scrt4_qs_vault_names)
    local count
    count=$(printf '%s\n' "$names" | grep -c . || true)
    echo "Vault status:  ${count} secret name(s) present"
    echo ""

    echo "Common modules — which secrets do you have?"
    echo ""

    echo "  [github]"
    _scrt4_qs_print_check_row GITHUB_PAT \
        "$(_scrt4_qs_have GITHUB_PAT "$names"      && echo 1 || echo 0)" \
        "GitHub API token (issues, PRs, repos)"
    _scrt4_qs_print_check_row GITHUB_USERNAME \
        "$(_scrt4_qs_have GITHUB_USERNAME "$names" && echo 1 || echo 0)" \
        "your GitHub login"
    echo ""

    echo "  [stripe]"
    _scrt4_qs_print_check_row STRIPE_SECRET_KEY \
        "$(_scrt4_qs_have STRIPE_SECRET_KEY "$names" && echo 1 || echo 0)" \
        "Stripe API key (restricted recommended)"
    echo ""

    echo "  [gcp]"
    _scrt4_qs_print_check_row GCP_INSTANCE_NAME \
        "$(_scrt4_qs_have GCP_INSTANCE_NAME "$names" && echo 1 || echo 0)" \
        "VM name"
    _scrt4_qs_print_check_row GCP_ZONE \
        "$(_scrt4_qs_have GCP_ZONE "$names"          && echo 1 || echo 0)" \
        "VM zone"
    echo ""

    echo "  [website / domain]"
    _scrt4_qs_print_check_row VERCEL_TOKEN \
        "$(_scrt4_qs_have VERCEL_TOKEN "$names" && echo 1 || echo 0)" \
        "Vercel deploys"
    _scrt4_qs_print_check_row GODADDY_API_KEY \
        "$(_scrt4_qs_have GODADDY_API_KEY "$names" && echo 1 || echo 0)" \
        "GoDaddy DNS read/write (optional)"
    echo ""

    echo "  [messages]"
    _scrt4_qs_print_check_row personal_google_workspace \
        "$(_scrt4_qs_have personal_google_workspace "$names" && echo 1 || echo 0)" \
        "Gmail via OAuth (optional)"
    echo ""

    echo "Next steps:"
    echo "  - Add a missing secret:   scrt4 quickstart templates | less"
    echo "  - Update CLAUDE.md now:   scrt4 learn"
    echo "  - Use in a command:       scrt4 run 'echo \$env[NAME]'"
    echo ""
    echo "See docs/SECRETS.md for per-secret generation + scopes + rotation."
}

# =====================================================================
# templates — print `scrt4 add` lines
# =====================================================================

scrt4_module_quickstart_templates() {
    cat <<'EOF'
# scrt4 quickstart — copy the lines you need, fill in VALUE, then run.
# See docs/SECRETS.md for how to generate each one (scopes, rotation).

# --- github -----------------------------------------------------------
scrt4 add GITHUB_PAT=VALUE           # fine-grained PAT, scopes: repo + read:user
scrt4 add GITHUB_USERNAME=VALUE      # your github login

# --- stripe -----------------------------------------------------------
scrt4 add STRIPE_SECRET_KEY=VALUE    # restricted key (read + refunds is a good default)

# --- gcp --------------------------------------------------------------
scrt4 add GCP_INSTANCE_NAME=VALUE    # e.g. prod-app-instance
scrt4 add GCP_ZONE=VALUE             # e.g. us-east4-c
scrt4 add GCP_EXTERNAL_IP=VALUE      # optional — for status display only

# --- website / domain -------------------------------------------------
scrt4 add VERCEL_TOKEN=VALUE         # https://vercel.com/account/tokens
scrt4 add GODADDY_API_KEY=VALUE      # https://developer.godaddy.com/keys
scrt4 add GODADDY_API_SECRET=VALUE   # (same page — shown once)

# --- wallet (ETH RPC, keys) ------------------------------------------
scrt4 add ALCHEMY_RPC_URL=VALUE
scrt4 add ALCHEMY_SEPOLIA_RPC_URL=VALUE
scrt4 add ETHERSCAN_API_KEY=VALUE
# Private keys — generate locally, never paste from anywhere:
#   scrt4 add PRIVATE_KEY=$(openssl rand -hex 32)

# --- messages (Gmail via OAuth refresh token) ------------------------
# Assemble the opaque blob per docs/SECRETS.md → messages; then:
scrt4 add 'personal_google_workspace={...}'
EOF
}

# =====================================================================
# run — walkthrough (interactive; falls back to check)
# =====================================================================

scrt4_module_quickstart_run() {
    # If not on a TTY, don't try to prompt — just print the snapshot.
    if [ ! -t 0 ] || [ ! -t 1 ]; then
        scrt4_module_quickstart_check
        return 0
    fi

    echo -e "${CYAN}Welcome to scrt4.${NC}"
    echo ""
    echo "This walkthrough will:"
    echo "  1. Check your vault readiness for common modules"
    echo "  2. Show you the exact 'scrt4 add' lines for missing secrets"
    echo "  3. Offer to regenerate your global CLAUDE.md with current names"
    echo ""
    read -rp "Continue? [Y/n] " ans
    case "${ans:-Y}" in
        [Nn]*) echo "Aborted."; return 0 ;;
    esac

    echo ""
    scrt4_module_quickstart_check
    echo ""
    read -rp "Print add-templates for every common secret? [y/N] " ans
    case "${ans:-N}" in
        [Yy]*)
            echo ""
            scrt4_module_quickstart_templates
            echo ""
            ;;
    esac

    read -rp "Regenerate ~/.claude/CLAUDE.md with current names now? [Y/n] " ans
    case "${ans:-Y}" in
        [Nn]*) : ;;
        *)
            if declare -F cmd_learn >/dev/null 2>&1; then
                cmd_learn
            else
                echo -e "${YELLOW}cmd_learn not available; run: scrt4 learn${NC}"
            fi
            ;;
    esac

    echo ""
    echo -e "${GREEN}Done.${NC} For deeper docs: docs/SECRETS.md, docs/MODULES.md."
}
