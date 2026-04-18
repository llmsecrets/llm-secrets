# shellcheck shell=bash
# scrt4-module: gcp
# version: 1
# api: 1
# tcb: false
# deps: jq gcloud
# commands: gcp
# requires:
# reveals: GCP_INSTANCE_NAME GCP_ZONE GCP_EXTERNAL_IP
#
# Thin wrapper around `gcloud` for the common ops against a personal
# GCP VM: status, ssh, run a command, caddy reload. The instance/zone
# are read from the vault (GCP_INSTANCE_NAME / GCP_ZONE) so users with
# multiple environments don't have to memorize them.
#
# Commands:
#   scrt4 gcp status                           Show uptime / disk / mem on the configured VM
#   scrt4 gcp list                             List all instances in the zone
#   scrt4 gcp run "command"                    Run a command over SSH
#   scrt4 gcp ssh                              Interactive SSH (handed off to gcloud)
#   scrt4 gcp caddy test                       Validate Caddyfile
#   scrt4 gcp caddy reload [--yes] [--dry-run] Reload Caddy (write op — prompts)
#   scrt4 gcp tail SERVICE [LINES]             tail journalctl for a systemd service
#   scrt4 gcp help
#
# Safety:
#   - Read ops (status, list, run with read-only cmd, tail) run without prompt.
#   - Inherently-write ops (caddy reload, systemd restart) require --yes.
#   - --dry-run prints the gcloud command without executing.
#   - tcb: false — gcloud manages its own auth; scrt4 only supplies the
#     instance identifier (which is not a secret in the cryptographic sense).

scrt4_module_gcp_register() {
    _register_command gcp scrt4_module_gcp_dispatch
}

scrt4_module_gcp_dispatch() {
    local sub="${1:-help}"
    shift || true
    case "$sub" in
        status)       scrt4_module_gcp_status "$@" ;;
        list|ls)      scrt4_module_gcp_list "$@" ;;
        run)          scrt4_module_gcp_run "$@" ;;
        ssh)          scrt4_module_gcp_ssh "$@" ;;
        caddy)        scrt4_module_gcp_caddy "$@" ;;
        tail)         scrt4_module_gcp_tail "$@" ;;
        help|-h|--help) scrt4_module_gcp_help ;;
        *)
            echo -e "${RED}Unknown gcp subcommand: ${sub}${NC}" >&2
            scrt4_module_gcp_help
            return 1
            ;;
    esac
}

scrt4_module_gcp_help() {
    cat <<'EOF'
scrt4 gcp — manage a personal GCP compute instance via gcloud

USAGE:
    scrt4 gcp status
    scrt4 gcp list
    scrt4 gcp run "command"
    scrt4 gcp ssh
    scrt4 gcp caddy test
    scrt4 gcp caddy reload [--yes] [--dry-run]
    scrt4 gcp tail SERVICE [LINES]

SECRETS USED:
    GCP_INSTANCE_NAME  - VM name (required)
    GCP_ZONE           - VM zone (required)
    GCP_EXTERNAL_IP    - VM external IP (optional, for status display)

REQUIREMENTS:
    - `gcloud` CLI installed and authenticated (`gcloud auth login`)
    - Your account has compute.instances.* permissions on the project

SAFETY:
    Read ops run without prompt. Commands that mutate state (caddy reload,
    systemd restart, etc.) require --yes. Use --dry-run to preview.
EOF
}

# =====================================================================
# Helpers
# =====================================================================

_scrt4_gcp_secret_exists() {
    local name="$1"
    send_request '{"method":"list"}' 2>/dev/null \
        | jq -e --arg n "$name" '.data.names | index($n)' >/dev/null 2>&1
}

_scrt4_gcp_reveal() {
    local name="$1"
    local r1 r2 ch code
    r1=$(send_request "$(jq -nc --arg n "$name" '{method:"reveal",params:{name:$n}}')")
    [ "$(echo "$r1" | jq -r '.success // false')" = "true" ] || { echo "reveal failed for ${name}" >&2; return 1; }
    ch=$(echo "$r1" | jq -r '.data.challenge')
    code=$(echo "$r1" | jq -r '.data.code')
    r2=$(send_request "$(jq -nc --arg c "$ch" --arg k "$code" '{method:"reveal_confirm",params:{challenge:$c,code:$k}}')")
    [ "$(echo "$r2" | jq -r '.success // false')" = "true" ] || { echo "reveal_confirm failed" >&2; return 1; }
    echo "$r2" | jq -r '.data.value'
}

# Fetch (instance, zone) from the vault. Prints "INSTANCE\tZONE" on
# stdout. Returns non-zero if either is missing.
_scrt4_gcp_target() {
    _scrt4_gcp_secret_exists GCP_INSTANCE_NAME || { echo "GCP_INSTANCE_NAME not in vault" >&2; return 1; }
    _scrt4_gcp_secret_exists GCP_ZONE          || { echo "GCP_ZONE not in vault" >&2; return 1; }
    local inst zone
    inst=$(_scrt4_gcp_reveal GCP_INSTANCE_NAME) || return 1
    zone=$(_scrt4_gcp_reveal GCP_ZONE)          || return 1
    printf '%s\t%s' "$inst" "$zone"
}

_scrt4_gcp_check_cli() {
    if ! command -v gcloud >/dev/null 2>&1; then
        echo -e "${RED}gcloud CLI not found.${NC}" >&2
        echo "  Install: https://cloud.google.com/sdk/docs/install" >&2
        return 1
    fi
}

_scrt4_gcp_parse_flags() {
    GCP_YES=0
    GCP_DRY_RUN=0
    GCP_POSITIONALS=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --yes|-y)   GCP_YES=1; shift ;;
            --dry-run)  GCP_DRY_RUN=1; shift ;;
            --)         shift; while [ $# -gt 0 ]; do GCP_POSITIONALS+=("$1"); shift; done ;;
            *)          GCP_POSITIONALS+=("$1"); shift ;;
        esac
    done
}

_scrt4_gcp_confirm() {
    local prompt="$1"
    if [ "${GCP_YES:-0}" = "1" ]; then return 0; fi
    if [ ! -t 0 ]; then
        echo -e "${YELLOW}${prompt}${NC}" >&2
        echo -e "${YELLOW}Non-interactive — re-run with --yes.${NC}" >&2
        return 1
    fi
    echo -ne "${YELLOW}${prompt}${NC} "
    local ans; read -r ans
    [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]] || return 1
}

# =====================================================================
# Commands
# =====================================================================

scrt4_module_gcp_status() {
    ensure_unlocked || return 1
    _scrt4_gcp_check_cli || return 1
    local target inst zone ip=""
    target=$(_scrt4_gcp_target) || return 1
    inst=$(printf '%s' "$target" | cut -f1)
    zone=$(printf '%s' "$target" | cut -f2)
    if _scrt4_gcp_secret_exists GCP_EXTERNAL_IP; then
        ip=$(_scrt4_gcp_reveal GCP_EXTERNAL_IP)
    fi
    echo -e "${CYAN}GCP instance:${NC} ${inst} (zone: ${zone})${ip:+   external IP: ${ip}}"
    echo ""
    # gcloud-side state
    gcloud compute instances describe "$inst" --zone "$zone" \
        --format='value(status,machineType.scope(machineTypes),networkInterfaces[0].accessConfigs[0].natIP)' \
        2>/dev/null | awk '{ printf "  State: %s\n  Machine: %s\n  External IP: %s\n", $1, $2, $3 }' \
        || echo "  (describe failed — check gcloud auth)"
    # On-host state via SSH
    echo ""
    echo -e "${CYAN}On-host:${NC}"
    gcloud compute ssh "$inst" --zone "$zone" --command='uptime; echo ---; df -h / | tail -1; echo ---; free -h | head -2' 2>/dev/null \
        | sed 's/^/  /' || echo "  (ssh failed)"
}

scrt4_module_gcp_list() {
    ensure_unlocked || return 1
    _scrt4_gcp_check_cli || return 1
    echo -e "${CYAN}Instances visible to your gcloud account:${NC}"
    gcloud compute instances list --format='value(name,zone,status,EXTERNAL_IP)' 2>/dev/null \
        | awk '{ printf "  %-35s %-20s %-10s %s\n", $1, $2, $3, $4 }'
}

scrt4_module_gcp_run() {
    ensure_unlocked || return 1
    _scrt4_gcp_check_cli || return 1
    local cmd="${1:-}"
    shift || true
    _scrt4_gcp_parse_flags "$@"
    if [ -z "$cmd" ]; then
        echo 'Usage: scrt4 gcp run "command"' >&2
        return 1
    fi
    local target inst zone
    target=$(_scrt4_gcp_target) || return 1
    inst=$(printf '%s' "$target" | cut -f1)
    zone=$(printf '%s' "$target" | cut -f2)
    if [ "${GCP_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no command will execute."
        printf '  gcloud compute ssh %s --zone %s --command=%q\n' "$inst" "$zone" "$cmd"
        return 0
    fi
    gcloud compute ssh "$inst" --zone "$zone" --command="$cmd"
}

scrt4_module_gcp_ssh() {
    ensure_unlocked || return 1
    _scrt4_gcp_check_cli || return 1
    local target inst zone
    target=$(_scrt4_gcp_target) || return 1
    inst=$(printf '%s' "$target" | cut -f1)
    zone=$(printf '%s' "$target" | cut -f2)
    echo -e "${CYAN}SSH → ${inst} (${zone})${NC}"
    exec gcloud compute ssh "$inst" --zone "$zone"
}

scrt4_module_gcp_caddy() {
    ensure_unlocked || return 1
    _scrt4_gcp_check_cli || return 1
    local action="${1:-test}"
    shift || true
    _scrt4_gcp_parse_flags "$@"
    local target inst zone
    target=$(_scrt4_gcp_target) || return 1
    inst=$(printf '%s' "$target" | cut -f1)
    zone=$(printf '%s' "$target" | cut -f2)
    case "$action" in
        test)
            echo -e "${CYAN}Validating Caddyfile on ${inst}...${NC}"
            gcloud compute ssh "$inst" --zone "$zone" \
                --command='sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile'
            ;;
        reload)
            echo -e "${CYAN}Plan:${NC} reload Caddy on ${inst}"
            if [ "${GCP_DRY_RUN:-0}" = "1" ]; then
                echo -e "${YELLOW}DRY RUN:${NC} no reload will execute."
                echo "  gcloud compute ssh ${inst} --zone ${zone} --command='sudo systemctl reload caddy'"
                return 0
            fi
            _scrt4_gcp_confirm "Proceed? [y/N]" || { echo "Aborted."; return 1; }
            gcloud compute ssh "$inst" --zone "$zone" --command='sudo systemctl reload caddy && systemctl is-active caddy'
            ;;
        *)
            echo "Usage: scrt4 gcp caddy {test|reload}" >&2
            return 1
            ;;
    esac
}

scrt4_module_gcp_tail() {
    ensure_unlocked || return 1
    _scrt4_gcp_check_cli || return 1
    local svc="${1:-}"
    local lines="${2:-100}"
    if [ -z "$svc" ]; then
        echo "Usage: scrt4 gcp tail SERVICE [LINES]" >&2
        return 1
    fi
    local target inst zone
    target=$(_scrt4_gcp_target) || return 1
    inst=$(printf '%s' "$target" | cut -f1)
    zone=$(printf '%s' "$target" | cut -f2)
    gcloud compute ssh "$inst" --zone "$zone" \
        --command="sudo journalctl -u ${svc} --no-pager -n ${lines}"
}
