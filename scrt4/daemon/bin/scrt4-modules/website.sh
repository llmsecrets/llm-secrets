# shellcheck shell=bash
# scrt4-module: website
# version: 1
# api: 1
# tcb: false
# deps: jq curl
# commands: website
# requires:
# reveals: VERCEL_TOKEN GCP_INSTANCE_NAME GCP_ZONE GCP_EXTERNAL_IP GODADDY_API_KEY GODADDY_API_SECRET
#
# Deploy websites to an existing user-owned domain.
#
# Two deploy targets:
#   1. Static mode (default):  Vercel + alias to your existing domain
#   2. App  mode (--app):      GCP VM + Caddy reverse-proxy + systemd unit
#
# Preconditions:
#   - You already own the domain. This module does NOT buy domains.
#   - For static mode: VERCEL_TOKEN in the vault and `vercel` CLI installed.
#   - For app mode:    GCP_INSTANCE_NAME / GCP_ZONE in vault, gcloud authed.
#   - For GoDaddy DNS helpers: GODADDY_API_KEY / GODADDY_API_SECRET.
#
# Commands:
#   scrt4 website help
#   scrt4 website init                            Show vault/tool readiness checklist
#   scrt4 website list                            List current Vercel deployments
#   scrt4 website deploy DIR --domain D [--yes] [--dry-run]
#   scrt4 website status DOMAIN                   DNS + HTTPS + deploy health
#   scrt4 website dns list DOMAIN                 List GoDaddy DNS records
#   scrt4 website app deploy DIR --domain D --port P [--yes] [--dry-run]
#   scrt4 website app status DOMAIN               GCP service health
#   scrt4 website app logs DOMAIN [--tail N]      journalctl tail
#
# Safety:
#   - Read ops run without prompt (init, list, status, dns list, app status, app logs).
#   - Write ops (deploy, app deploy) require --yes and support --dry-run.
#   - Tokens are revealed per-call, used, and unset.
#   - tcb: false — network/CLI ops only.

scrt4_module_website_register() {
    _register_command website scrt4_module_website_dispatch
}

scrt4_module_website_dispatch() {
    local sub="${1:-help}"
    shift || true
    case "$sub" in
        init)             scrt4_module_website_init "$@" ;;
        list|ls)          scrt4_module_website_list "$@" ;;
        deploy)           scrt4_module_website_deploy "$@" ;;
        status)           scrt4_module_website_status "$@" ;;
        dns)              scrt4_module_website_dns "$@" ;;
        app)              scrt4_module_website_app "$@" ;;
        help|-h|--help)   scrt4_module_website_help ;;
        *)
            echo -e "${RED}Unknown website subcommand: ${sub}${NC}" >&2
            scrt4_module_website_help
            return 1
            ;;
    esac
}

scrt4_module_website_help() {
    cat <<'EOF'
scrt4 website — deploy to your existing domain

USAGE (static — Vercel):
    scrt4 website init
    scrt4 website list
    scrt4 website deploy DIR --domain D [--yes] [--dry-run]
    scrt4 website status DOMAIN

USAGE (DNS helpers — GoDaddy):
    scrt4 website dns list DOMAIN

USAGE (app — GCP + Caddy):
    scrt4 website app deploy DIR --domain D --port P [--yes] [--dry-run]
    scrt4 website app status DOMAIN
    scrt4 website app logs DOMAIN [--tail N]

SECRETS (varies by mode):
    Static:  VERCEL_TOKEN
    App:     GCP_INSTANCE_NAME, GCP_ZONE, GCP_EXTERNAL_IP
    DNS:     GODADDY_API_KEY, GODADDY_API_SECRET (GoDaddy)

PRECONDITION: You already own the domain.
              This module does not buy, transfer, or register domains.

SAFETY:
    Writes (deploy, app deploy) require --yes; --dry-run prints the plan.
EOF
}

# =====================================================================
# Helpers (standard scrt4 module idioms)
# =====================================================================

_scrt4_website_secret_exists() {
    local name="$1"
    send_request '{"method":"list"}' 2>/dev/null \
        | jq -e --arg n "$name" '.data.names | index($n)' >/dev/null 2>&1
}

_scrt4_website_reveal() {
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

_scrt4_website_parse_flags() {
    WEB_YES=0
    WEB_DRY_RUN=0
    WEB_DOMAIN=""
    WEB_PORT=""
    WEB_TAIL=""
    WEB_POSITIONALS=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --yes|-y)     WEB_YES=1; shift ;;
            --dry-run)    WEB_DRY_RUN=1; shift ;;
            --domain)     WEB_DOMAIN="${2:-}"; shift 2 ;;
            --domain=*)   WEB_DOMAIN="${1#--domain=}"; shift ;;
            --port)       WEB_PORT="${2:-}"; shift 2 ;;
            --port=*)     WEB_PORT="${1#--port=}"; shift ;;
            --tail)       WEB_TAIL="${2:-}"; shift 2 ;;
            --tail=*)     WEB_TAIL="${1#--tail=}"; shift ;;
            --)           shift; while [ $# -gt 0 ]; do WEB_POSITIONALS+=("$1"); shift; done ;;
            *)            WEB_POSITIONALS+=("$1"); shift ;;
        esac
    done
}

_scrt4_website_confirm() {
    local prompt="$1"
    if [ "${WEB_YES:-0}" = "1" ]; then return 0; fi
    if [ ! -t 0 ]; then
        echo -e "${YELLOW}${prompt}${NC}" >&2
        echo -e "${YELLOW}Non-interactive — re-run with --yes.${NC}" >&2
        return 1
    fi
    echo -ne "${YELLOW}${prompt}${NC} "
    local ans; read -r ans
    [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]] || return 1
}

_scrt4_website_check_cmd() {
    local cmd="$1" install_hint="$2"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${RED}${cmd} not found.${NC}" >&2
        [ -n "$install_hint" ] && echo "  Install: ${install_hint}" >&2
        return 1
    fi
}

# Redact a bearer token for dry-run display: show prefix + length.
_scrt4_website_redact() {
    local s="${1:-}"
    local n=${#s}
    if [ "$n" -ge 8 ]; then
        echo "${s:0:4}...[${n} chars]"
    else
        echo "[redacted — ${n} chars]"
    fi
}

# =====================================================================
# init — readiness checklist
# =====================================================================

scrt4_module_website_init() {
    ensure_unlocked || return 1
    echo -e "${CYAN}scrt4 website — readiness check${NC}"
    echo ""
    echo "Static (Vercel) mode:"
    _scrt4_website_secret_exists VERCEL_TOKEN \
        && echo -e "  ${GREEN}OK${NC}      VERCEL_TOKEN in vault" \
        || echo -e "  ${YELLOW}MISSING${NC} VERCEL_TOKEN    (run: scrt4 add VERCEL_TOKEN=...)"
    if command -v vercel >/dev/null 2>&1; then
        echo -e "  ${GREEN}OK${NC}      vercel CLI: $(vercel --version 2>/dev/null | head -1)"
    else
        echo -e "  ${YELLOW}MISSING${NC} vercel CLI       (npm i -g vercel  or  curl -fsSL https://vercel.com/install.sh | sh)"
    fi
    echo ""
    echo "App (GCP + Caddy) mode:"
    for s in GCP_INSTANCE_NAME GCP_ZONE; do
        _scrt4_website_secret_exists "$s" \
            && echo -e "  ${GREEN}OK${NC}      ${s} in vault" \
            || echo -e "  ${YELLOW}MISSING${NC} ${s}    (run: scrt4 add ${s}=...)"
    done
    if command -v gcloud >/dev/null 2>&1; then
        echo -e "  ${GREEN}OK${NC}      gcloud CLI: $(gcloud --version 2>/dev/null | head -1)"
    else
        echo -e "  ${YELLOW}MISSING${NC} gcloud CLI       (https://cloud.google.com/sdk/docs/install)"
    fi
    echo ""
    echo "DNS (GoDaddy) helpers:"
    for s in GODADDY_API_KEY GODADDY_API_SECRET; do
        _scrt4_website_secret_exists "$s" \
            && echo -e "  ${GREEN}OK${NC}      ${s} in vault" \
            || echo -e "  ${YELLOW}MISSING${NC} ${s}    (optional — only for DNS helpers)"
    done
    echo ""
    echo "Next: scrt4 website deploy ./dist --domain mysite.example.com --dry-run"
}

# =====================================================================
# list — Vercel deployments
# =====================================================================

scrt4_module_website_list() {
    ensure_unlocked || return 1
    _scrt4_website_check_cmd curl "https://curl.se" || return 1
    _scrt4_website_secret_exists VERCEL_TOKEN || { echo "VERCEL_TOKEN not in vault" >&2; return 1; }
    local tok
    tok=$(_scrt4_website_reveal VERCEL_TOKEN) || return 1
    local resp
    resp=$(curl -sS -H "Authorization: Bearer ${tok}" \
        "https://api.vercel.com/v6/deployments?limit=20" 2>/dev/null)
    unset tok
    if [ -z "$resp" ] || [ "$(echo "$resp" | jq -r '.error.code // empty')" != "" ]; then
        echo -e "${RED}Vercel API error:${NC} $(echo "$resp" | jq -r '.error.message // "unknown"')" >&2
        return 1
    fi
    echo -e "${CYAN}Recent Vercel deployments:${NC}"
    echo "$resp" | jq -r '.deployments[]? | "  \(.state)\t\(.name)\t\(.url)\t\(.createdAt)"' \
        | awk -F '\t' '{ printf "  %-8s %-30s %-45s %s\n", $1, $2, $3, strftime("%Y-%m-%d %H:%M", $4/1000) }'
}

# =====================================================================
# deploy — static via Vercel
# =====================================================================

scrt4_module_website_deploy() {
    local dir="${1:-}"
    shift || true
    _scrt4_website_parse_flags "$@"

    if [ -z "$dir" ] || [ "$dir" = "--domain" ]; then
        echo "Usage: scrt4 website deploy DIR --domain DOMAIN [--yes] [--dry-run]" >&2
        return 1
    fi
    if [ -z "$WEB_DOMAIN" ]; then
        echo -e "${RED}--domain required.${NC}" >&2
        echo "Usage: scrt4 website deploy DIR --domain DOMAIN [--yes] [--dry-run]" >&2
        return 1
    fi
    if [ ! -d "$dir" ]; then
        echo -e "${RED}Directory not found: ${dir}${NC}" >&2
        return 1
    fi

    # Plan
    echo -e "${CYAN}Plan:${NC}"
    echo "  Dir:    $dir"
    echo "  Domain: $WEB_DOMAIN  (must be owned by you; module does NOT register domains)"
    echo "  Target: Vercel (production)"
    echo "  Steps:  1. vercel deploy --prod"
    echo "          2. vercel alias DEPLOYMENT_URL ${WEB_DOMAIN}"
    echo "          3. Print DNS record you must add (CNAME → cname.vercel-dns.com)"
    echo ""

    if [ "${WEB_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN — no deploy.${NC}"
        echo "  Would: vercel deploy --prod --token [redacted — from vault]"
        echo "  Would: vercel alias DEPLOYMENT_URL ${WEB_DOMAIN} --token [redacted]"
        return 0
    fi

    ensure_unlocked || return 1
    _scrt4_website_check_cmd vercel "npm i -g vercel" || return 1
    _scrt4_website_secret_exists VERCEL_TOKEN || { echo "VERCEL_TOKEN not in vault" >&2; return 1; }
    _scrt4_website_confirm "Proceed with deploy to ${WEB_DOMAIN}? [y/N]" || { echo "Aborted."; return 1; }

    local tok
    tok=$(_scrt4_website_reveal VERCEL_TOKEN) || return 1
    local deploy_url
    deploy_url=$(cd "$dir" && vercel deploy --prod --yes --token "$tok" 2>&1 | tail -1)
    if [[ ! "$deploy_url" =~ ^https?:// ]]; then
        echo -e "${RED}Deploy did not produce a URL:${NC} $deploy_url" >&2
        unset tok
        return 1
    fi
    echo -e "${GREEN}Deployed:${NC} $deploy_url"

    vercel alias "$deploy_url" "$WEB_DOMAIN" --token "$tok" >/dev/null 2>&1 \
        && echo -e "${GREEN}Aliased:${NC}  https://${WEB_DOMAIN}" \
        || echo -e "${YELLOW}Alias may need a DNS CNAME first (see below).${NC}"
    unset tok

    cat <<EOF

${CYAN:-}DNS setup (one-time):${NC:-}
  Add a CNAME record at your registrar:
    ${WEB_DOMAIN}   CNAME   cname.vercel-dns.com
  Or for apex domains, an ALIAS/ANAME or two A records — see:
    https://vercel.com/docs/projects/domains/working-with-domains

EOF
}

# =====================================================================
# status — DNS, TLS, Vercel deployment
# =====================================================================

scrt4_module_website_status() {
    local domain="${1:-}"
    if [ -z "$domain" ]; then
        echo "Usage: scrt4 website status DOMAIN" >&2
        return 1
    fi
    ensure_unlocked || return 1
    echo -e "${CYAN}Status: ${domain}${NC}"
    echo ""
    echo "DNS:"
    if command -v dig >/dev/null 2>&1; then
        dig +short "$domain" | sed 's/^/  /' || echo "  (dig failed)"
    else
        getent hosts "$domain" | sed 's/^/  /' || echo "  (getent failed)"
    fi
    echo ""
    echo "HTTPS:"
    local http_info
    http_info=$(curl -sS -o /dev/null -w "  %{http_code} (%{time_total}s, TLS %{ssl_verify_result})\n" \
        --max-time 10 "https://${domain}/" 2>&1)
    echo "$http_info"
    echo ""
    if _scrt4_website_secret_exists VERCEL_TOKEN; then
        echo "Vercel:"
        local tok
        tok=$(_scrt4_website_reveal VERCEL_TOKEN) || return 1
        local resp
        resp=$(curl -sS -H "Authorization: Bearer ${tok}" \
            "https://api.vercel.com/v9/projects" 2>/dev/null)
        unset tok
        echo "$resp" | jq -r --arg d "$domain" '
            .projects[]? as $p
            | ($p.targets.production.alias // [])[]?
            | select(. == $d)
            | "  project: \($p.name)  latest: \($p.targets.production.url)"
        ' 2>/dev/null || echo "  (no matching project)"
    fi
}

# =====================================================================
# dns — GoDaddy record helpers
# =====================================================================

scrt4_module_website_dns() {
    local action="${1:-}"
    shift || true
    case "$action" in
        list|ls)  scrt4_module_website_dns_list "$@" ;;
        *)
            echo "Usage: scrt4 website dns list DOMAIN" >&2
            return 1
            ;;
    esac
}

scrt4_module_website_dns_list() {
    local domain="${1:-}"
    if [ -z "$domain" ]; then
        echo "Usage: scrt4 website dns list DOMAIN" >&2
        return 1
    fi
    ensure_unlocked || return 1
    _scrt4_website_check_cmd curl "https://curl.se" || return 1
    _scrt4_website_secret_exists GODADDY_API_KEY    || { echo "GODADDY_API_KEY not in vault" >&2; return 1; }
    _scrt4_website_secret_exists GODADDY_API_SECRET || { echo "GODADDY_API_SECRET not in vault" >&2; return 1; }

    local k s
    k=$(_scrt4_website_reveal GODADDY_API_KEY)    || return 1
    s=$(_scrt4_website_reveal GODADDY_API_SECRET) || return 1

    local resp
    resp=$(curl -sS -H "Authorization: sso-key ${k}:${s}" \
        "https://api.godaddy.com/v1/domains/${domain}/records" 2>/dev/null)
    unset k s

    if [ -z "$resp" ] || [ "$(echo "$resp" | jq -r 'type')" != "array" ]; then
        echo -e "${RED}GoDaddy API error:${NC} $(echo "$resp" | jq -r '.message // .error // "unknown"')" >&2
        return 1
    fi
    echo -e "${CYAN}DNS records for ${domain}:${NC}"
    echo "$resp" | jq -r '.[] | "  \(.type)\t\(.name)\t\(.data)\t\(.ttl)"' \
        | awk -F '\t' '{ printf "  %-8s %-25s %-40s TTL=%s\n", $1, $2, $3, $4 }'
}

# =====================================================================
# app mode — rsync to GCP + Caddy + systemd
# =====================================================================

scrt4_module_website_app() {
    local sub="${1:-help}"
    shift || true
    case "$sub" in
        deploy) scrt4_module_website_app_deploy "$@" ;;
        status) scrt4_module_website_app_status "$@" ;;
        logs)   scrt4_module_website_app_logs   "$@" ;;
        *)
            echo "Usage: scrt4 website app {deploy|status|logs} ..." >&2
            return 1
            ;;
    esac
}

_scrt4_website_gcp_target() {
    _scrt4_website_secret_exists GCP_INSTANCE_NAME || { echo "GCP_INSTANCE_NAME not in vault" >&2; return 1; }
    _scrt4_website_secret_exists GCP_ZONE          || { echo "GCP_ZONE not in vault" >&2; return 1; }
    local inst zone
    inst=$(_scrt4_website_reveal GCP_INSTANCE_NAME) || return 1
    zone=$(_scrt4_website_reveal GCP_ZONE)          || return 1
    printf '%s\t%s' "$inst" "$zone"
}

scrt4_module_website_app_deploy() {
    local dir="${1:-}"
    shift || true
    _scrt4_website_parse_flags "$@"

    if [ -z "$dir" ] || [ "$dir" = "--domain" ]; then
        echo "Usage: scrt4 website app deploy DIR --domain DOMAIN --port PORT [--yes] [--dry-run]" >&2
        return 1
    fi
    if [ -z "$WEB_DOMAIN" ] || [ -z "$WEB_PORT" ]; then
        echo -e "${RED}--domain and --port required.${NC}" >&2
        return 1
    fi
    if [ ! -d "$dir" ]; then
        echo -e "${RED}Directory not found: ${dir}${NC}" >&2
        return 1
    fi
    case "$WEB_PORT" in
        ''|*[!0-9]*) echo "--port must be numeric" >&2; return 1 ;;
    esac

    local slug
    slug=$(echo "$WEB_DOMAIN" | tr 'A-Z.' 'a-z-' | tr -cd 'a-z0-9-')
    local remote_dir="/opt/scrt4-app-${slug}"
    local unit_name="scrt4-app-${slug}.service"
    local caddy_snippet="/etc/caddy/sites/${slug}.caddy"

    echo -e "${CYAN}Plan:${NC}"
    echo "  Local dir:     $dir"
    echo "  Domain:        $WEB_DOMAIN  (must resolve to GCP VM IP; set A record yourself)"
    echo "  Port:          $WEB_PORT   (service listens on 127.0.0.1:${WEB_PORT})"
    echo "  Remote dir:    $remote_dir"
    echo "  systemd unit:  $unit_name"
    echo "  Caddy file:    $caddy_snippet"
    echo "  Steps:"
    echo "    1. rsync $dir -> $remote_dir (over gcloud ssh)"
    echo "    2. Write systemd unit (runs: ./start.sh — user must provide)"
    echo "    3. Write Caddy snippet:  https://${WEB_DOMAIN} { reverse_proxy localhost:${WEB_PORT} }"
    echo "    4. systemctl daemon-reload && enable --now ${unit_name}"
    echo "    5. caddy validate && systemctl reload caddy"
    echo ""

    if [ "${WEB_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN — no changes.${NC}"
        return 0
    fi

    if [ ! -x "${dir}/start.sh" ]; then
        echo -e "${RED}${dir}/start.sh not found or not executable.${NC}" >&2
        echo "  Create a start.sh that launches your service on \$PORT (env var provided by the unit)." >&2
        return 1
    fi

    ensure_unlocked || return 1
    _scrt4_website_check_cmd gcloud "https://cloud.google.com/sdk/docs/install" || return 1
    _scrt4_website_confirm "Proceed with app deploy of ${WEB_DOMAIN}? [y/N]" || { echo "Aborted."; return 1; }

    local target inst zone
    target=$(_scrt4_website_gcp_target) || return 1
    inst=$(printf '%s' "$target" | cut -f1)
    zone=$(printf '%s' "$target" | cut -f2)

    echo -e "${CYAN}rsync → ${inst}:${remote_dir}${NC}"
    gcloud compute ssh "$inst" --zone "$zone" \
        --command="sudo mkdir -p ${remote_dir} && sudo chown \$(id -u):\$(id -g) ${remote_dir}" \
        >/dev/null 2>&1 || { echo -e "${RED}remote prep failed${NC}" >&2; return 1; }

    # Use gcloud scp for the transfer
    gcloud compute scp --recurse "$dir"/* "${inst}:${remote_dir}/" --zone "$zone" \
        >/dev/null 2>&1 || { echo -e "${RED}scp failed${NC}" >&2; return 1; }

    echo -e "${CYAN}Installing systemd unit...${NC}"
    local unit_body
    unit_body=$(cat <<UNIT
[Unit]
Description=scrt4 app — ${WEB_DOMAIN}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${remote_dir}
Environment=PORT=${WEB_PORT}
ExecStart=${remote_dir}/start.sh
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
)
    local caddy_body
    caddy_body="https://${WEB_DOMAIN} {
    reverse_proxy localhost:${WEB_PORT}
}
"
    local install_cmd
    install_cmd=$(cat <<CMD
set -e
sudo tee /etc/systemd/system/${unit_name} >/dev/null <<'UNIT'
${unit_body}
UNIT
sudo mkdir -p /etc/caddy/sites
sudo tee ${caddy_snippet} >/dev/null <<'CDY'
${caddy_body}
CDY
grep -q 'import /etc/caddy/sites/\*.caddy' /etc/caddy/Caddyfile || \
    echo 'import /etc/caddy/sites/*.caddy' | sudo tee -a /etc/caddy/Caddyfile >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now ${unit_name}
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl reload caddy
systemctl is-active ${unit_name}
CMD
)
    gcloud compute ssh "$inst" --zone "$zone" --command="$install_cmd" \
        || { echo -e "${RED}remote install failed${NC}" >&2; return 1; }

    echo -e "${GREEN}Deployed.${NC} https://${WEB_DOMAIN}"
    echo "  Make sure ${WEB_DOMAIN} has an A record -> GCP VM's external IP."
}

scrt4_module_website_app_status() {
    local domain="${1:-}"
    if [ -z "$domain" ]; then
        echo "Usage: scrt4 website app status DOMAIN" >&2
        return 1
    fi
    ensure_unlocked || return 1
    _scrt4_website_check_cmd gcloud "https://cloud.google.com/sdk/docs/install" || return 1
    local slug; slug=$(echo "$domain" | tr 'A-Z.' 'a-z-' | tr -cd 'a-z0-9-')
    local unit="scrt4-app-${slug}.service"
    local target inst zone
    target=$(_scrt4_website_gcp_target) || return 1
    inst=$(printf '%s' "$target" | cut -f1)
    zone=$(printf '%s' "$target" | cut -f2)
    gcloud compute ssh "$inst" --zone "$zone" \
        --command="systemctl status --no-pager ${unit} 2>/dev/null || echo 'unit not found: ${unit}'"
}

scrt4_module_website_app_logs() {
    local domain="${1:-}"
    shift || true
    _scrt4_website_parse_flags "$@"
    local lines="${WEB_TAIL:-100}"
    if [ -z "$domain" ]; then
        echo "Usage: scrt4 website app logs DOMAIN [--tail N]" >&2
        return 1
    fi
    ensure_unlocked || return 1
    _scrt4_website_check_cmd gcloud "https://cloud.google.com/sdk/docs/install" || return 1
    local slug; slug=$(echo "$domain" | tr 'A-Z.' 'a-z-' | tr -cd 'a-z0-9-')
    local unit="scrt4-app-${slug}.service"
    local target inst zone
    target=$(_scrt4_website_gcp_target) || return 1
    inst=$(printf '%s' "$target" | cut -f1)
    zone=$(printf '%s' "$target" | cut -f2)
    gcloud compute ssh "$inst" --zone "$zone" \
        --command="sudo journalctl -u ${unit} --no-pager -n ${lines}"
}
