# shellcheck shell=bash
# scrt4-module: domain
# version: 1
# api: 1
# tcb: false
# deps: jq curl
# commands: domain
# requires:
#
# User-facing surface for domain / DNS / deploy / email operations
# across Cloudflare, Vercel, GoDaddy, AWS Route 53, and GCP Cloud DNS.
#
# Commands:
#   scrt4 domain status                        Show which providers have credentials
#   scrt4 domain list                          List domains across all configured providers
#   scrt4 domain dns DOMAIN                    Show DNS records for DOMAIN
#   scrt4 domain dns DOMAIN add TYPE NAME VALUE [--ttl N] [--yes]
#   scrt4 domain dns DOMAIN rm  TYPE NAME [--yes]
#   scrt4 domain deploy DOMAIN --to vercel [--project NAME] [--yes]
#   scrt4 domain buy DOMAIN [--yes]            GoDaddy purchase (prints price, then confirms)
#   scrt4 domain nameservers DOMAIN [NS1 NS2 ...] [--yes]
#   scrt4 domain email DOMAIN                  Show MX/SPF/DKIM/DMARC
#   scrt4 domain email DOMAIN --setup gws [--yes]
#   scrt4 domain transfer DOMAIN [--yes]       Track/initiate registrar transfer
#   scrt4 domain help
#
# Safety:
#   - Read-heavy ops (status, list, dns show, email show, nameservers show)
#     run without confirmation.
#   - Write ops (dns add/rm, deploy, buy, --setup, nameservers set)
#     require --yes OR interactive confirmation with the diff printed.
#   - --dry-run on any write op prints the planned call without executing.
#   - Tokens are fetched via the daemon's reveal flow, never stored in files.
#
# tcb: false — the bash side does not gate anything itself. All reveal
# authorization is daemon-side via `handle_reveal` (step-up WA + session).

scrt4_module_domain_register() {
    _register_command domain scrt4_module_domain_dispatch
}

scrt4_module_domain_dispatch() {
    local sub="${1:-help}"
    shift || true
    case "$sub" in
        status)       scrt4_module_domain_status "$@" ;;
        list|ls)      scrt4_module_domain_list "$@" ;;
        dns)          scrt4_module_domain_dns "$@" ;;
        deploy)       scrt4_module_domain_deploy "$@" ;;
        buy)          scrt4_module_domain_buy "$@" ;;
        nameservers|ns) scrt4_module_domain_nameservers "$@" ;;
        email)        scrt4_module_domain_email "$@" ;;
        transfer)     scrt4_module_domain_transfer "$@" ;;
        help|-h|--help) scrt4_module_domain_help ;;
        *)
            echo -e "${RED}Unknown domain subcommand: ${sub}${NC}" >&2
            scrt4_module_domain_help
            return 1
            ;;
    esac
}

scrt4_module_domain_help() {
    cat <<'EOF'
scrt4 domain — manage domains, DNS, deploys, and email across providers

USAGE:
    scrt4 domain status
    scrt4 domain list
    scrt4 domain dns DOMAIN
    scrt4 domain dns DOMAIN add TYPE NAME VALUE [--ttl N] [--yes] [--dry-run]
    scrt4 domain dns DOMAIN rm  TYPE NAME       [--yes] [--dry-run]
    scrt4 domain deploy DOMAIN --to vercel [--project NAME] [--yes] [--dry-run]
    scrt4 domain buy DOMAIN [--yes] [--dry-run]
    scrt4 domain nameservers DOMAIN [NS1 NS2 ...] [--yes] [--dry-run]
    scrt4 domain email DOMAIN
    scrt4 domain email DOMAIN --setup gws [--yes] [--dry-run]
    scrt4 domain transfer DOMAIN [--yes] [--dry-run]

PROVIDERS:
    Cloudflare  — DNS zones and records       (needs CLOUDFLARE_API_TOKEN)
    Vercel      — projects, domains, deploys  (needs VERCEL_TOKEN)
    GoDaddy     — registration, domain search (needs GODADDY_API_KEY + _SECRET)
    AWS         — Route 53 DNS                (needs aws CLI + AWS_* secrets)
    GCP         — Cloud DNS / Caddy reverse   (needs gcloud CLI + GCP_* secrets)

EXAMPLES:
    scrt4 domain status
    scrt4 domain dns example.com
    scrt4 domain dns example.com add A @ 1.2.3.4 --yes
    scrt4 domain deploy example.com --to vercel --project myapp --yes
    scrt4 domain buy newdomain.io --dry-run

SAFETY:
    Write ops require --yes (or interactive confirm). Use --dry-run to
    preview the API calls that would be made without executing them.
EOF
}

# =====================================================================
# Vault helpers
# =====================================================================

# Check if a secret name exists in the vault without revealing its value.
_scrt4_domain_secret_exists() {
    local name="$1"
    local resp
    resp=$(send_request '{"method":"list"}' 2>/dev/null)
    echo "$resp" | jq -e --arg n "$name" '.data.names | index($n)' >/dev/null 2>&1
}

# Reveal a single secret's value via the daemon's two-phase reveal flow.
# Prints the raw value to stdout on success. Caller should quote
# capture immediately and unset the holding variable when done.
_scrt4_domain_reveal() {
    local name="$1"
    local resp1 challenge code resp2 ok value
    resp1=$(send_request "$(jq -nc --arg n "$name" '{method:"reveal",params:{name:$n}}')")
    ok=$(echo "$resp1" | jq -r '.success // false')
    if [ "$ok" != "true" ]; then
        echo "reveal failed for ${name}: $(echo "$resp1" | jq -r '.error // "unknown"')" >&2
        return 1
    fi
    challenge=$(echo "$resp1" | jq -r '.data.challenge')
    code=$(echo "$resp1" | jq -r '.data.code')
    resp2=$(send_request "$(jq -nc --arg c "$challenge" --arg k "$code" \
        '{method:"reveal_confirm",params:{challenge:$c,code:$k}}')")
    ok=$(echo "$resp2" | jq -r '.success // false')
    if [ "$ok" != "true" ]; then
        echo "reveal_confirm failed for ${name}: $(echo "$resp2" | jq -r '.error // "unknown"')" >&2
        return 1
    fi
    value=$(echo "$resp2" | jq -r '.data.value')
    printf '%s' "$value"
}

# =====================================================================
# Flag parsing
# =====================================================================

# Scan a trailing arg list for --yes, --dry-run, --provider NAME, --project NAME,
# --ttl N, --setup NAME, --to NAME. Sets DOMAIN_YES, DOMAIN_DRY_RUN,
# DOMAIN_PROVIDER, DOMAIN_PROJECT, DOMAIN_TTL, DOMAIN_SETUP, DOMAIN_TO.
# Remaining positionals are left in DOMAIN_POSITIONALS (array).
_scrt4_domain_parse_flags() {
    DOMAIN_YES=0
    DOMAIN_DRY_RUN=0
    DOMAIN_PROVIDER=""
    DOMAIN_PROJECT=""
    DOMAIN_TTL=""
    DOMAIN_SETUP=""
    DOMAIN_TO=""
    DOMAIN_POSITIONALS=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --yes|-y)    DOMAIN_YES=1; shift ;;
            --dry-run)   DOMAIN_DRY_RUN=1; shift ;;
            --provider)  DOMAIN_PROVIDER="${2:-}"; shift 2 ;;
            --project)   DOMAIN_PROJECT="${2:-}"; shift 2 ;;
            --ttl)       DOMAIN_TTL="${2:-}"; shift 2 ;;
            --setup)     DOMAIN_SETUP="${2:-}"; shift 2 ;;
            --to)        DOMAIN_TO="${2:-}"; shift 2 ;;
            --)          shift; while [ $# -gt 0 ]; do DOMAIN_POSITIONALS+=("$1"); shift; done ;;
            *)           DOMAIN_POSITIONALS+=("$1"); shift ;;
        esac
    done
}

# Confirm a write operation. Returns 0 if approved, 1 if denied.
_scrt4_domain_confirm() {
    local prompt="$1"
    if [ "${DOMAIN_YES:-0}" = "1" ]; then
        return 0
    fi
    # Non-interactive without --yes is treated as denial; print the diff
    # and tell the user to re-run with --yes.
    if [ ! -t 0 ]; then
        echo -e "${YELLOW}${prompt}${NC}" >&2
        echo -e "${YELLOW}Non-interactive session — re-run with --yes to execute.${NC}" >&2
        return 1
    fi
    echo -ne "${YELLOW}${prompt}${NC} "
    local ans
    read -r ans
    [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]] || return 1
    return 0
}

# =====================================================================
# Provider: Cloudflare
# =====================================================================

_scrt4_domain_cf_token() {
    _scrt4_domain_reveal CLOUDFLARE_API_TOKEN
}

_scrt4_domain_cf_api() {
    local method="$1" path="$2" token="$3"
    shift 3
    # Remaining args are extra curl options (e.g. -d BODY).
    curl -sS --max-time 20 \
        -X "$method" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        "https://api.cloudflare.com/client/v4${path}" "$@"
}

_scrt4_domain_cf_zone_id() {
    local domain="$1" token="$2"
    _scrt4_domain_cf_api GET "/zones?name=${domain}" "$token" \
        | jq -r '.result[0].id // empty'
}

_scrt4_domain_cf_list_zones() {
    local token="$1"
    _scrt4_domain_cf_api GET "/zones?per_page=100" "$token" \
        | jq -r '.result[]? | "\(.name)\t\(.status)\t\(.id)"'
}

_scrt4_domain_cf_list_records() {
    local zone_id="$1" token="$2"
    _scrt4_domain_cf_api GET "/zones/${zone_id}/dns_records?per_page=200" "$token" \
        | jq -r '.result[]? | "\(.type)\t\(.name)\t\(.content)\t\(.ttl)\t\(.proxied)"'
}

_scrt4_domain_cf_add_record() {
    local zone_id="$1" token="$2" type="$3" name="$4" content="$5" ttl="${6:-1}"
    local body
    body=$(jq -nc --arg t "$type" --arg n "$name" --arg c "$content" \
        --argjson ttl "$ttl" '{type:$t,name:$n,content:$c,ttl:$ttl}')
    _scrt4_domain_cf_api POST "/zones/${zone_id}/dns_records" "$token" -d "$body"
}

_scrt4_domain_cf_find_record_id() {
    local zone_id="$1" token="$2" type="$3" name="$4"
    _scrt4_domain_cf_api GET \
        "/zones/${zone_id}/dns_records?type=${type}&name=${name}" "$token" \
        | jq -r '.result[0].id // empty'
}

_scrt4_domain_cf_delete_record() {
    local zone_id="$1" token="$2" record_id="$3"
    _scrt4_domain_cf_api DELETE "/zones/${zone_id}/dns_records/${record_id}" "$token"
}

# =====================================================================
# Provider: Vercel
# =====================================================================

_scrt4_domain_vercel_token() {
    _scrt4_domain_reveal VERCEL_TOKEN
}

_scrt4_domain_vercel_api() {
    local method="$1" path="$2" token="$3"
    shift 3
    curl -sS --max-time 20 -X "$method" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        "https://api.vercel.com${path}" "$@"
}

_scrt4_domain_vercel_list_projects() {
    local token="$1"
    _scrt4_domain_vercel_api GET "/v9/projects?limit=100" "$token" \
        | jq -r '.projects[]? | "\(.name)\t\(.framework // "none")\t\(.updatedAt)"'
}

_scrt4_domain_vercel_list_domains() {
    local token="$1"
    _scrt4_domain_vercel_api GET "/v5/domains?limit=100" "$token" \
        | jq -r '.domains[]? | "\(.name)\t\(if .verified then "verified" else "unverified" end)"'
}

_scrt4_domain_vercel_attach_domain() {
    local token="$1" project="$2" domain="$3"
    local body
    body=$(jq -nc --arg n "$domain" '{name:$n}')
    _scrt4_domain_vercel_api POST "/v10/projects/${project}/domains" "$token" -d "$body"
}

# =====================================================================
# Provider: GoDaddy
# =====================================================================

_scrt4_domain_godaddy_auth() {
    # Returns "Authorization: sso-key KEY:SECRET" via env.
    local key secret
    key=$(_scrt4_domain_reveal GODADDY_API_KEY) || return 1
    secret=$(_scrt4_domain_reveal GODADDY_API_SECRET) || return 1
    printf 'sso-key %s:%s' "$key" "$secret"
}

_scrt4_domain_godaddy_api() {
    local method="$1" path="$2" auth="$3"
    shift 3
    curl -sS --max-time 20 -X "$method" \
        -H "Authorization: ${auth}" \
        -H "Content-Type: application/json" \
        "https://api.godaddy.com${path}" "$@"
}

_scrt4_domain_godaddy_list_domains() {
    local auth="$1"
    _scrt4_domain_godaddy_api GET "/v1/domains?statuses=ACTIVE&limit=500" "$auth" \
        | jq -r '.[]? | "\(.domain)\t\(.status)\t\(.expires)"'
}

_scrt4_domain_godaddy_available() {
    local auth="$1" domain="$2"
    _scrt4_domain_godaddy_api GET "/v1/domains/available?domain=${domain}" "$auth"
}

_scrt4_domain_godaddy_get_nameservers() {
    local auth="$1" domain="$2"
    _scrt4_domain_godaddy_api GET "/v1/domains/${domain}" "$auth" \
        | jq -r '.nameServers[]?'
}

_scrt4_domain_godaddy_set_nameservers() {
    local auth="$1" domain="$2"
    shift 2
    # Remaining args are nameserver hostnames.
    local body
    body=$(printf '%s\n' "$@" | jq -R . | jq -sc '{nameServers: .}')
    _scrt4_domain_godaddy_api PUT "/v1/domains/${domain}" "$auth" -d "$body"
}

# =====================================================================
# Provider: AWS (Route 53) via the aws CLI
# =====================================================================
#
# Route 53 is authenticated via AWS Sigv4 which is impractical to sign
# in pure bash. We shell out to the `aws` CLI, setting creds via env
# vars injected from vault for the call only.

_scrt4_domain_aws_available() {
    command -v aws >/dev/null 2>&1
}

_scrt4_domain_aws_env_export() {
    # Echoes the env var KEY=VALUE lines for aws CLI auth. Caller
    # should eval inside a subshell to keep the creds scoped.
    local k s r
    k=$(_scrt4_domain_reveal AWS_ACCESS_KEY_ID) || return 1
    s=$(_scrt4_domain_reveal AWS_SECRET_ACCESS_KEY) || return 1
    r=$(_scrt4_domain_secret_exists AWS_REGION && _scrt4_domain_reveal AWS_REGION || echo "us-east-1")
    printf 'AWS_ACCESS_KEY_ID=%q\nAWS_SECRET_ACCESS_KEY=%q\nAWS_REGION=%q\n' "$k" "$s" "$r"
}

_scrt4_domain_aws_list_zones() {
    local env_vars
    env_vars=$(_scrt4_domain_aws_env_export) || return 1
    (
        eval "export ${env_vars//$'\n'/ }"
        aws route53 list-hosted-zones --output json 2>/dev/null \
            | jq -r '.HostedZones[]? | "\(.Name)\t\(.Id)\t\(.ResourceRecordSetCount)"'
    )
}

_scrt4_domain_aws_list_records() {
    local domain="$1"
    local env_vars zone_id
    env_vars=$(_scrt4_domain_aws_env_export) || return 1
    (
        eval "export ${env_vars//$'\n'/ }"
        zone_id=$(aws route53 list-hosted-zones --output json 2>/dev/null \
            | jq -r --arg d "${domain}." '.HostedZones[] | select(.Name==$d) | .Id' \
            | head -1)
        [ -n "$zone_id" ] || { echo "No Route 53 zone for ${domain}"; return 1; }
        aws route53 list-resource-record-sets --hosted-zone-id "$zone_id" --output json 2>/dev/null \
            | jq -r '.ResourceRecordSets[]? | "\(.Type)\t\(.Name)\t\((.ResourceRecords // [{}])[0].Value // "-")\t\(.TTL // "auto")"'
    )
}

# =====================================================================
# Provider: GCP (Cloud DNS + compute info) via the gcloud CLI
# =====================================================================

_scrt4_domain_gcp_available() {
    command -v gcloud >/dev/null 2>&1
}

_scrt4_domain_gcp_list_zones() {
    _scrt4_domain_gcp_available || return 1
    gcloud dns managed-zones list --format='value(name,dnsName,visibility)' 2>/dev/null
}

_scrt4_domain_gcp_list_records() {
    local domain="$1"
    _scrt4_domain_gcp_available || return 1
    local zone
    zone=$(gcloud dns managed-zones list --format=json 2>/dev/null \
        | jq -r --arg d "${domain}." '.[] | select(.dnsName==$d) | .name' \
        | head -1)
    [ -n "$zone" ] || { echo "No Cloud DNS zone for ${domain}"; return 1; }
    gcloud dns record-sets list --zone="$zone" \
        --format='value(type,name,rrdatas[0],ttl)' 2>/dev/null
}

# =====================================================================
# Command: status
# =====================================================================

scrt4_module_domain_status() {
    ensure_unlocked || return 1
    echo -e "${CYAN}Domain module — provider status:${NC}"
    _check() {
        local label="$1"; shift
        local missing=""
        for n in "$@"; do
            _scrt4_domain_secret_exists "$n" || missing="${missing}${n} "
        done
        if [ -z "$missing" ]; then
            echo -e "  ${GREEN}[✓]${NC} ${label}"
        else
            echo -e "  ${YELLOW}[ ]${NC} ${label}    missing: ${missing}"
        fi
    }
    _check "Cloudflare    " CLOUDFLARE_API_TOKEN
    _check "Vercel        " VERCEL_TOKEN
    _check "GoDaddy       " GODADDY_API_KEY GODADDY_API_SECRET
    if _scrt4_domain_aws_available; then
        _check "AWS (Route 53)" AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
    else
        echo -e "  ${YELLOW}[ ]${NC} AWS (Route 53)    aws CLI not installed"
    fi
    if _scrt4_domain_gcp_available; then
        echo -e "  ${GREEN}[✓]${NC} GCP (gcloud)      gcloud CLI present"
    else
        echo -e "  ${YELLOW}[ ]${NC} GCP (gcloud)      gcloud CLI not installed"
    fi
    echo ""
    echo -e "${CYAN}Critical-tag recommended for:${NC}"
    echo "  CLOUDFLARE_API_TOKEN  VERCEL_TOKEN  GODADDY_API_SECRET  AWS_SECRET_ACCESS_KEY"
    echo "  (scrt4 critical add NAME)"
}

# =====================================================================
# Command: list
# =====================================================================

scrt4_module_domain_list() {
    ensure_unlocked || return 1
    local any=0

    if _scrt4_domain_secret_exists CLOUDFLARE_API_TOKEN; then
        echo -e "${CYAN}Cloudflare zones:${NC}"
        local cf_tok
        cf_tok=$(_scrt4_domain_cf_token) || { echo "  (reveal failed)"; cf_tok=""; }
        if [ -n "$cf_tok" ]; then
            local zones
            zones=$(_scrt4_domain_cf_list_zones "$cf_tok")
            if [ -n "$zones" ]; then
                printf '%s\n' "$zones" | awk -F'\t' '{ printf "  %-30s %s\n", $1, $2 }'
                any=1
            else
                echo "  (none)"
            fi
        fi
        unset cf_tok
        echo ""
    fi

    if _scrt4_domain_secret_exists VERCEL_TOKEN; then
        echo -e "${CYAN}Vercel domains:${NC}"
        local v_tok
        v_tok=$(_scrt4_domain_vercel_token) || { echo "  (reveal failed)"; v_tok=""; }
        if [ -n "$v_tok" ]; then
            local domains
            domains=$(_scrt4_domain_vercel_list_domains "$v_tok")
            if [ -n "$domains" ]; then
                printf '%s\n' "$domains" | awk -F'\t' '{ printf "  %-30s %s\n", $1, $2 }'
                any=1
            else
                echo "  (none)"
            fi
        fi
        unset v_tok
        echo ""
    fi

    if _scrt4_domain_secret_exists GODADDY_API_KEY \
        && _scrt4_domain_secret_exists GODADDY_API_SECRET; then
        echo -e "${CYAN}GoDaddy domains:${NC}"
        local gd_auth
        gd_auth=$(_scrt4_domain_godaddy_auth) || { echo "  (reveal failed)"; gd_auth=""; }
        if [ -n "$gd_auth" ]; then
            local domains
            domains=$(_scrt4_domain_godaddy_list_domains "$gd_auth")
            if [ -n "$domains" ]; then
                printf '%s\n' "$domains" | awk -F'\t' '{ printf "  %-30s %-10s expires %s\n", $1, $2, $3 }'
                any=1
            else
                echo "  (none)"
            fi
        fi
        unset gd_auth
        echo ""
    fi

    if _scrt4_domain_aws_available && _scrt4_domain_secret_exists AWS_ACCESS_KEY_ID; then
        echo -e "${CYAN}AWS Route 53 zones:${NC}"
        local zones
        zones=$(_scrt4_domain_aws_list_zones 2>/dev/null)
        if [ -n "$zones" ]; then
            printf '%s\n' "$zones" | awk -F'\t' '{ printf "  %-30s %s\n", $1, $3 " records" }'
            any=1
        else
            echo "  (none or aws list-hosted-zones failed)"
        fi
        echo ""
    fi

    if _scrt4_domain_gcp_available; then
        echo -e "${CYAN}GCP Cloud DNS zones:${NC}"
        local zones
        zones=$(_scrt4_domain_gcp_list_zones 2>/dev/null)
        if [ -n "$zones" ]; then
            printf '%s\n' "$zones" | awk '{ printf "  %-30s %s\n", $2, $3 }'
            any=1
        else
            echo "  (no zones — or not authenticated to any project)"
        fi
        echo ""
    fi

    if [ "$any" = "0" ]; then
        echo -e "${YELLOW}No provider credentials found.${NC}"
        echo -e "  Run: ${BOLD}scrt4 domain status${NC} to see what's missing."
    fi
}

# =====================================================================
# Command: dns
# =====================================================================

scrt4_module_domain_dns() {
    ensure_unlocked || return 1
    local domain="${1:-}"
    shift || true
    if [ -z "$domain" ]; then
        echo "Usage: scrt4 domain dns DOMAIN [show | add TYPE NAME VALUE | rm TYPE NAME]" >&2
        return 1
    fi
    local action="${1:-show}"
    if [[ "$action" == -* ]]; then
        action="show"
    else
        shift || true
    fi
    _scrt4_domain_parse_flags "$@"
    case "$action" in
        show)                 _scrt4_domain_dns_show "$domain" ;;
        add)                  _scrt4_domain_dns_add  "$domain" ;;
        rm|remove|del|delete) _scrt4_domain_dns_rm   "$domain" ;;
        *)
            echo -e "${RED}Unknown dns action: ${action}${NC}" >&2
            return 1
            ;;
    esac
}

_scrt4_domain_dns_show() {
    local domain="$1"
    local printed=0

    if _scrt4_domain_secret_exists CLOUDFLARE_API_TOKEN; then
        local tok zone recs
        tok=$(_scrt4_domain_cf_token) || tok=""
        if [ -n "$tok" ]; then
            zone=$(_scrt4_domain_cf_zone_id "$domain" "$tok")
            if [ -n "$zone" ]; then
                echo -e "${CYAN}Cloudflare DNS for ${domain}:${NC}"
                recs=$(_scrt4_domain_cf_list_records "$zone" "$tok")
                if [ -n "$recs" ]; then
                    printf '%s\n' "$recs" | awk -F'\t' '{ printf "  %-6s %-30s %-30s  TTL=%s proxied=%s\n", $1, $2, $3, $4, $5 }'
                else
                    echo "  (no records)"
                fi
                printed=1
            fi
        fi
        unset tok
    fi

    if _scrt4_domain_aws_available \
        && _scrt4_domain_secret_exists AWS_ACCESS_KEY_ID \
        && [ "$printed" = "0" ]; then
        local aws_out
        aws_out=$(_scrt4_domain_aws_list_records "$domain" 2>/dev/null)
        if [ -n "$aws_out" ]; then
            echo -e "${CYAN}AWS Route 53 DNS for ${domain}:${NC}"
            printf '%s\n' "$aws_out" | awk -F'\t' '{ printf "  %-6s %-30s %-30s  TTL=%s\n", $1, $2, $3, $4 }'
            printed=1
        fi
    fi

    if _scrt4_domain_gcp_available && [ "$printed" = "0" ]; then
        local gcp_out
        gcp_out=$(_scrt4_domain_gcp_list_records "$domain" 2>/dev/null)
        if [ -n "$gcp_out" ]; then
            echo -e "${CYAN}GCP Cloud DNS for ${domain}:${NC}"
            printf '%s\n' "$gcp_out" | awk '{ printf "  %-6s %-30s %-30s  TTL=%s\n", $1, $2, $3, $4 }'
            printed=1
        fi
    fi

    if [ "$printed" = "0" ]; then
        echo -e "${YELLOW}No zone found for ${domain} in any configured provider.${NC}"
        return 1
    fi
}

_scrt4_domain_dns_add() {
    local domain="$1"
    local type="${DOMAIN_POSITIONALS[0]:-}"
    local name="${DOMAIN_POSITIONALS[1]:-}"
    local value="${DOMAIN_POSITIONALS[2]:-}"
    if [ -z "$type" ] || [ -z "$name" ] || [ -z "$value" ]; then
        echo "Usage: scrt4 domain dns DOMAIN add TYPE NAME VALUE [--ttl N] [--yes] [--dry-run]" >&2
        return 1
    fi

    # Resolve name -- Cloudflare treats '@' as the root.
    local full_name="$name"
    if [ "$name" = "@" ]; then
        full_name="$domain"
    elif [[ "$name" != *.${domain} && "$name" != "$domain" ]]; then
        full_name="${name}.${domain}"
    fi
    local ttl="${DOMAIN_TTL:-1}"

    echo -e "${CYAN}Plan:${NC} add ${type} record ${full_name} → ${value} (TTL=${ttl})"
    if [ "${DOMAIN_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no API call will be made."
        echo "  Cloudflare POST /zones/ZONE_ID/dns_records"
        echo "  body: $(jq -nc --arg t "$type" --arg n "$full_name" --arg c "$value" --argjson ttl "$ttl" \
            '{type:$t,name:$n,content:$c,ttl:$ttl}')"
        return 0
    fi

    _scrt4_domain_confirm "Proceed? [y/N]" || { echo "Aborted."; return 1; }

    local tok zone resp ok
    tok=$(_scrt4_domain_cf_token) || { echo "No CLOUDFLARE_API_TOKEN."; return 1; }
    zone=$(_scrt4_domain_cf_zone_id "$domain" "$tok")
    if [ -z "$zone" ]; then
        unset tok
        echo -e "${RED}No Cloudflare zone for ${domain}.${NC}" >&2
        return 1
    fi
    resp=$(_scrt4_domain_cf_add_record "$zone" "$tok" "$type" "$full_name" "$value" "$ttl")
    unset tok
    ok=$(echo "$resp" | jq -r '.success')
    if [ "$ok" = "true" ]; then
        echo -e "${GREEN}Record added.${NC}"
    else
        echo -e "${RED}Cloudflare API error: $(echo "$resp" | jq -c '.errors')${NC}" >&2
        return 1
    fi
}

_scrt4_domain_dns_rm() {
    local domain="$1"
    local type="${DOMAIN_POSITIONALS[0]:-}"
    local name="${DOMAIN_POSITIONALS[1]:-}"
    if [ -z "$type" ] || [ -z "$name" ]; then
        echo "Usage: scrt4 domain dns DOMAIN rm TYPE NAME [--yes] [--dry-run]" >&2
        return 1
    fi
    local full_name="$name"
    if [ "$name" = "@" ]; then
        full_name="$domain"
    elif [[ "$name" != *.${domain} && "$name" != "$domain" ]]; then
        full_name="${name}.${domain}"
    fi

    echo -e "${CYAN}Plan:${NC} remove ${type} record ${full_name}"
    if [ "${DOMAIN_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no API call will be made."
        echo "  Cloudflare DELETE /zones/ZONE_ID/dns_records/RECORD_ID"
        return 0
    fi

    _scrt4_domain_confirm "Proceed? [y/N]" || { echo "Aborted."; return 1; }

    local tok zone rid resp ok
    tok=$(_scrt4_domain_cf_token) || { echo "No CLOUDFLARE_API_TOKEN."; return 1; }
    zone=$(_scrt4_domain_cf_zone_id "$domain" "$tok")
    if [ -z "$zone" ]; then
        unset tok
        echo -e "${RED}No Cloudflare zone for ${domain}.${NC}" >&2
        return 1
    fi
    rid=$(_scrt4_domain_cf_find_record_id "$zone" "$tok" "$type" "$full_name")
    if [ -z "$rid" ]; then
        unset tok
        echo -e "${YELLOW}No matching record found.${NC}"
        return 1
    fi
    resp=$(_scrt4_domain_cf_delete_record "$zone" "$tok" "$rid")
    unset tok
    ok=$(echo "$resp" | jq -r '.success')
    if [ "$ok" = "true" ]; then
        echo -e "${GREEN}Record removed.${NC}"
    else
        echo -e "${RED}Cloudflare API error: $(echo "$resp" | jq -c '.errors')${NC}" >&2
        return 1
    fi
}

# =====================================================================
# Command: deploy
# =====================================================================

scrt4_module_domain_deploy() {
    ensure_unlocked || return 1
    local domain="${1:-}"
    shift || true
    if [ -z "$domain" ]; then
        echo "Usage: scrt4 domain deploy DOMAIN --to vercel [--project NAME] [--yes] [--dry-run]" >&2
        return 1
    fi
    _scrt4_domain_parse_flags "$@"
    local target="${DOMAIN_TO:-vercel}"
    case "$target" in
        vercel)
            _scrt4_domain_deploy_vercel "$domain"
            ;;
        gcp|caddy)
            echo -e "${YELLOW}GCP/Caddy deploy wiring is manual today.${NC}"
            echo "  See docs/install-llmsecrets.md for the install.llmsecrets.com pattern."
            return 1
            ;;
        *)
            echo -e "${RED}Unknown --to target: ${target}${NC}" >&2
            echo "  Supported: vercel, gcp, caddy" >&2
            return 1
            ;;
    esac
}

_scrt4_domain_deploy_vercel() {
    local domain="$1"
    local project="${DOMAIN_PROJECT:-}"
    if [ -z "$project" ]; then
        echo "Usage: scrt4 domain deploy DOMAIN --to vercel --project NAME" >&2
        return 1
    fi
    echo -e "${CYAN}Plan:${NC} attach ${domain} to Vercel project '${project}'"
    if [ "${DOMAIN_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no API call will be made."
        echo "  Vercel POST /v10/projects/${project}/domains"
        echo "  body: $(jq -nc --arg n "$domain" '{name:$n}')"
        return 0
    fi
    _scrt4_domain_confirm "Proceed? [y/N]" || { echo "Aborted."; return 1; }

    local tok resp ok
    tok=$(_scrt4_domain_vercel_token) || { echo "No VERCEL_TOKEN."; return 1; }
    resp=$(_scrt4_domain_vercel_attach_domain "$tok" "$project" "$domain")
    unset tok
    ok=$(echo "$resp" | jq -r 'if .error then "false" else "true" end')
    if [ "$ok" = "true" ]; then
        echo -e "${GREEN}Domain attached to Vercel project.${NC}"
    else
        echo -e "${RED}Vercel API error: $(echo "$resp" | jq -c '.error')${NC}" >&2
        return 1
    fi
}

# =====================================================================
# Command: buy
# =====================================================================

scrt4_module_domain_buy() {
    ensure_unlocked || return 1
    local domain="${1:-}"
    shift || true
    if [ -z "$domain" ]; then
        echo "Usage: scrt4 domain buy DOMAIN [--yes] [--dry-run]" >&2
        return 1
    fi
    _scrt4_domain_parse_flags "$@"

    if ! _scrt4_domain_secret_exists GODADDY_API_KEY; then
        echo -e "${RED}GODADDY_API_KEY not in vault.${NC}" >&2
        return 1
    fi

    echo -e "${CYAN}Checking availability of ${domain}...${NC}"
    local auth result
    auth=$(_scrt4_domain_godaddy_auth) || return 1
    result=$(_scrt4_domain_godaddy_available "$auth" "$domain")
    local available price currency
    available=$(echo "$result" | jq -r '.available // false')
    price=$(echo "$result" | jq -r '.price // "unknown"')
    currency=$(echo "$result" | jq -r '.currency // "USD"')

    if [ "$available" != "true" ]; then
        unset auth
        echo -e "${YELLOW}${domain} is NOT available for purchase.${NC}"
        return 1
    fi
    # GoDaddy returns price in micro-units (multiply by 10^-6).
    local price_display
    if [[ "$price" =~ ^[0-9]+$ ]]; then
        price_display=$(awk -v p="$price" 'BEGIN{printf "%.2f", p/1000000}')
    else
        price_display="$price"
    fi
    echo -e "${GREEN}Available.${NC} Price: ${price_display} ${currency}"

    if [ "${DOMAIN_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} not purchasing."
        unset auth
        return 0
    fi

    echo -e "${YELLOW}WARNING:${NC} purchasing a domain is a real-money operation."
    _scrt4_domain_confirm "Buy ${domain} for ${price_display} ${currency}? [y/N]" \
        || { unset auth; echo "Aborted."; return 1; }

    # The actual purchase endpoint (POST /v1/domains/purchase) needs
    # full contact info (registrant, admin, tech, billing). We stop
    # here and tell the user — we will not invent fake contact info.
    unset auth
    echo -e "${YELLOW}GoDaddy purchase requires full contact info (registrant, admin, tech, billing).${NC}"
    echo "  scrt4 does not prompt for PII today. Finish the purchase at:"
    echo -e "  ${BOLD}https://www.godaddy.com/domainsearch/find?domainToCheck=${domain}${NC}"
    echo "  After purchase, run: scrt4 domain nameservers ${domain} --yes  to delegate to Cloudflare"
    return 0
}

# =====================================================================
# Command: nameservers
# =====================================================================

scrt4_module_domain_nameservers() {
    ensure_unlocked || return 1
    local domain="${1:-}"
    shift || true
    if [ -z "$domain" ]; then
        echo "Usage: scrt4 domain nameservers DOMAIN [NS1 NS2 ...] [--yes] [--dry-run]" >&2
        return 1
    fi
    _scrt4_domain_parse_flags "$@"

    if ! _scrt4_domain_secret_exists GODADDY_API_KEY; then
        echo -e "${RED}GODADDY_API_KEY not in vault (nameserver management needs GoDaddy).${NC}" >&2
        return 1
    fi
    local auth
    auth=$(_scrt4_domain_godaddy_auth) || return 1

    if [ "${#DOMAIN_POSITIONALS[@]}" = "0" ]; then
        # Show current NS
        echo -e "${CYAN}Current nameservers for ${domain}:${NC}"
        local ns
        ns=$(_scrt4_domain_godaddy_get_nameservers "$auth" "$domain")
        unset auth
        if [ -n "$ns" ]; then
            printf '%s\n' "$ns" | sed 's/^/  /'
        else
            echo "  (none or error)"
        fi
        return 0
    fi

    echo -e "${CYAN}Plan:${NC} set nameservers for ${domain} to:"
    for ns in "${DOMAIN_POSITIONALS[@]}"; do echo "  $ns"; done

    if [ "${DOMAIN_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no API call will be made."
        echo "  GoDaddy PUT /v1/domains/${domain}"
        unset auth
        return 0
    fi

    _scrt4_domain_confirm "Proceed? [y/N]" || { unset auth; echo "Aborted."; return 1; }

    local resp
    resp=$(_scrt4_domain_godaddy_set_nameservers "$auth" "$domain" "${DOMAIN_POSITIONALS[@]}")
    unset auth
    # GoDaddy returns 200 with empty body on success, or a JSON error.
    if [ -z "$resp" ] || echo "$resp" | jq -e '.code == null' >/dev/null 2>&1; then
        echo -e "${GREEN}Nameservers updated.${NC}"
    else
        echo -e "${RED}GoDaddy API error: $(echo "$resp" | jq -c '.')${NC}" >&2
        return 1
    fi
}

# =====================================================================
# Command: email
# =====================================================================

scrt4_module_domain_email() {
    ensure_unlocked || return 1
    local domain="${1:-}"
    shift || true
    if [ -z "$domain" ]; then
        echo "Usage: scrt4 domain email DOMAIN [--setup gws] [--yes] [--dry-run]" >&2
        return 1
    fi
    _scrt4_domain_parse_flags "$@"

    if [ -z "$DOMAIN_SETUP" ]; then
        _scrt4_domain_email_show "$domain"
        return
    fi

    case "$DOMAIN_SETUP" in
        gws|google|workspace)
            _scrt4_domain_email_setup_gws "$domain"
            ;;
        *)
            echo -e "${RED}Unknown --setup target: ${DOMAIN_SETUP}${NC}" >&2
            return 1
            ;;
    esac
}

_scrt4_domain_email_show() {
    local domain="$1"
    echo -e "${CYAN}Email DNS for ${domain}:${NC}"
    # Prefer dig — fall back to host. Note: this reads public DNS, no auth.
    if command -v dig >/dev/null 2>&1; then
        echo "  MX:"
        dig +short MX "$domain" 2>/dev/null | sed 's/^/    /'
        echo "  SPF (TXT @):"
        dig +short TXT "$domain" 2>/dev/null | grep -i spf1 | sed 's/^/    /'
        echo "  DMARC (TXT _dmarc):"
        dig +short TXT "_dmarc.${domain}" 2>/dev/null | sed 's/^/    /'
    elif command -v host >/dev/null 2>&1; then
        echo "  MX:"
        host -t MX "$domain" 2>/dev/null | sed 's/^/    /'
        echo "  SPF / DMARC: install 'dig' for full check"
    else
        echo "  (install 'dig' or 'host' to see records)"
    fi
}

_scrt4_domain_email_setup_gws() {
    local domain="$1"
    if ! _scrt4_domain_secret_exists CLOUDFLARE_API_TOKEN; then
        echo -e "${RED}CLOUDFLARE_API_TOKEN not in vault (GWS setup writes Cloudflare records).${NC}" >&2
        return 1
    fi
    echo -e "${CYAN}Plan:${NC} set up Google Workspace email for ${domain}."
    echo "  Records that will be added in Cloudflare:"
    echo "    MX  @   1  SMTP.GOOGLE.COM"
    echo "    TXT @      \"v=spf1 include:_spf.google.com ~all\""
    echo "    TXT _dmarc \"v=DMARC1; p=none; rua=mailto:postmaster@${domain}\""
    echo "  (DKIM key is generated in Google Admin and added separately.)"
    if [ "${DOMAIN_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no records will be written."
        return 0
    fi
    _scrt4_domain_confirm "Proceed? [y/N]" || { echo "Aborted."; return 1; }

    local tok zone
    tok=$(_scrt4_domain_cf_token) || return 1
    zone=$(_scrt4_domain_cf_zone_id "$domain" "$tok")
    if [ -z "$zone" ]; then
        unset tok
        echo -e "${RED}No Cloudflare zone for ${domain}.${NC}" >&2
        return 1
    fi

    # MX — Cloudflare accepts MX via dns_records with priority field.
    _scrt4_domain_cf_api POST "/zones/${zone}/dns_records" "$tok" -d \
        '{"type":"MX","name":"@","content":"SMTP.GOOGLE.COM","ttl":1,"priority":1}' \
        | jq -c '{success,errors:.errors}' | sed 's/^/  MX:    /'

    _scrt4_domain_cf_api POST "/zones/${zone}/dns_records" "$tok" -d \
        "$(jq -nc --arg c "v=spf1 include:_spf.google.com ~all" \
            '{type:"TXT",name:"@",content:$c,ttl:1}')" \
        | jq -c '{success,errors:.errors}' | sed 's/^/  SPF:   /'

    _scrt4_domain_cf_api POST "/zones/${zone}/dns_records" "$tok" -d \
        "$(jq -nc --arg d "$domain" \
            --arg c "v=DMARC1; p=none; rua=mailto:postmaster@${domain}" \
            '{type:"TXT",name:"_dmarc",content:$c,ttl:1}')" \
        | jq -c '{success,errors:.errors}' | sed 's/^/  DMARC: /'

    unset tok
    echo -e "${GREEN}Records written. Generate DKIM key in Google Admin and add it manually.${NC}"
}

# =====================================================================
# Command: transfer (stub — prints guidance)
# =====================================================================

scrt4_module_domain_transfer() {
    ensure_unlocked || return 1
    local domain="${1:-}"
    shift || true
    _scrt4_domain_parse_flags "$@"
    if [ -z "$domain" ]; then
        echo "Usage: scrt4 domain transfer DOMAIN" >&2
        return 1
    fi
    echo -e "${CYAN}Registrar transfers are a multi-step process:${NC}"
    echo "  1. Unlock the domain at the losing registrar."
    echo "  2. Get the EPP/auth code."
    echo "  3. Start transfer at the gaining registrar (pay any fee)."
    echo "  4. Confirm the transfer email at the admin contact address."
    echo ""
    echo "scrt4 does not automate step 4 (email confirmation) today."
    echo "For GoDaddy transfer status, check:"
    echo -e "  ${BOLD}https://dcc.godaddy.com/domains/transfers/incoming${NC}"
}
