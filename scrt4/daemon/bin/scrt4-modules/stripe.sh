# shellcheck shell=bash
# scrt4-module: stripe
# version: 1
# api: 1
# tcb: false
# deps: jq curl
# commands: stripe
# requires:
# reveals: STRIPE_SECRET_KEY
#
# Stripe REST API wrapper for the ops people do in the dashboard:
# browse recent activity, check balance, look up a customer, refund a
# charge. STRIPE_SECRET_KEY is fetched via the daemon's reveal flow
# per-call and unset immediately.
#
# Commands:
#   scrt4 stripe balance                        Available + pending balance
#   scrt4 stripe charges [--limit N]            Recent charges
#   scrt4 stripe charge CHARGE_ID               Detail on a single charge
#   scrt4 stripe customers [--limit N]          Recent customers
#   scrt4 stripe customer CUSTOMER_ID           Customer detail
#   scrt4 stripe subs [--status active|all]     Subscriptions
#   scrt4 stripe refund CHARGE_ID [--amount N] [--yes] [--dry-run]
#                                               Refund (real money — --yes gated)
#   scrt4 stripe help
#
# Safety:
#   - All read ops (balance, charges, customer lookup) are free.
#   - Refund requires --yes (interactive confirm in a TTY).
#   - --dry-run prints the curl call without executing.
#   - tcb: false — key is revealed per-call, used, and the variable is
#     unset. The key itself lives in the daemon-held vault, not on disk.

scrt4_module_stripe_register() {
    _register_command stripe scrt4_module_stripe_dispatch
}

scrt4_module_stripe_dispatch() {
    local sub="${1:-help}"
    shift || true
    case "$sub" in
        balance)       scrt4_module_stripe_balance "$@" ;;
        charges)       scrt4_module_stripe_charges "$@" ;;
        charge)        scrt4_module_stripe_charge_detail "$@" ;;
        customers)     scrt4_module_stripe_customers "$@" ;;
        customer)      scrt4_module_stripe_customer_detail "$@" ;;
        subs|subscriptions) scrt4_module_stripe_subs "$@" ;;
        refund)        scrt4_module_stripe_refund "$@" ;;
        help|-h|--help) scrt4_module_stripe_help ;;
        *)
            echo -e "${RED}Unknown stripe subcommand: ${sub}${NC}" >&2
            scrt4_module_stripe_help
            return 1
            ;;
    esac
}

scrt4_module_stripe_help() {
    cat <<'EOF'
scrt4 stripe — Stripe REST API wrapper backed by STRIPE_SECRET_KEY in the vault

USAGE:
    scrt4 stripe balance
    scrt4 stripe charges [--limit N]
    scrt4 stripe charge CHARGE_ID
    scrt4 stripe customers [--limit N]
    scrt4 stripe customer CUSTOMER_ID
    scrt4 stripe subs [--status active|all]
    scrt4 stripe refund CHARGE_ID [--amount CENTS] [--yes] [--dry-run]

SECRETS USED:
    STRIPE_SECRET_KEY   - sk_live_... or sk_test_... (required)

SAFETY:
    Refund is a real-money operation — requires --yes or interactive
    confirm. --dry-run prints the curl call without executing.
EOF
}

# =====================================================================
# Helpers
# =====================================================================

_scrt4_stripe_secret_exists() {
    local name="$1"
    send_request '{"method":"list"}' 2>/dev/null \
        | jq -e --arg n "$name" '.data.names | index($n)' >/dev/null 2>&1
}

_scrt4_stripe_reveal() {
    local name="$1"
    local r1 r2 ch code
    r1=$(send_request "$(jq -nc --arg n "$name" '{method:"reveal",params:{name:$n}}')")
    [ "$(echo "$r1" | jq -r '.success // false')" = "true" ] || { echo "reveal failed: ${name}" >&2; return 1; }
    ch=$(echo "$r1" | jq -r '.data.challenge')
    code=$(echo "$r1" | jq -r '.data.code')
    r2=$(send_request "$(jq -nc --arg c "$ch" --arg k "$code" '{method:"reveal_confirm",params:{challenge:$c,code:$k}}')")
    [ "$(echo "$r2" | jq -r '.success // false')" = "true" ] || { echo "reveal_confirm failed" >&2; return 1; }
    echo "$r2" | jq -r '.data.value'
}

_scrt4_stripe_key() { _scrt4_stripe_reveal STRIPE_SECRET_KEY; }

_scrt4_stripe_parse_flags() {
    STRIPE_YES=0
    STRIPE_DRY_RUN=0
    STRIPE_LIMIT=10
    STRIPE_STATUS="all"
    STRIPE_AMOUNT=""
    STRIPE_POSITIONALS=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --yes|-y)   STRIPE_YES=1; shift ;;
            --dry-run)  STRIPE_DRY_RUN=1; shift ;;
            --limit)    STRIPE_LIMIT="${2:-10}"; shift 2 ;;
            --status)   STRIPE_STATUS="${2:-all}"; shift 2 ;;
            --amount)   STRIPE_AMOUNT="${2:-}"; shift 2 ;;
            --)         shift; while [ $# -gt 0 ]; do STRIPE_POSITIONALS+=("$1"); shift; done ;;
            *)          STRIPE_POSITIONALS+=("$1"); shift ;;
        esac
    done
}

_scrt4_stripe_confirm() {
    local prompt="$1"
    if [ "${STRIPE_YES:-0}" = "1" ]; then return 0; fi
    if [ ! -t 0 ]; then
        echo -e "${YELLOW}${prompt}${NC}" >&2
        echo -e "${YELLOW}Non-interactive — re-run with --yes.${NC}" >&2
        return 1
    fi
    echo -ne "${YELLOW}${prompt}${NC} "
    local ans; read -r ans
    [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]] || return 1
}

_scrt4_stripe_api() {
    local method="$1" path="$2" key="$3"
    shift 3
    curl -sS --max-time 20 -X "$method" \
        -u "${key}:" \
        "https://api.stripe.com${path}" "$@"
}

# Render cents to "$12.34" (assumes USD — Stripe amounts are lowest denom)
_scrt4_stripe_fmt_amount() {
    local cents="$1" currency="${2:-usd}"
    awk -v c="$cents" -v cur="$currency" 'BEGIN { printf "%.2f %s", c/100, toupper(cur) }'
}

# =====================================================================
# Commands
# =====================================================================

scrt4_module_stripe_balance() {
    ensure_unlocked || return 1
    local key resp
    key=$(_scrt4_stripe_key) || return 1
    resp=$(_scrt4_stripe_api GET "/v1/balance" "$key")
    unset key
    if [ "$(echo "$resp" | jq -r '.object // "null"')" != "balance" ]; then
        echo -e "${RED}Stripe API error: $(echo "$resp" | jq -r '.error.message // "unknown"')${NC}" >&2
        return 1
    fi
    echo -e "${CYAN}Stripe balance:${NC}"
    echo "$resp" | jq -r '
        "  Available:",
        (.available[]? | "    \(.amount/100 | tostring) \(.currency | ascii_upcase)"),
        "  Pending:",
        (.pending[]?   | "    \(.amount/100 | tostring) \(.currency | ascii_upcase)")'
}

scrt4_module_stripe_charges() {
    ensure_unlocked || return 1
    _scrt4_stripe_parse_flags "$@"
    local key resp
    key=$(_scrt4_stripe_key) || return 1
    resp=$(_scrt4_stripe_api GET "/v1/charges?limit=${STRIPE_LIMIT}" "$key")
    unset key
    if [ "$(echo "$resp" | jq -r '.object // "null"')" != "list" ]; then
        echo -e "${RED}Stripe API error: $(echo "$resp" | jq -r '.error.message // "unknown"')${NC}" >&2
        return 1
    fi
    echo -e "${CYAN}Recent charges (limit ${STRIPE_LIMIT}):${NC}"
    echo "$resp" | jq -r '.data[]? | "\(.id)\t\(.amount/100)\t\(.currency)\t\(.status)\t\(.description // "")"' \
        | awk -F'\t' '{ printf "  %-28s %8.2f %s  %-10s %s\n", $1, $2, toupper($3), $4, $5 }'
}

scrt4_module_stripe_charge_detail() {
    ensure_unlocked || return 1
    local id="${1:-}"
    if [ -z "$id" ]; then
        echo "Usage: scrt4 stripe charge CHARGE_ID" >&2
        return 1
    fi
    local key resp
    key=$(_scrt4_stripe_key) || return 1
    resp=$(_scrt4_stripe_api GET "/v1/charges/${id}" "$key")
    unset key
    if [ "$(echo "$resp" | jq -r '.id // "null"')" = "null" ]; then
        echo -e "${RED}$(echo "$resp" | jq -r '.error.message // "not found"')${NC}" >&2
        return 1
    fi
    echo -e "${CYAN}Charge ${id}:${NC}"
    echo "$resp" | jq -r '
        "  Amount:     " + (.amount/100|tostring) + " " + (.currency|ascii_upcase),
        "  Status:     " + .status,
        "  Paid:       " + (.paid|tostring),
        "  Refunded:   " + (.refunded|tostring) + "  (" + (.amount_refunded/100|tostring) + ")",
        "  Customer:   " + (.customer // "-"),
        "  Created:    " + (.created | todate),
        "  Description:" + (.description // "-")'
}

scrt4_module_stripe_customers() {
    ensure_unlocked || return 1
    _scrt4_stripe_parse_flags "$@"
    local key resp
    key=$(_scrt4_stripe_key) || return 1
    resp=$(_scrt4_stripe_api GET "/v1/customers?limit=${STRIPE_LIMIT}" "$key")
    unset key
    if [ "$(echo "$resp" | jq -r '.object // "null"')" != "list" ]; then
        echo -e "${RED}Stripe API error: $(echo "$resp" | jq -r '.error.message // "unknown"')${NC}" >&2
        return 1
    fi
    echo -e "${CYAN}Recent customers (limit ${STRIPE_LIMIT}):${NC}"
    echo "$resp" | jq -r '.data[]? | "\(.id)\t\(.email // "-")\t\(.name // "-")"' \
        | awk -F'\t' '{ printf "  %-28s %-30s %s\n", $1, $2, $3 }'
}

scrt4_module_stripe_customer_detail() {
    ensure_unlocked || return 1
    local id="${1:-}"
    if [ -z "$id" ]; then
        echo "Usage: scrt4 stripe customer CUSTOMER_ID" >&2
        return 1
    fi
    local key resp
    key=$(_scrt4_stripe_key) || return 1
    resp=$(_scrt4_stripe_api GET "/v1/customers/${id}" "$key")
    unset key
    if [ "$(echo "$resp" | jq -r '.id // "null"')" = "null" ]; then
        echo -e "${RED}$(echo "$resp" | jq -r '.error.message // "not found"')${NC}" >&2
        return 1
    fi
    echo -e "${CYAN}Customer ${id}:${NC}"
    echo "$resp" | jq -r '
        "  Email:   " + (.email // "-"),
        "  Name:    " + (.name // "-"),
        "  Created: " + (.created | todate),
        "  Balance: " + (.balance/100|tostring),
        "  Currency:" + (.currency // "-"),
        "  Delinquent: " + (.delinquent|tostring)'
}

scrt4_module_stripe_subs() {
    ensure_unlocked || return 1
    _scrt4_stripe_parse_flags "$@"
    local key resp q
    q="limit=${STRIPE_LIMIT}"
    case "$STRIPE_STATUS" in
        all) q="${q}&status=all" ;;
        *)   q="${q}&status=${STRIPE_STATUS}" ;;
    esac
    key=$(_scrt4_stripe_key) || return 1
    resp=$(_scrt4_stripe_api GET "/v1/subscriptions?${q}" "$key")
    unset key
    if [ "$(echo "$resp" | jq -r '.object // "null"')" != "list" ]; then
        echo -e "${RED}Stripe API error: $(echo "$resp" | jq -r '.error.message // "unknown"')${NC}" >&2
        return 1
    fi
    echo -e "${CYAN}Subscriptions (status=${STRIPE_STATUS}):${NC}"
    echo "$resp" | jq -r '.data[]? | "\(.id)\t\(.status)\t\(.customer)\t\(.current_period_end | todate)"' \
        | awk -F'\t' '{ printf "  %-28s %-10s %-28s ends %s\n", $1, $2, $3, $4 }'
}

scrt4_module_stripe_refund() {
    ensure_unlocked || return 1
    local id="${1:-}"
    shift || true
    _scrt4_stripe_parse_flags "$@"
    if [ -z "$id" ]; then
        echo "Usage: scrt4 stripe refund CHARGE_ID [--amount CENTS] [--yes]" >&2
        return 1
    fi
    local amount_desc="full charge"
    [ -n "$STRIPE_AMOUNT" ] && amount_desc="$(_scrt4_stripe_fmt_amount "$STRIPE_AMOUNT")"
    echo -e "${CYAN}Plan:${NC} refund ${amount_desc} from charge ${id}"
    if [ "${STRIPE_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no refund will be created."
        echo "  Stripe POST /v1/refunds  body: charge=${id}${STRIPE_AMOUNT:+&amount=${STRIPE_AMOUNT}}"
        return 0
    fi
    echo -e "${YELLOW}WARNING:${NC} refunds move real money back to the customer."
    _scrt4_stripe_confirm "Proceed? [y/N]" || { echo "Aborted."; return 1; }
    local key resp
    key=$(_scrt4_stripe_key) || return 1
    local body="charge=${id}"
    [ -n "$STRIPE_AMOUNT" ] && body="${body}&amount=${STRIPE_AMOUNT}"
    resp=$(_scrt4_stripe_api POST "/v1/refunds" "$key" -d "$body")
    unset key
    local rid status
    rid=$(echo "$resp" | jq -r '.id // empty')
    status=$(echo "$resp" | jq -r '.status // empty')
    if [ -n "$rid" ]; then
        echo -e "${GREEN}Refund ${rid} created (status: ${status}).${NC}"
    else
        echo -e "${RED}Stripe API error: $(echo "$resp" | jq -r '.error.message // "unknown"')${NC}" >&2
        return 1
    fi
}
