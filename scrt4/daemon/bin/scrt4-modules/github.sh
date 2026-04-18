# shellcheck shell=bash
# scrt4-module: github
# version: 1
# api: 1
# tcb: false
# deps: jq curl
# commands: github, gh-list, gh-issue, gh-pr
# requires:
# reveals: GITHUB_PAT GITHUB_USERNAME
#
# Thin wrapper around the GitHub REST API for the ops people do most
# from the terminal: list repos/issues/PRs, create issues, comment,
# close. Uses GITHUB_PAT from the vault — the token is fetched once per
# command via the daemon's reveal flow and unset as soon as the call
# completes.
#
# Commands:
#   scrt4 github repos [--user NAME]          List repos (default: authed user)
#   scrt4 github issues OWNER/REPO [--state open|closed|all]
#   scrt4 github issue view OWNER/REPO NUMBER
#   scrt4 github issue create OWNER/REPO "title" "body" [--yes] [--dry-run]
#   scrt4 github issue close OWNER/REPO NUMBER [--yes] [--dry-run]
#   scrt4 github issue comment OWNER/REPO NUMBER "body" [--yes] [--dry-run]
#   scrt4 github prs OWNER/REPO [--state open|closed|all]
#   scrt4 github pr view OWNER/REPO NUMBER
#   scrt4 github pr merge OWNER/REPO NUMBER [--yes] [--dry-run]
#   scrt4 github whoami
#   scrt4 github help
#
# Safety:
#   - Read ops (list, view, whoami) run without confirmation.
#   - Write ops (create, close, comment, merge) require --yes or
#     interactive confirm. --dry-run previews the HTTP call without
#     executing.
#   - tcb: false — authorization is daemon-side via handle_reveal.

scrt4_module_github_register() {
    _register_command github   scrt4_module_github_dispatch
    _register_command gh-list  scrt4_module_github_repos
    _register_command gh-issue scrt4_module_github_issue_cmd
    _register_command gh-pr    scrt4_module_github_pr_cmd
}

scrt4_module_github_dispatch() {
    local sub="${1:-help}"
    shift || true
    case "$sub" in
        repos|list)    scrt4_module_github_repos "$@" ;;
        issues)        scrt4_module_github_issues "$@" ;;
        issue)         scrt4_module_github_issue_cmd "$@" ;;
        prs)           scrt4_module_github_prs "$@" ;;
        pr)            scrt4_module_github_pr_cmd "$@" ;;
        whoami)        scrt4_module_github_whoami ;;
        help|-h|--help) scrt4_module_github_help ;;
        *)
            echo -e "${RED}Unknown github subcommand: ${sub}${NC}" >&2
            scrt4_module_github_help
            return 1
            ;;
    esac
}

scrt4_module_github_help() {
    cat <<'EOF'
scrt4 github — GitHub REST API wrapper backed by GITHUB_PAT in the vault

USAGE:
    scrt4 github repos [--user NAME]
    scrt4 github issues OWNER/REPO [--state open|closed|all]
    scrt4 github issue view OWNER/REPO NUMBER
    scrt4 github issue create OWNER/REPO "title" "body" [--yes] [--dry-run]
    scrt4 github issue close OWNER/REPO NUMBER [--yes] [--dry-run]
    scrt4 github issue comment OWNER/REPO NUMBER "body" [--yes] [--dry-run]
    scrt4 github prs OWNER/REPO [--state open|closed|all]
    scrt4 github pr view OWNER/REPO NUMBER
    scrt4 github pr merge OWNER/REPO NUMBER [--yes] [--dry-run]
    scrt4 github whoami

SECRETS USED:
    GITHUB_PAT        - Personal Access Token (required)
    GITHUB_USERNAME   - Default user for 'repos' (optional)

SAFETY:
    Write ops require --yes or interactive confirm.
    --dry-run previews the HTTP call without executing.
EOF
}

# =====================================================================
# Helpers
# =====================================================================

_scrt4_gh_secret_exists() {
    local name="$1"
    send_request '{"method":"list"}' 2>/dev/null \
        | jq -e --arg n "$name" '.data.names | index($n)' >/dev/null 2>&1
}

_scrt4_gh_reveal() {
    local name="$1"
    local r1 r2 ok ch code
    r1=$(send_request "$(jq -nc --arg n "$name" '{method:"reveal",params:{name:$n}}')")
    ok=$(echo "$r1" | jq -r '.success // false')
    [ "$ok" = "true" ] || { echo "reveal failed: $(echo "$r1" | jq -r '.error')" >&2; return 1; }
    ch=$(echo "$r1" | jq -r '.data.challenge')
    code=$(echo "$r1" | jq -r '.data.code')
    r2=$(send_request "$(jq -nc --arg c "$ch" --arg k "$code" '{method:"reveal_confirm",params:{challenge:$c,code:$k}}')")
    [ "$(echo "$r2" | jq -r '.success // false')" = "true" ] \
        || { echo "reveal_confirm failed" >&2; return 1; }
    echo "$r2" | jq -r '.data.value'
}

_scrt4_gh_token() { _scrt4_gh_reveal GITHUB_PAT; }

_scrt4_gh_parse_flags() {
    GH_YES=0
    GH_DRY_RUN=0
    GH_STATE="open"
    GH_USER=""
    GH_POSITIONALS=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --yes|-y)   GH_YES=1; shift ;;
            --dry-run)  GH_DRY_RUN=1; shift ;;
            --state)    GH_STATE="${2:-open}"; shift 2 ;;
            --user)     GH_USER="${2:-}"; shift 2 ;;
            --)         shift; while [ $# -gt 0 ]; do GH_POSITIONALS+=("$1"); shift; done ;;
            *)          GH_POSITIONALS+=("$1"); shift ;;
        esac
    done
}

_scrt4_gh_confirm() {
    local prompt="$1"
    if [ "${GH_YES:-0}" = "1" ]; then return 0; fi
    if [ ! -t 0 ]; then
        echo -e "${YELLOW}${prompt}${NC}" >&2
        echo -e "${YELLOW}Non-interactive session — re-run with --yes to execute.${NC}" >&2
        return 1
    fi
    echo -ne "${YELLOW}${prompt}${NC} "
    local ans; read -r ans
    [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]] || return 1
    return 0
}

_scrt4_gh_api() {
    local method="$1" path="$2" token="$3"
    shift 3
    curl -sS --max-time 20 -X "$method" \
        -H "Authorization: Bearer ${token}" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "https://api.github.com${path}" "$@"
}

# =====================================================================
# Commands
# =====================================================================

scrt4_module_github_whoami() {
    ensure_unlocked || return 1
    local tok resp
    tok=$(_scrt4_gh_token) || return 1
    resp=$(_scrt4_gh_api GET "/user" "$tok")
    unset tok
    local login name
    login=$(echo "$resp" | jq -r '.login // "?"')
    name=$(echo "$resp" | jq -r '.name // empty')
    if [ "$login" = "?" ] || [ "$login" = "null" ]; then
        echo -e "${RED}GitHub auth failed: $(echo "$resp" | jq -r '.message // "unknown"')${NC}" >&2
        return 1
    fi
    echo -e "${GREEN}Authed as ${login}${NC}${name:+ ($name)}"
}

scrt4_module_github_repos() {
    ensure_unlocked || return 1
    _scrt4_gh_parse_flags "$@"
    local tok path
    tok=$(_scrt4_gh_token) || return 1
    if [ -n "$GH_USER" ]; then
        path="/users/${GH_USER}/repos?per_page=100&sort=updated"
    else
        path="/user/repos?per_page=100&sort=updated&affiliation=owner"
    fi
    local resp
    resp=$(_scrt4_gh_api GET "$path" "$tok")
    unset tok
    if ! echo "$resp" | jq -e 'type == "array"' >/dev/null 2>&1; then
        echo -e "${RED}API error: $(echo "$resp" | jq -r '.message // "unknown"')${NC}" >&2
        return 1
    fi
    echo -e "${CYAN}Repositories:${NC}"
    echo "$resp" | jq -r '.[] | "\(.full_name)\t\(if .private then "private" else "public" end)\t\(.pushed_at)"' \
        | awk -F'\t' '{ printf "  %-40s %-8s %s\n", $1, $2, $3 }'
}

scrt4_module_github_issues() {
    ensure_unlocked || return 1
    local repo="${1:-}"
    shift || true
    _scrt4_gh_parse_flags "$@"
    if [ -z "$repo" ]; then
        echo "Usage: scrt4 github issues OWNER/REPO [--state open|closed|all]" >&2
        return 1
    fi
    local tok resp
    tok=$(_scrt4_gh_token) || return 1
    resp=$(_scrt4_gh_api GET "/repos/${repo}/issues?state=${GH_STATE}&per_page=50" "$tok")
    unset tok
    if ! echo "$resp" | jq -e 'type == "array"' >/dev/null 2>&1; then
        echo -e "${RED}API error: $(echo "$resp" | jq -r '.message // "unknown"')${NC}" >&2
        return 1
    fi
    echo -e "${CYAN}Issues in ${repo} (state=${GH_STATE}):${NC}"
    # Filter out pull requests (GitHub returns PRs via the issues endpoint too)
    echo "$resp" | jq -r '.[] | select(.pull_request == null) | "#\(.number)\t\(.state)\t\(.title)"' \
        | awk -F'\t' '{ printf "  %-6s %-7s %s\n", $1, $2, $3 }'
}

scrt4_module_github_issue_cmd() {
    ensure_unlocked || return 1
    local sub="${1:-view}"
    shift || true
    case "$sub" in
        view)    _scrt4_gh_issue_view    "$@" ;;
        create)  _scrt4_gh_issue_create  "$@" ;;
        close)   _scrt4_gh_issue_close   "$@" ;;
        comment) _scrt4_gh_issue_comment "$@" ;;
        *)
            echo -e "${RED}Unknown issue subcommand: ${sub}${NC}" >&2
            return 1
            ;;
    esac
}

_scrt4_gh_issue_view() {
    local repo="${1:-}" num="${2:-}"
    if [ -z "$repo" ] || [ -z "$num" ]; then
        echo "Usage: scrt4 github issue view OWNER/REPO NUMBER" >&2
        return 1
    fi
    local tok resp
    tok=$(_scrt4_gh_token) || return 1
    resp=$(_scrt4_gh_api GET "/repos/${repo}/issues/${num}" "$tok")
    unset tok
    if [ "$(echo "$resp" | jq -r '.number // "null"')" = "null" ]; then
        echo -e "${RED}$(echo "$resp" | jq -r '.message // "not found"')${NC}" >&2
        return 1
    fi
    echo -e "${CYAN}#$(echo "$resp" | jq -r '.number') — $(echo "$resp" | jq -r '.title')${NC}"
    echo "state: $(echo "$resp" | jq -r '.state')"
    echo "author: $(echo "$resp" | jq -r '.user.login')"
    echo "url: $(echo "$resp" | jq -r '.html_url')"
    echo ""
    echo "$resp" | jq -r '.body // "(no body)"'
}

_scrt4_gh_issue_create() {
    local repo="${1:-}" title="${2:-}" body="${3:-}"
    shift 3 2>/dev/null || true
    _scrt4_gh_parse_flags "$@"
    if [ -z "$repo" ] || [ -z "$title" ]; then
        echo 'Usage: scrt4 github issue create OWNER/REPO "title" "body" [--yes]' >&2
        return 1
    fi
    echo -e "${CYAN}Plan:${NC} create issue in ${repo}"
    echo "  title: ${title}"
    echo "  body:  ${body:0:80}$([ ${#body} -gt 80 ] && echo '...')"
    if [ "${GH_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no API call will be made."
        echo "  GitHub POST /repos/${repo}/issues"
        return 0
    fi
    _scrt4_gh_confirm "Proceed? [y/N]" || { echo "Aborted."; return 1; }
    local tok resp
    tok=$(_scrt4_gh_token) || return 1
    local bodyjson
    bodyjson=$(jq -nc --arg t "$title" --arg b "$body" '{title:$t,body:$b}')
    resp=$(_scrt4_gh_api POST "/repos/${repo}/issues" "$tok" -d "$bodyjson")
    unset tok
    local num url
    num=$(echo "$resp" | jq -r '.number // empty')
    url=$(echo "$resp" | jq -r '.html_url // empty')
    if [ -n "$num" ]; then
        echo -e "${GREEN}Created issue #${num}: ${url}${NC}"
    else
        echo -e "${RED}API error: $(echo "$resp" | jq -r '.message // "unknown"')${NC}" >&2
        return 1
    fi
}

_scrt4_gh_issue_close() {
    local repo="${1:-}" num="${2:-}"
    shift 2 2>/dev/null || true
    _scrt4_gh_parse_flags "$@"
    if [ -z "$repo" ] || [ -z "$num" ]; then
        echo 'Usage: scrt4 github issue close OWNER/REPO NUMBER [--yes]' >&2
        return 1
    fi
    echo -e "${CYAN}Plan:${NC} close issue #${num} in ${repo}"
    if [ "${GH_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no API call will be made."
        echo "  GitHub PATCH /repos/${repo}/issues/${num}  body: {\"state\":\"closed\"}"
        return 0
    fi
    _scrt4_gh_confirm "Proceed? [y/N]" || { echo "Aborted."; return 1; }
    local tok resp
    tok=$(_scrt4_gh_token) || return 1
    resp=$(_scrt4_gh_api PATCH "/repos/${repo}/issues/${num}" "$tok" -d '{"state":"closed"}')
    unset tok
    if [ "$(echo "$resp" | jq -r '.state // "null"')" = "closed" ]; then
        echo -e "${GREEN}Issue #${num} closed.${NC}"
    else
        echo -e "${RED}API error: $(echo "$resp" | jq -r '.message // "unknown"')${NC}" >&2
        return 1
    fi
}

_scrt4_gh_issue_comment() {
    local repo="${1:-}" num="${2:-}" body="${3:-}"
    shift 3 2>/dev/null || true
    _scrt4_gh_parse_flags "$@"
    if [ -z "$repo" ] || [ -z "$num" ] || [ -z "$body" ]; then
        echo 'Usage: scrt4 github issue comment OWNER/REPO NUMBER "body" [--yes]' >&2
        return 1
    fi
    echo -e "${CYAN}Plan:${NC} comment on ${repo}#${num}"
    if [ "${GH_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no API call will be made."
        echo "  GitHub POST /repos/${repo}/issues/${num}/comments"
        return 0
    fi
    _scrt4_gh_confirm "Proceed? [y/N]" || { echo "Aborted."; return 1; }
    local tok resp bodyjson
    tok=$(_scrt4_gh_token) || return 1
    bodyjson=$(jq -nc --arg b "$body" '{body:$b}')
    resp=$(_scrt4_gh_api POST "/repos/${repo}/issues/${num}/comments" "$tok" -d "$bodyjson")
    unset tok
    local url
    url=$(echo "$resp" | jq -r '.html_url // empty')
    if [ -n "$url" ]; then
        echo -e "${GREEN}Commented: ${url}${NC}"
    else
        echo -e "${RED}API error: $(echo "$resp" | jq -r '.message // "unknown"')${NC}" >&2
        return 1
    fi
}

# =====================================================================
# PRs
# =====================================================================

scrt4_module_github_prs() {
    ensure_unlocked || return 1
    local repo="${1:-}"
    shift || true
    _scrt4_gh_parse_flags "$@"
    if [ -z "$repo" ]; then
        echo "Usage: scrt4 github prs OWNER/REPO [--state open|closed|all]" >&2
        return 1
    fi
    local tok resp
    tok=$(_scrt4_gh_token) || return 1
    resp=$(_scrt4_gh_api GET "/repos/${repo}/pulls?state=${GH_STATE}&per_page=50" "$tok")
    unset tok
    if ! echo "$resp" | jq -e 'type == "array"' >/dev/null 2>&1; then
        echo -e "${RED}API error: $(echo "$resp" | jq -r '.message // "unknown"')${NC}" >&2
        return 1
    fi
    echo -e "${CYAN}PRs in ${repo} (state=${GH_STATE}):${NC}"
    echo "$resp" | jq -r '.[] | "#\(.number)\t\(.state)\t\(.user.login)\t\(.title)"' \
        | awk -F'\t' '{ printf "  %-6s %-7s %-20s %s\n", $1, $2, $3, $4 }'
}

scrt4_module_github_pr_cmd() {
    ensure_unlocked || return 1
    local sub="${1:-view}"
    shift || true
    case "$sub" in
        view)  _scrt4_gh_pr_view  "$@" ;;
        merge) _scrt4_gh_pr_merge "$@" ;;
        *)
            echo -e "${RED}Unknown pr subcommand: ${sub}${NC}" >&2
            return 1
            ;;
    esac
}

_scrt4_gh_pr_view() {
    local repo="${1:-}" num="${2:-}"
    if [ -z "$repo" ] || [ -z "$num" ]; then
        echo "Usage: scrt4 github pr view OWNER/REPO NUMBER" >&2
        return 1
    fi
    local tok resp
    tok=$(_scrt4_gh_token) || return 1
    resp=$(_scrt4_gh_api GET "/repos/${repo}/pulls/${num}" "$tok")
    unset tok
    if [ "$(echo "$resp" | jq -r '.number // "null"')" = "null" ]; then
        echo -e "${RED}$(echo "$resp" | jq -r '.message // "not found"')${NC}" >&2
        return 1
    fi
    echo -e "${CYAN}#$(echo "$resp" | jq -r '.number') — $(echo "$resp" | jq -r '.title')${NC}"
    echo "state: $(echo "$resp" | jq -r '.state')  mergeable: $(echo "$resp" | jq -r '.mergeable // "unknown"')"
    echo "author: $(echo "$resp" | jq -r '.user.login')"
    echo "head: $(echo "$resp" | jq -r '.head.ref')  →  base: $(echo "$resp" | jq -r '.base.ref')"
    echo "url: $(echo "$resp" | jq -r '.html_url')"
}

_scrt4_gh_pr_merge() {
    local repo="${1:-}" num="${2:-}"
    shift 2 2>/dev/null || true
    _scrt4_gh_parse_flags "$@"
    if [ -z "$repo" ] || [ -z "$num" ]; then
        echo 'Usage: scrt4 github pr merge OWNER/REPO NUMBER [--yes]' >&2
        return 1
    fi
    echo -e "${CYAN}Plan:${NC} merge PR #${num} in ${repo}"
    if [ "${GH_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no API call will be made."
        echo "  GitHub PUT /repos/${repo}/pulls/${num}/merge"
        return 0
    fi
    _scrt4_gh_confirm "Proceed? [y/N]" || { echo "Aborted."; return 1; }
    local tok resp
    tok=$(_scrt4_gh_token) || return 1
    resp=$(_scrt4_gh_api PUT "/repos/${repo}/pulls/${num}/merge" "$tok" -d '{}')
    unset tok
    if [ "$(echo "$resp" | jq -r '.merged // false')" = "true" ]; then
        echo -e "${GREEN}PR #${num} merged.${NC}"
    else
        echo -e "${RED}API error: $(echo "$resp" | jq -r '.message // "unknown"')${NC}" >&2
        return 1
    fi
}
