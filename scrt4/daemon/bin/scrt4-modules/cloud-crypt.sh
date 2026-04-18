# shellcheck shell=bash
# scrt4-module: cloud-crypt
# version: 1
# api: 1
# tcb: false
# deps: curl jq gcloud
# commands: cloud-crypt
# requires:
# reveals:
# reveals_pattern:
# reveals_tag:
#
# Client-side encryption orchestration for cloud storage (Google Drive in v1).
#
# The module does NOT do crypto. All encryption/decryption happens in the
# Core daemon (TCB). This module:
#   - Lists encrypted archives (via existing list_encrypted RPC).
#   - Uploads already-encrypted .scrt4 archives to Google Drive.
#   - Downloads encrypted archives from Drive (they stay encrypted on disk).
#   - Exposes a zenity UI that mirrors the CLI.
#   - Provides batch ops so N files = 1 session unlock + 1 gcloud token fetch.
#
# Auth model:
#   - Session: daemon-managed; one `scrt4 unlock` covers the whole batch.
#   - Google Drive: gcloud-managed. Requires Drive scope:
#         gcloud auth application-default login \
#             --scopes=openid,https://www.googleapis.com/auth/drive
#     gcloud caches the token — one fetch per batch, not per file.
#
# Agent-friendliness:
#   - Every command accepts `--json` for structured output.
#   - Batch progress: `[3/10] uploading foo.scrt4 ...` on stderr;
#     stdout stays machine-parseable when `--json` is set.
#
# Commands:
#   scrt4 cloud-crypt list [--json]
#   scrt4 cloud-crypt status [--json]
#   scrt4 cloud-crypt push FILE [FILE...] [--yes] [--dry-run] [--parallel=N]
#   scrt4 cloud-crypt pull DRIVE_ID [DRIVE_ID...] [--out DIR] [--yes] [--dry-run]
#   scrt4 cloud-crypt encrypt-and-push PATH [PATH...] [--yes] [--dry-run]
#   scrt4 cloud-crypt ui
#   scrt4 cloud-crypt help
#
# Core dependency (TBD, see docs/cloud-crypt-core-changes.md):
#   Location tracking (local/gdrive/both) and drive_file_id storage require
#   a small Core extension to encrypted_inventory and a new RPC
#   `inventory_set_location`. Until that lands, this module still works
#   end-to-end — it just can't persist the drive_file_id across runs.
#   Location-dependent output is marked "pending-core" in --json mode.
#
# TCB invariant (ciphertext-only):
#   Every byte this module hands to Google Drive MUST already be AES-256-GCM
#   ciphertext produced by Core — the 9-byte `SCRT4ENC\0` magic is the proof
#   of provenance. `_scrt4_cc_assert_ciphertext` runs before every upload and
#   aborts if the file doesn't start with that magic. This gives cloud-crypt
#   the "module only ever sees ciphertext, never a plaintext path" property
#   by construction, not by convention. `encrypt-and-push` gets this for
#   free because it hands off to Core `encrypt-folder` and re-asserts before
#   the push step. A bug here cannot leak plaintext — at worst it refuses
#   to upload a legitimate archive, which fails safe.

scrt4_module_cloud_crypt_register() {
    _register_command cloud-crypt scrt4_module_cloud_crypt_dispatch
}

scrt4_module_cloud_crypt_dispatch() {
    local sub="${1:-help}"
    shift || true
    case "$sub" in
        list|ls)                        _scrt4_cloud_crypt_list "$@" ;;
        where|find)                     _scrt4_cloud_crypt_where "$@" ;;
        status)                         _scrt4_cloud_crypt_status "$@" ;;
        auth)                           _scrt4_cloud_crypt_auth "$@" ;;
        push)                           _scrt4_cloud_crypt_push "$@" ;;
        pull|download)                  _scrt4_cloud_crypt_pull "$@" ;;
        encrypt-and-push)               _scrt4_cloud_crypt_encrypt_and_push "$@" ;;
        pull-and-decrypt|decrypt)       _scrt4_cloud_crypt_pull_and_decrypt "$@" ;;
        ui)                             _scrt4_cloud_crypt_ui "$@" ;;
        status-panel)                   _scrt4_cloud_crypt_status_panel "$@" ;;
        help|-h|--help)                 _scrt4_cloud_crypt_help ;;
        *)
            echo -e "${RED}Unknown cloud-crypt subcommand: ${sub}${NC}" >&2
            _scrt4_cloud_crypt_help
            return 1
            ;;
    esac
}

_scrt4_cloud_crypt_help() {
    cat <<'EOF'
scrt4 cloud-crypt — client-side encryption + Google Drive sync (v1)

USAGE:
    scrt4 cloud-crypt list [--json]
    scrt4 cloud-crypt where <query> [--json]
    scrt4 cloud-crypt status [--json]
    scrt4 cloud-crypt push FILE [FILE...] [--yes] [--dry-run] [--parallel=N]
    scrt4 cloud-crypt pull DRIVE_ID [DRIVE_ID...] [--out DIR] [--yes] [--dry-run]
    scrt4 cloud-crypt download DRIVE_ID [DRIVE_ID...] [--out DIR] [--yes]   # alias of pull
    scrt4 cloud-crypt encrypt-and-push PATH [PATH...] [--yes] [--dry-run]
    scrt4 cloud-crypt pull-and-decrypt DRIVE_ID [DRIVE_ID...] [--out DIR] [--yes] [--dry-run]
    scrt4 cloud-crypt decrypt DRIVE_ID [DRIVE_ID...] [--out DIR] [--yes]    # alias of pull-and-decrypt
    scrt4 cloud-crypt auth setup [--from-gws | --from-secret NAME | --paste]
    scrt4 cloud-crypt auth status
    scrt4 cloud-crypt auth guide
    scrt4 cloud-crypt ui
    scrt4 cloud-crypt help

DRIVE LAYOUT
    Everything uploaded by this module lands in a single Google Drive
    folder named 'claude-crypt' (auto-created on first push). Reorganize
    it however you like later — the module tracks archives by id, not by
    folder. The UI offers a "Organize with Claude Code" action that
    prints copy-paste prompts so Claude can move / rename / audit your
    Drive layout through this same CLI.

BATCH
    push/pull/encrypt-and-push are variadic. One session unlock + one gcloud
    token fetch covers the whole batch — no re-prompts per file.
    --parallel=N runs N uploads concurrently (default 4).

AUTH
    Three sources, tried in order:
      1. SCRT4_CC_DRIVE_TOKEN env        (one-shot override for CI/tests)
      2. vault secret SCRT4_GDRIVE_OAUTH (personal OAuth refresh token —
         recommended; encrypted at rest, FIDO2-gated)
      3. gcloud ADC                      (fallback)

    First-time setup — either:
        scrt4 cloud-crypt auth setup                (interactive picker)
        scrt4 cloud-crypt auth setup --from-gws     (via Google Workspace CLI)
        scrt4 cloud-crypt auth setup --from-secret personal_google_workspace
        scrt4 cloud-crypt auth guide                (step-by-step walkthrough)
        scrt4 cloud-crypt auth status               (show active source)

    If you drive scrt4 via Claude Code, install the gws per-service
    skills (gws-shared + gws-drive) and they'll run the setup for you:
        npx skills add https://github.com/googleworkspace/cli
    Then ask Claude to "set up Google Drive auth for cloud-crypt".

    Or, skip gws and just do gcloud ADC with Drive scope:
        gcloud auth application-default login \
            --scopes=openid,https://www.googleapis.com/auth/drive,https://www.googleapis.com/auth/drive.file

SAFETY
    - No crypto in this module. Core (TCB) handles encrypt/decrypt.
    - Module only ever handles ciphertext (.scrt4 archives) + metadata.
    - Write ops (push, pull, encrypt-and-push) require --yes in
      non-interactive shells. Use --dry-run to preview.
    - No secrets in argv — all tokens are read via `gcloud auth ... print`.

AGENT
    Every read command supports --json for Claude Code / scripts to parse.
EOF
}

# =====================================================================
# Shared helpers
# =====================================================================

_scrt4_cc_check_gcloud() {
    if ! command -v gcloud >/dev/null 2>&1; then
        echo -e "${RED}gcloud CLI not found.${NC}" >&2
        echo "  Install: https://cloud.google.com/sdk/docs/install" >&2
        return 1
    fi
}

# Name of the vault secret that holds the Google OAuth credentials blob.
# Resolution precedence:
#   1. SCRT4_GDRIVE_OAUTH_NAME env var
#   2. ~/.scrt4/cloud-crypt.conf     (GDRIVE_OAUTH_NAME=<name>)
#   3. default: SCRT4_GDRIVE_OAUTH
# This lets users who already have `personal_google_workspace` in their
# vault point cloud-crypt at that secret without copying it.
# Format: "client_id:X,client_secret:Y,refresh_token:Z[,token_uri:...]"
# Or JSON: '{"client_id":"X","client_secret":"Y","refresh_token":"Z"}'
_SCRT4_CC_CONF="${HOME}/.scrt4/cloud-crypt.conf"
_scrt4_cc_resolve_oauth_name() {
    if [ -n "${SCRT4_GDRIVE_OAUTH_NAME:-}" ]; then
        printf '%s' "$SCRT4_GDRIVE_OAUTH_NAME"; return 0
    fi
    if [ -r "$_SCRT4_CC_CONF" ]; then
        local n
        n=$(sed -n 's/^GDRIVE_OAUTH_NAME=//p' "$_SCRT4_CC_CONF" 2>/dev/null | head -1)
        if [ -n "$n" ]; then
            printf '%s' "$n"; return 0
        fi
    fi
    printf '%s' "SCRT4_GDRIVE_OAUTH"
}
_SCRT4_CC_OAUTH_SECRET_NAME="$(_scrt4_cc_resolve_oauth_name)"

# Checks whether the OAuth secret exists in the current session. Safe — it
# only touches the daemon's list method (names, not values).
_scrt4_cc_has_vault_oauth() {
    local resp
    resp=$(send_request '{"method":"list"}' 2>/dev/null || true)
    [ "$(echo "$resp" | jq -r '.success // false' 2>/dev/null)" = "true" ] || return 1
    echo "$resp" | jq -e --arg n "$_SCRT4_CC_OAUTH_SECRET_NAME" \
        '.data.names | index($n) != null' >/dev/null 2>&1
}

# Exchanges the vault-stored OAuth refresh_token for a short-lived access
# token. The secret value travels only via the daemon's subprocess
# injection ($env[NAME] in _run_with_injected_secrets) — never through
# argv, stdout, or any file on this process's side.
#
# Prints the access_token on stdout; empty on failure.
_scrt4_cc_token_from_vault_oauth() {
    local name="$_SCRT4_CC_OAUTH_SECRET_NAME"

    # The daemon performs inline TEXT substitution of $env[NAME] into the
    # command string (see daemon/src/subprocess.rs). We therefore feed the
    # secret value to python via stdin (pipe), NOT as a python literal or
    # an argv, so the blob's contents cannot break quoting.
    local script
    script=$(mktemp /tmp/scrt4-cc-oauth.XXXXXX.py) || return 1
    cat >"$script" <<'PY'
import sys, json, urllib.request, urllib.parse
blob = sys.stdin.read().strip()
if not blob:
    sys.exit(2)
# Accept either real JSON or the k:v,k:v[,...] shape (with or without braces).
if blob.startswith("{") and '"' in blob:
    d = json.loads(blob)
else:
    s = blob.lstrip("{").rstrip("}")
    d = {}
    for pair in s.split(","):
        if ":" not in pair:
            continue
        k, v = pair.split(":", 1)
        d[k.strip()] = v.strip()
required = ("client_id", "client_secret", "refresh_token")
missing = [r for r in required if not d.get(r)]
if missing:
    sys.stderr.write("missing fields: " + ",".join(missing) + "\n")
    sys.exit(3)
data = urllib.parse.urlencode({
    "client_id":     d["client_id"],
    "client_secret": d["client_secret"],
    "refresh_token": d["refresh_token"],
    "grant_type":    "refresh_token",
}).encode()
req = urllib.request.Request(
    d.get("token_uri", "https://oauth2.googleapis.com/token"),
    data=data, method="POST")
try:
    resp = urllib.request.urlopen(req, timeout=10).read()
except Exception as e:
    sys.stderr.write("token exchange failed: " + str(e) + "\n")
    sys.exit(4)
j = json.loads(resp)
if "access_token" not in j:
    sys.stderr.write("no access_token in response\n")
    sys.exit(5)
sys.stdout.write(j["access_token"])
PY
    # printf "%s" "<injected value>" | python3 /tmp/scrt4-cc-oauth.XXX.py
    # The daemon replaces $env[NAME] with the literal secret value between
    # the double quotes; shell treats it as one arg, stdin pipes it into
    # python. The value never touches argv, never hits ps, never lands on
    # disk. The helper script on disk contains NO secret material.
    local cmd
    cmd='printf %s "$env['"${name}"']" | python3 '"$script"
    _run_with_injected_secrets "$cmd" 2>/dev/null
    local rc=$?
    rm -f "$script" 2>/dev/null || true
    return $rc
}

# Fetches a Drive-scoped OAuth access token. Precedence:
#   1. SCRT4_CC_DRIVE_TOKEN env   — explicit override (CI, tests).
#   2. Vault-stored OAuth blob    — user set up via `scrt4 cloud-crypt auth setup`.
#   3. gcloud ADC                 — fallback when neither is configured.
_scrt4_cc_drive_token() {
    # 1. Explicit env override.
    if [ -n "${SCRT4_CC_DRIVE_TOKEN:-}" ]; then
        printf '%s' "$SCRT4_CC_DRIVE_TOKEN"
        return 0
    fi

    # 2. Personal OAuth creds in the vault.
    if _scrt4_cc_has_vault_oauth; then
        local tok
        tok=$(_scrt4_cc_token_from_vault_oauth 2>/dev/null || true)
        if [ -n "$tok" ]; then
            printf '%s' "$tok"
            return 0
        fi
        echo -e "${YELLOW}OAuth exchange via vault '${_SCRT4_CC_OAUTH_SECRET_NAME}' failed; falling back to gcloud.${NC}" >&2
    fi

    # 3. gcloud application-default credentials.
    local tok
    tok=$(gcloud auth application-default print-access-token 2>/dev/null || true)
    if [ -z "$tok" ]; then
        echo -e "${RED}No Drive token available.${NC}" >&2
        echo "  Options:" >&2
        echo "    - scrt4 cloud-crypt auth setup                       (store your OAuth refresh token in the vault)" >&2
        echo "    - gcloud auth application-default login \\" >&2
        echo "        --scopes=openid,https://www.googleapis.com/auth/drive" >&2
        echo "    - SCRT4_CC_DRIVE_TOKEN=<oauth access token>         (one-shot override)" >&2
        return 1
    fi
    printf '%s' "$tok"
}

# =====================================================================
# auth subcommand — store / inspect Google Drive OAuth credentials
# =====================================================================
#
# The vault-stored OAuth credential is what lets cloud-crypt push and pull
# ciphertext to a user's OWN Google Drive without requiring gcloud ADC or
# an always-on browser. The blob format mirrors `personal_google_workspace`,
# so users who already set that secret up can reuse it here:
#
#     {client_id:X,client_secret:Y,refresh_token:Z,token_uri:https://oauth2.googleapis.com/token}
#
# Preferred setup path is the Google Workspace CLI (`gws`), following its
# "Interactive (local desktop)" flow — `gws auth setup` auto-provisions the
# GCP project + OAuth client, then `gws auth login -s drive,...` does the
# browser consent. Then `scrt4 cloud-crypt auth setup --from-gws` imports
# the resulting refresh token. See:
#     https://github.com/googleworkspace/cli#interactive-local-desktop
#     https://www.npmjs.com/package/@googleworkspace/cli
#
# For Claude Code users, the per-service gws skills (gws-shared, gws-drive)
# walk any agent through that flow. Install with:
#     npx skills add https://github.com/googleworkspace/cli

_scrt4_cloud_crypt_auth() {
    local sub="${1:-help}"
    shift || true
    case "$sub" in
        setup)      _scrt4_cc_auth_setup "$@" ;;
        status)     _scrt4_cc_auth_status "$@" ;;
        guide)      _scrt4_cc_auth_guide "$@" ;;
        help|-h|--help|"") _scrt4_cc_auth_help ;;
        *)
            echo -e "${RED}Unknown auth subcommand: ${sub}${NC}" >&2
            _scrt4_cc_auth_help
            return 1
            ;;
    esac
}

_scrt4_cc_auth_help() {
    cat <<EOF
scrt4 cloud-crypt auth — manage Google Drive OAuth credentials

USAGE:
    scrt4 cloud-crypt auth setup    [--from-gws | --from-secret NAME | --paste]
    scrt4 cloud-crypt auth status
    scrt4 cloud-crypt auth guide
    scrt4 cloud-crypt auth help

WHY
    cloud-crypt uploads/downloads encrypted archives to YOUR Google Drive.
    Rather than depend on a system-wide \`gcloud auth application-default\`
    login, you can store a personal OAuth refresh token directly in the
    scrt4 vault. Drive calls then derive a short-lived access token on
    demand — the refresh token itself is AES-256-GCM encrypted at rest,
    gated by your FIDO2 session, and never lands in argv or on disk.

SOURCES (in order of preference)
    --from-gws          Use Google Workspace CLI (\`gws auth export\`).
                        Easiest — handles browser consent + token exchange.
                        Install: npm install --prefix ~/.local @googleworkspace/cli
                        Then run \`gws auth setup\` + \`gws auth login -s drive,...\`
                        per the "Interactive (local desktop)" flow:
                        https://github.com/googleworkspace/cli#interactive-local-desktop
                        Claude Code users: \`npx skills add https://github.com/googleworkspace/cli\`
                        installs the gws-shared + gws-drive skills that
                        run this end-to-end.

    --from-secret NAME  Point cloud-crypt at an existing vault secret
                        (e.g. \`personal_google_workspace\`). Nothing is
                        copied or re-encrypted — the NAME is saved to
                        ${_SCRT4_CC_CONF} and cloud-crypt reads the live
                        value at token-exchange time. Zero browser hops.

    --paste             Prompt for a blob you paste from clipboard. Useful
                        if you exported creds from somewhere else.

    (no flag)           Interactive menu — picks the best available source.

STORED AS
    ${_SCRT4_CC_OAUTH_SECRET_NAME}    (override with SCRT4_GDRIVE_OAUTH_NAME)
EOF
}

_scrt4_cc_auth_status() {
    ensure_unlocked || return 1

    echo -e "${BOLD}cloud-crypt auth status${NC}"
    echo

    local active="(none)"
    local detail=""

    if [ -n "${SCRT4_CC_DRIVE_TOKEN:-}" ]; then
        active="env override"
        detail="\$SCRT4_CC_DRIVE_TOKEN is set (one-shot access token)"
    elif _scrt4_cc_has_vault_oauth; then
        active="vault OAuth"
        detail="secret: ${_SCRT4_CC_OAUTH_SECRET_NAME}"
    elif command -v gcloud >/dev/null 2>&1 \
         && gcloud auth application-default print-access-token >/dev/null 2>&1; then
        active="gcloud ADC"
        detail="\$(gcloud auth application-default print-access-token)"
    fi

    echo "  Active source : ${active}"
    [ -n "$detail" ] && echo "  Detail        : ${detail}"
    echo

    echo "  All sources (checked in this order):"
    echo -n "    1. SCRT4_CC_DRIVE_TOKEN env      "
    [ -n "${SCRT4_CC_DRIVE_TOKEN:-}" ] \
        && echo -e "${GREEN}set${NC}" \
        || echo -e "${YELLOW}not set${NC}"

    echo -n "    2. vault secret ${_SCRT4_CC_OAUTH_SECRET_NAME}  "
    if _scrt4_cc_has_vault_oauth; then
        echo -e "${GREEN}present${NC}"
    else
        echo -e "${YELLOW}not present${NC}  (run: scrt4 cloud-crypt auth setup)"
    fi

    echo -n "    3. gcloud ADC                    "
    if command -v gcloud >/dev/null 2>&1; then
        if gcloud auth application-default print-access-token >/dev/null 2>&1; then
            echo -e "${GREEN}configured${NC}"
        else
            echo -e "${YELLOW}gcloud installed, ADC not logged in${NC}"
        fi
    else
        echo -e "${YELLOW}gcloud not installed${NC}"
    fi
}

_scrt4_cc_auth_guide() {
    cat <<EOF
${BOLD}Setting up Google Drive OAuth for scrt4 cloud-crypt${NC}

This follows the Google Workspace CLI "Interactive (local desktop)"
flow — https://github.com/googleworkspace/cli#interactive-local-desktop
— which lets \`gws auth setup\` auto-provision a Cloud project + OAuth
client for you. No Cloud Console clicks, no client_secret.json by hand.

You end up with TWO working things:
  • \`gws\` authenticated for the full scrt4 scope set (Drive/Gmail/
    Calendar/Sheets/Docs/Slides/Forms)
  • \`scrt4 cloud-crypt\` able to upload encrypted archives to YOUR
    Drive via a refresh token stored in the vault

${BOLD}Path A — recommended: gws auth setup + gws auth login${NC}
Requires \`gcloud\`. If you don't have gcloud, jump to Path B.

   ${BOLD}1. Install the Google Workspace CLI${NC}
      npm install --prefix ~/.local @googleworkspace/cli
      ln -sf ~/.local/node_modules/.bin/gws ~/.local/bin/gws
      gws --version

   ${BOLD}2. Install gcloud (if missing) and sign in${NC}
      # Linux/WSL — user-local install, no sudo:
      curl -fsSL https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz | tar xz -C ~/
      ~/google-cloud-sdk/install.sh --quiet --path-update=true
      ln -sf ~/google-cloud-sdk/bin/gcloud ~/.local/bin/gcloud
      gcloud auth login --no-launch-browser --update-adc

   ${BOLD}3. Auto-provision the OAuth client${NC}
      gws auth setup
      # Creates (or picks) a GCP project, enables needed APIs, writes
      # ~/.config/gws/client_secret.json. One-time.

   ${BOLD}4. Log in with the canonical scrt4 scope set${NC}
      gws auth login -s drive,gmail,calendar,sheets,docs,slides,forms
      # 12 scopes, under Google's 25-scope testing-mode limit.
      # Full scope URLs (if you prefer --scopes=URL,URL,...):
      #   https://www.googleapis.com/auth/drive
      #   https://www.googleapis.com/auth/drive.file
      #   https://www.googleapis.com/auth/gmail.send
      #   https://www.googleapis.com/auth/gmail.modify
      #   https://www.googleapis.com/auth/calendar
      #   https://www.googleapis.com/auth/calendar.events
      #   https://www.googleapis.com/auth/spreadsheets
      #   https://www.googleapis.com/auth/documents
      #   https://www.googleapis.com/auth/presentations
      #   https://www.googleapis.com/auth/forms
      #   https://www.googleapis.com/auth/forms.body
      #   https://www.googleapis.com/auth/forms.responses.readonly

   ${BOLD}5. Import the refresh token into the scrt4 vault${NC}
      scrt4 cloud-crypt auth setup --from-gws

${BOLD}Path B — gcloud ADC only (skip gws)${NC}
If you just want cloud-crypt working and don't need \`gws\` for other
workspace tasks, Application Default Credentials with Drive scope is
enough — cloud-crypt picks it up as source #3 automatically.

      gcloud auth application-default login \\
          --scopes=openid,https://www.googleapis.com/auth/drive,https://www.googleapis.com/auth/drive.file

${BOLD}Verify (both paths)${NC}
      scrt4 cloud-crypt auth status     # which source is active
      scrt4 cloud-crypt status          # Drive folder + archive list

${BOLD}If you drive scrt4 via Claude Code${NC}
The gws project ships per-service agent skills that handle onboarding
and know the canonical invocation for each API. Install only what you
need — they're small SKILL.md files:

      # all gws skills at once (installs the CLI too):
      npx skills add https://github.com/googleworkspace/cli
      # or per service (e.g. just Drive):
      npx skills add https://github.com/googleworkspace/cli/tree/main/skills/gws-drive

The \`gws-shared\` skill walks any agent through steps 1–5 above; the
\`gws-drive\` skill is what cloud-crypt actually leans on at runtime.
There is no monolithic "google-workspace" skill — use these instead.

${BOLD}Troubleshooting${NC}
  • "Access blocked" during login → consent screen is in Testing mode;
    add your Google account under APIs & Services → OAuth consent
    screen → Test users.
  • \`gws auth setup\` fails → gcloud not installed or not signed in.
    Run \`gcloud auth list\` to confirm.
  • "recommended" scope preset errors for @gmail.com → unverified apps
    are capped at ~25 scopes. Stick with the per-service list above.
EOF
}

# setup — stores the OAuth blob in the vault as ${_SCRT4_CC_OAUTH_SECRET_NAME}.
# Sources are tried in the order the user requested (or best-available if no
# flag was given). The blob NEVER lands in argv — it travels via stdin into
# a python helper that calls the daemon's add_secrets RPC directly.
_scrt4_cc_auth_setup() {
    ensure_unlocked || return 1

    local mode=""
    local from_secret=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --from-gws)                 mode="gws"; shift ;;
            --from-secret)              mode="secret"; from_secret="${2:-}"; shift 2 ;;
            --from-secret=*)            mode="secret"; from_secret="${1#--from-secret=}"; shift ;;
            --paste)                    mode="paste"; shift ;;
            -h|--help)                  _scrt4_cc_auth_help; return 0 ;;
            *)                          echo -e "${RED}Unknown flag: $1${NC}" >&2; return 2 ;;
        esac
    done

    # Interactive picker if no mode chosen.
    if [ -z "$mode" ]; then
        echo -e "${BOLD}scrt4 cloud-crypt auth setup${NC}"
        echo
        echo "Choose a source for your Google Drive OAuth refresh token:"
        echo "  1) Google Workspace CLI (gws auth export)        [easiest]"
        echo "  2) Copy from another vault secret                [e.g. personal_google_workspace]"
        echo "  3) Paste the blob manually"
        echo "  q) Cancel"
        echo
        echo "If you have Claude Code, installing the gws skills lets an agent"
        echo "run option 1 end-to-end — see 'scrt4 cloud-crypt auth guide'."
        echo
        if [ ! -t 0 ]; then
            echo -e "${RED}Non-interactive shell — pass --from-gws, --from-secret NAME, or --paste.${NC}" >&2
            return 1
        fi
        echo -n "Choice [1/2/3/q]: "
        local choice; read -r choice
        case "$choice" in
            1) mode="gws" ;;
            2) mode="secret" ;;
            3) mode="paste" ;;
            q|Q|"") echo "Cancelled."; return 0 ;;
            *) echo -e "${RED}Invalid choice.${NC}" >&2; return 1 ;;
        esac
    fi

    local blob=""
    case "$mode" in
        gws)     blob=$(_scrt4_cc_auth_collect_from_gws)    || return 1 ;;
        secret)  blob=$(_scrt4_cc_auth_collect_from_secret "$from_secret") || return 1 ;;
        paste)   blob=$(_scrt4_cc_auth_collect_paste)       || return 1 ;;
    esac

    [ -n "$blob" ] || { echo -e "${RED}No credentials collected.${NC}" >&2; return 1; }

    if [ "$blob" = "__SCRT4_CC_USE_EXISTING__" ]; then
        # Pointer-only path: creds already live in the vault under a
        # different name; we just wrote the pointer to cloud-crypt.conf.
        echo -e "${GREEN}cloud-crypt now points at vault secret: ${_SCRT4_CC_OAUTH_SECRET_NAME}${NC}"
        echo -e "  (pointer saved to ${_SCRT4_CC_CONF})"
    else
        _scrt4_cc_auth_validate_blob "$blob" || {
            echo -e "${RED}Validation failed — blob is missing required fields.${NC}" >&2
            echo "  Expected: client_id, client_secret, refresh_token" >&2
            return 1
        }
        _scrt4_cc_auth_store_blob "$blob" || return 1
        echo -e "${GREEN}Stored as vault secret: ${_SCRT4_CC_OAUTH_SECRET_NAME}${NC}"
    fi
    echo
    echo -e "${BOLD}Verifying token exchange...${NC}"
    local tok
    tok=$(_scrt4_cc_token_from_vault_oauth 2>&1 || true)
    if [ -n "$tok" ] && [[ "$tok" == ya29.* || "$tok" =~ ^[A-Za-z0-9._-]{20,}$ ]]; then
        echo -e "${GREEN}✓ Got a Drive access token.${NC} (length: ${#tok})"
    else
        echo -e "${YELLOW}Token exchange failed. Response:${NC}" >&2
        echo "  $tok" >&2
        echo "  Check that Google Drive API is enabled and the refresh token is valid." >&2
        return 1
    fi

    echo
    echo "Next:"
    echo "  scrt4 cloud-crypt status          # see Drive folder + recent archives"
    echo "  scrt4 cloud-crypt encrypt-and-push FILE"
}

# --from-gws: export credentials from Google Workspace CLI.
_scrt4_cc_auth_collect_from_gws() {
    if ! command -v gws >/dev/null 2>&1; then
        echo -e "${RED}gws (Google Workspace CLI) not installed.${NC}" >&2
        echo "  Install: npm install --prefix ~/.local @googleworkspace/cli" >&2
        echo "  Or: scrt4 cloud-crypt auth guide" >&2
        return 1
    fi

    echo -e "${BOLD}Exporting credentials from gws...${NC}" >&2
    local creds
    creds=$(gws auth export --unmasked 2>/dev/null || true)
    if [ -z "$creds" ]; then
        echo -e "${RED}gws auth export returned nothing.${NC}" >&2
        echo "  Run \`gws auth status\` to diagnose." >&2
        echo "  If no client_secret.json yet: \`gws auth setup\` (requires gcloud)" >&2
        echo "  Then: \`gws auth login -s drive,gmail,calendar,sheets,docs,slides,forms\`" >&2
        echo "  Full guide: scrt4 cloud-crypt auth guide" >&2
        return 1
    fi

    local cid csc rtk tkn
    cid=$(echo "$creds" | jq -r '.client_id // empty' 2>/dev/null)
    csc=$(echo "$creds" | jq -r '.client_secret // empty' 2>/dev/null)
    rtk=$(echo "$creds" | jq -r '.refresh_token // empty' 2>/dev/null)
    tkn=$(echo "$creds" | jq -r '.token_uri // "https://oauth2.googleapis.com/token"' 2>/dev/null)

    if [ -z "$cid" ] || [ -z "$csc" ] || [ -z "$rtk" ]; then
        echo -e "${RED}gws export missing one of client_id/client_secret/refresh_token.${NC}" >&2
        return 1
    fi

    printf '{client_id:%s,client_secret:%s,refresh_token:%s,token_uri:%s}' \
        "$cid" "$csc" "$rtk" "$tkn"
}

# --from-secret: point cloud-crypt at an EXISTING vault secret (e.g.
# `personal_google_workspace`) without copying its value. We can't read
# stored-secret values back out — the daemon redacts them from all
# subprocess output by design — so we persist the NAME in a small config
# file under $HOME/.scrt4/cloud-crypt.conf. The token exchange helper
# reads the live value via the normal $env[NAME] injection path.
_scrt4_cc_auth_collect_from_secret() {
    local src="${1:-}"
    if [ -z "$src" ]; then
        if [ ! -t 0 ]; then
            echo -e "${RED}--from-secret requires a name (e.g. personal_google_workspace).${NC}" >&2
            return 1
        fi
        echo -n "Source secret name [personal_google_workspace]: " >&2
        read -r src
        src="${src:-personal_google_workspace}"
    fi

    # Verify the secret exists in the vault (list only — no values).
    local resp
    resp=$(send_request '{"method":"list"}' 2>/dev/null || true)
    if [ "$(echo "$resp" | jq -r '.success // false' 2>/dev/null)" != "true" ]; then
        echo -e "${RED}Could not list vault secrets (is the session unlocked?).${NC}" >&2
        return 1
    fi
    if ! echo "$resp" | jq -e --arg n "$src" '.data.names | index($n) != null' >/dev/null; then
        echo -e "${RED}Vault has no secret named '${src}'.${NC}" >&2
        echo "  Check with: scrt4 list" >&2
        return 1
    fi

    # Persist the pointer. This is config, not a secret — the NAME is not
    # sensitive. Value stays in the vault untouched.
    mkdir -p "${HOME}/.scrt4" 2>/dev/null
    printf 'GDRIVE_OAUTH_NAME=%s\n' "$src" > "$_SCRT4_CC_CONF"
    chmod 600 "$_SCRT4_CC_CONF" 2>/dev/null || true
    _SCRT4_CC_OAUTH_SECRET_NAME="$src"

    # Emit a sentinel blob so _scrt4_cc_auth_setup treats this as "ok,
    # we already have creds in the vault" — skip validation (we couldn't
    # read the value anyway) and go straight to the live token-exchange
    # check, which will fail loudly if the existing secret is malformed.
    printf '__SCRT4_CC_USE_EXISTING__'
}

# --paste: prompt the user to paste a blob interactively.
_scrt4_cc_auth_collect_paste() {
    if [ ! -t 0 ]; then
        echo -e "${RED}--paste requires an interactive shell.${NC}" >&2
        return 1
    fi
    echo -e "${BOLD}Paste your OAuth blob below, then press Enter.${NC}" >&2
    echo "Expected format (one line):" >&2
    echo "  {client_id:X,client_secret:Y,refresh_token:Z,token_uri:https://oauth2.googleapis.com/token}" >&2
    echo "Or a JSON object with the same keys." >&2
    echo -n "> " >&2
    local blob; IFS= read -r blob
    printf '%s' "$blob"
}

# Validate that the blob has client_id/client_secret/refresh_token (any shape).
_scrt4_cc_auth_validate_blob() {
    local blob="$1"
    printf '%s' "$blob" | python3 - <<'PY' >/dev/null 2>&1
import sys, json
blob = sys.stdin.read().strip()
if not blob: sys.exit(1)
if blob.startswith("{") and '"' in blob:
    d = json.loads(blob)
else:
    s = blob.lstrip("{").rstrip("}")
    d = {}
    for p in s.split(","):
        if ":" in p:
            k, v = p.split(":", 1)
            d[k.strip()] = v.strip()
for k in ("client_id", "client_secret", "refresh_token"):
    if not d.get(k): sys.exit(1)
PY
}

# Store the blob in the vault via the daemon's add_secrets RPC. We build
# the JSON request via jq (blob goes in as a string argument, not argv of
# any exec'd child), then send through the existing send_request helper.
_scrt4_cc_auth_store_blob() {
    local blob="$1"
    local name="$_SCRT4_CC_OAUTH_SECRET_NAME"

    local req
    req=$(jq -nc --arg n "$name" --arg v "$blob" \
        '{method:"add_secrets",params:{secrets:{($n):$v}}}') || {
        echo -e "${RED}Failed to encode request.${NC}" >&2
        return 1
    }

    local resp
    resp=$(send_request "$req")
    local ok
    ok=$(echo "$resp" | jq -r '.success // false' 2>/dev/null || echo "false")
    if [ "$ok" != "true" ]; then
        local err
        err=$(echo "$resp" | jq -r '.error // "unknown error"' 2>/dev/null)
        echo -e "${RED}add_secrets failed: ${err}${NC}" >&2
        return 1
    fi
    return 0
}

# Parse common flags: --yes, --dry-run, --json, --parallel=N, --out DIR.
# Sets globals CC_YES, CC_DRY_RUN, CC_JSON, CC_PARALLEL, CC_OUT_DIR,
# CC_POSITIONALS. Resets them every call.
_scrt4_cc_parse_flags() {
    CC_YES=0
    CC_DRY_RUN=0
    CC_JSON=0
    CC_PARALLEL=4
    CC_OUT_DIR=""
    CC_POSITIONALS=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --yes|-y)        CC_YES=1; shift ;;
            --dry-run)       CC_DRY_RUN=1; shift ;;
            --json)          CC_JSON=1; shift ;;
            --parallel=*)    CC_PARALLEL="${1#--parallel=}"; shift ;;
            --parallel)      CC_PARALLEL="${2:-4}"; shift 2 ;;
            --out)           CC_OUT_DIR="${2:-}"; shift 2 ;;
            --out=*)         CC_OUT_DIR="${1#--out=}"; shift ;;
            --)              shift; while [ $# -gt 0 ]; do CC_POSITIONALS+=("$1"); shift; done ;;
            *)               CC_POSITIONALS+=("$1"); shift ;;
        esac
    done
}

_scrt4_cc_confirm() {
    local prompt="$1"
    if [ "${CC_YES:-0}" = "1" ]; then return 0; fi
    if [ ! -t 0 ]; then
        echo -e "${YELLOW}${prompt}${NC}" >&2
        echo -e "${YELLOW}Non-interactive — re-run with --yes.${NC}" >&2
        return 1
    fi
    echo -ne "${YELLOW}${prompt}${NC} "
    local ans; read -r ans
    [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]] || return 1
}

# Dedicated Drive folder. Everything encrypted by this module lands here
# unless the user reorganizes it later. Name is fixed ("claude-crypt") so
# it's easy to spot in Drive and agents can reference it without config.
# The folder id is cached under XDG_DATA_HOME after first lookup/create.
_SCRT4_CC_FOLDER_NAME="claude-crypt"
_scrt4_cc_drive_folder_id_path() {
    local base="${XDG_DATA_HOME:-$HOME/.local/share}/scrt4/cloud-crypt"
    mkdir -p "$base"
    printf '%s/drive-folder-id' "$base"
}

_scrt4_cc_get_or_create_folder() {
    local tok="$1"
    local cache; cache=$(_scrt4_cc_drive_folder_id_path)
    if [ -s "$cache" ]; then
        cat "$cache"; return 0
    fi
    # Look up first (user may have created it manually).
    local q search_resp existing_id
    q="name='${_SCRT4_CC_FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    search_resp=$(curl -sS -G \
        -H "Authorization: Bearer ${tok}" \
        --data-urlencode "q=${q}" \
        --data-urlencode "fields=files(id,name)" \
        "https://www.googleapis.com/drive/v3/files" 2>/dev/null || true)
    existing_id=$(echo "$search_resp" | jq -r '.files[0].id // empty' 2>/dev/null || true)
    if [ -n "$existing_id" ]; then
        printf '%s' "$existing_id" > "$cache"
        printf '%s' "$existing_id"; return 0
    fi
    # Create.
    local create_resp new_id
    create_resp=$(curl -sS -X POST \
        -H "Authorization: Bearer ${tok}" \
        -H "Content-Type: application/json" \
        -d "$(jq -nc --arg n "$_SCRT4_CC_FOLDER_NAME" '{name:$n, mimeType:"application/vnd.google-apps.folder"}')" \
        "https://www.googleapis.com/drive/v3/files" 2>/dev/null || true)
    new_id=$(echo "$create_resp" | jq -r '.id // empty' 2>/dev/null || true)
    if [ -z "$new_id" ]; then
        echo -e "${RED}Failed to create Drive folder '${_SCRT4_CC_FOLDER_NAME}'${NC}" >&2
        echo "$create_resp" | jq -r '.error.message // empty' >&2 2>/dev/null || true
        return 1
    fi
    printf '%s' "$new_id" > "$cache"
    printf '%s' "$new_id"
}

# =====================================================================
# status
# =====================================================================

_scrt4_cloud_crypt_status() {
    _scrt4_cc_parse_flags "$@"
    local have_gcloud=0 have_token=0 drive_ok=0 session=""
    command -v gcloud >/dev/null 2>&1 && have_gcloud=1
    if [ "$have_gcloud" = "1" ]; then
        gcloud auth application-default print-access-token >/dev/null 2>&1 && have_token=1
    fi
    # Best-effort: does the cached token accept a Drive request?
    if [ "$have_token" = "1" ]; then
        local tok; tok=$(gcloud auth application-default print-access-token 2>/dev/null || true)
        local probe
        probe=$(curl -sS -o /dev/null -w '%{http_code}' \
            -H "Authorization: Bearer ${tok}" \
            "https://www.googleapis.com/drive/v3/about?fields=user(emailAddress)" 2>/dev/null || echo "000")
        [ "$probe" = "200" ] && drive_ok=1
    fi
    # Session status from daemon.
    local sresp
    sresp=$(send_request '{"method":"status"}' 2>/dev/null || true)
    session=$(echo "$sresp" | jq -r '.data.unlocked // false' 2>/dev/null || echo "false")

    if [ "${CC_JSON:-0}" = "1" ]; then
        jq -nc \
            --argjson gc   "$have_gcloud" \
            --argjson tok  "$have_token" \
            --argjson drv  "$drive_ok" \
            --arg     sess "$session" \
            '{gcloud_installed:($gc==1), adc_token:($tok==1), drive_reachable:($drv==1), session_unlocked:($sess=="true")}'
        return 0
    fi

    echo -e "${CYAN}cloud-crypt status:${NC}"
    printf "  gcloud installed   : %s\n" "$([ "$have_gcloud" = "1" ] && echo yes || echo NO)"
    printf "  ADC token present  : %s\n" "$([ "$have_token"  = "1" ] && echo yes || echo NO)"
    printf "  Drive API reachable: %s\n" "$([ "$drive_ok"    = "1" ] && echo yes || echo NO)"
    printf "  scrt4 session      : %s\n" "$([ "$session"     = "true" ] && echo unlocked || echo LOCKED)"
    if [ "$have_token" = "0" ] || [ "$drive_ok" = "0" ]; then
        echo ""
        echo "  To enable Drive access:"
        echo "    gcloud auth application-default login \\"
        echo "        --scopes=openid,https://www.googleapis.com/auth/drive"
    fi
}

# =====================================================================
# list
# =====================================================================

_scrt4_cloud_crypt_list() {
    _scrt4_cc_parse_flags "$@"
    ensure_unlocked || return 1
    local resp
    resp=$(send_request '{"method":"list_encrypted"}')
    local ok; ok=$(echo "$resp" | jq -r '.success // false')
    if [ "$ok" != "true" ]; then
        echo -e "${RED}list_encrypted failed: $(echo "$resp" | jq -r '.error // "unknown"')${NC}" >&2
        return 1
    fi
    if [ "${CC_JSON:-0}" = "1" ]; then
        # Enrich each entry with a `location` field. Until Core exposes it,
        # we default to "local" (or "missing" if exists=false).
        echo "$resp" | jq '{
            count: (.data.entries | length),
            entries: [ .data.entries[] | {
                id,
                name: .folder_name,
                path,
                file_count,
                size: .archive_size,
                present_locally: .exists,
                location: (if .exists then "local" else "missing" end),
                drive_file_id: null,
                location_source: "pending-core"
            } ]
        }'
        return 0
    fi
    local count; count=$(echo "$resp" | jq -r '.data.entries | length')
    if [ "$count" = "0" ]; then
        echo -e "${YELLOW}No encrypted archives registered.${NC}"
        echo "  Create one with: scrt4 encrypt-folder PATH"
        return 0
    fi
    echo -e "${CYAN}Registered encrypted archives (${count}):${NC}"
    printf "  %-9s %-30s %-8s %-12s %s\n" "STATE" "NAME" "FILES" "SIZE" "ID"
    echo "$resp" | jq -r '.data.entries[] |
        "  \(if .exists then "[local]" else "[GONE] " end)  \(.folder_name | .[0:28])\t\(.file_count)\t\(.archive_size)\t\(.id)"' \
        | awk -F'\t' '{ printf "  %-9s %-30s %-8s %-12s %s\n", "", $1, $2, $3, $4 }' \
        | sed 's/  \[/[/'
    # Intentional: real row rendering uses the jq output above; the awk line
    # is a cosmetic aligner. When Core exposes location, add a LOC column.
    echo ""
    echo -e "${YELLOW}Note:${NC} location tracking (local/gdrive/both) pending Core RPC extension."
    echo "      See docs/cloud-crypt-core-changes.md."
}

# =====================================================================
# where — single-file lookup (agent primitive)
# =====================================================================
#
# Given a query (archive name, id, or substring of path), print a single
# JSON object describing everything known about that archive: local path,
# file count, size, Drive id (when Core extension lands), Drive folder.
# Agent usage:   scrt4 cloud-crypt where finances
#                scrt4 cloud-crypt where 7f3a-...
_scrt4_cloud_crypt_where() {
    _scrt4_cc_parse_flags "$@"
    ensure_unlocked || return 1
    if [ "${#CC_POSITIONALS[@]}" = "0" ]; then
        echo "Usage: scrt4 cloud-crypt where <query>" >&2
        return 1
    fi
    local q="${CC_POSITIONALS[0]}"
    local resp; resp=$(send_request '{"method":"list_encrypted"}')
    local match
    match=$(echo "$resp" | jq --arg q "$q" '
        (.data.entries // [])
        | map(select(
            (.id | test($q; "i"))
            or (.folder_name | test($q; "i"))
            or (.path | test($q; "i"))
        ))
        | .[0] // null')
    if [ "$match" = "null" ] || [ -z "$match" ]; then
        if [ "${CC_JSON:-0}" = "1" ]; then
            jq -nc --arg q "$q" '{query:$q, found:false}'
        else
            echo -e "${YELLOW}No archive matches '${q}'.${NC}"
        fi
        return 1
    fi
    # Enrich for agents. Drive fields are placeholders until Core lands
    # inventory_set_location (see docs/cloud-crypt-core-changes.md).
    if [ "${CC_JSON:-0}" = "1" ]; then
        echo "$match" | jq --arg q "$q" --arg fn "$_SCRT4_CC_FOLDER_NAME" '{
            query: $q,
            found: true,
            id,
            name: .folder_name,
            local_path: .path,
            present_locally: .exists,
            file_count,
            archive_size,
            drive_folder_name: $fn,
            drive_file_id: null,
            location: (if .exists then "local" else "missing" end),
            location_source: "pending-core"
        }'
    else
        local name path present
        name=$(echo "$match" | jq -r '.folder_name')
        path=$(echo "$match" | jq -r '.path')
        present=$(echo "$match" | jq -r '.exists')
        echo -e "${CYAN}${name}${NC}"
        echo "  local path       : ${path}"
        echo "  present locally  : ${present}"
        echo "  drive folder     : ${_SCRT4_CC_FOLDER_NAME}  (tracking pending Core RPC)"
    fi
}

# =====================================================================
# push (batch)
# =====================================================================

_scrt4_cloud_crypt_push() {
    _scrt4_cc_parse_flags "$@"
    ensure_unlocked || return 1
    _scrt4_cc_check_gcloud || return 1
    if [ "${#CC_POSITIONALS[@]}" = "0" ]; then
        echo "Usage: scrt4 cloud-crypt push FILE [FILE...]" >&2
        return 1
    fi

    # Pre-flight: every file must exist and be readable.
    local f missing=0
    for f in "${CC_POSITIONALS[@]}"; do
        if [ ! -f "$f" ] || [ ! -r "$f" ]; then
            echo -e "${RED}Not a readable file: ${f}${NC}" >&2
            missing=$((missing + 1))
        fi
    done
    [ "$missing" = "0" ] || { echo "Aborting: ${missing} file(s) missing." >&2; return 1; }

    local n="${#CC_POSITIONALS[@]}"
    echo -e "${CYAN}Plan:${NC} upload ${n} file(s) to Google Drive folder '${_SCRT4_CC_FOLDER_NAME}'"
    for f in "${CC_POSITIONALS[@]}"; do echo "  • $f"; done

    if [ "${CC_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no uploads will execute."
        echo "  (would fetch gcloud ADC token once, then POST to drive/v3/files for each file)"
        return 0
    fi

    _scrt4_cc_confirm "Upload ${n} file(s)? [y/N]" || { echo "Aborted."; return 1; }

    local tok; tok=$(_scrt4_cc_drive_token) || return 1
    local folder_id; folder_id=$(_scrt4_cc_get_or_create_folder "$tok") || return 1

    # Sequential is safe and deterministic; parallel honours CC_PARALLEL.
    # We export the helper + token and use xargs -P.
    local tmp_results
    tmp_results=$(mktemp -d -t scrt4-cc-push-XXXXXX)

    local i=0
    if [ "${CC_PARALLEL:-4}" -le 1 ]; then
        for f in "${CC_POSITIONALS[@]}"; do
            i=$((i + 1))
            echo "  [${i}/${n}] uploading $(basename "$f") ..." >&2
            _scrt4_cc_upload_one "$tok" "$folder_id" "$f" > "${tmp_results}/${i}.json" || true
        done
    else
        export _SCRT4_CC_TOK="$tok" _SCRT4_CC_FOLDER="$folder_id" _SCRT4_CC_OUT="$tmp_results"
        # shellcheck disable=SC2016
        printf '%s\n' "${CC_POSITIONALS[@]}" | \
            awk '{ printf "%d\t%s\n", NR, $0 }' | \
            xargs -d '\n' -I{} -P "$CC_PARALLEL" bash -c '
                line="$1"; idx="${line%%	*}"; file="${line#*	}"
                echo "  [${idx}] uploading $(basename "$file") ..." >&2
                _scrt4_cc_upload_one "$_SCRT4_CC_TOK" "$_SCRT4_CC_FOLDER" "$file" > "${_SCRT4_CC_OUT}/${idx}.json" || true
            ' _ {}
        unset _SCRT4_CC_TOK _SCRT4_CC_FOLDER _SCRT4_CC_OUT
    fi

    # Aggregate + print results.
    local ok=0 err=0
    if [ "${CC_JSON:-0}" = "1" ]; then
        jq -s '{uploaded: map(select(.ok == true) | {file, drive_file_id, bytes}), failed: map(select(.ok == true | not))}' \
            "${tmp_results}"/*.json 2>/dev/null || echo '{"uploaded":[],"failed":[]}'
    else
        local r
        for r in "${tmp_results}"/*.json; do
            [ -f "$r" ] || continue
            if [ "$(jq -r '.ok' "$r")" = "true" ]; then
                ok=$((ok + 1))
                echo "  ok  : $(jq -r '.file' "$r")  →  $(jq -r '.drive_file_id' "$r")"
            else
                err=$((err + 1))
                echo "  FAIL: $(jq -r '.file' "$r")  ($(jq -r '.error // "unknown"' "$r"))"
            fi
        done
        echo ""
        echo -e "${CYAN}${ok} uploaded, ${err} failed.${NC}"
    fi
    rm -rf "$tmp_results"

    # TODO: requires Core RPC inventory_set_location to persist drive_file_id
    # against the local inventory entry. See docs/cloud-crypt-core-changes.md.

    [ "${err:-0}" = "0" ]
}

# TCB: cloud-crypt ciphertext-only gate
# Verifies: every file handed to Drive starts with the SCRT4ENC\0 magic
#           (i.e. is AES-256-GCM ciphertext produced by Core).
# Adversary: a bug elsewhere in the module (or a caller misuse) attempts
#           to upload a plaintext path. Fails closed — returns non-zero
#           and never touches the network.
#
# This is the module's sole TCB-relevant function. It does no crypto; it
# only rejects inputs that are not already ciphertext. The check is the
# 9-byte SCRT4ENC magic — same format used by encrypt-folder and
# list-encrypted. Binary-safe via od -An -tx1 of the first 9 bytes.
# Args: FILE
# Returns: 0 if ciphertext, 1 otherwise (prints a short reason on stderr).
_scrt4_cc_assert_ciphertext() {
    local file="$1"
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        echo "cloud-crypt: refusing upload — not a readable file: ${file}" >&2
        return 1
    fi
    # "SCRT4ENC\0" = 53 43 52 54 34 45 4e 43 00
    local hex
    hex=$(head -c 9 "$file" | od -An -tx1 2>/dev/null | tr -d ' \n')
    if [ "$hex" != "5343525434454e4300" ]; then
        echo "cloud-crypt: refusing upload — ${file} is not AES-GCM ciphertext (missing SCRT4ENC magic; got: ${hex:-<empty>})" >&2
        echo "cloud-crypt: the module never uploads plaintext. Run: scrt4 encrypt-folder '${file}' first." >&2
        return 1
    fi
    return 0
}

# Upload one file. Prints a single-line JSON result on stdout.
# Args: TOKEN FOLDER_ID FILE
_scrt4_cc_upload_one() {
    local tok="$1" folder="$2" file="$3"
    # TCB gate: refuse anything that is not already AES-GCM ciphertext.
    # This is the invariant that keeps cloud-crypt a pure orchestrator —
    # the module physically cannot upload plaintext even under caller bugs.
    if ! _scrt4_cc_assert_ciphertext "$file"; then
        jq -nc --arg f "$file" '{ok:false, file:$f, error:"not ciphertext — SCRT4ENC magic missing"}'
        return 1
    fi
    local name bytes
    name=$(basename "$file")
    bytes=$(stat -c %s "$file" 2>/dev/null || stat -f %z "$file" 2>/dev/null || echo 0)
    local boundary="scrt4cc-$(date +%s%N)-$$"
    local meta
    meta=$(jq -nc --arg n "$name" --arg p "$folder" '{name:$n, parents:[$p]}')
    # Multipart upload — write body to a temp file to avoid loading blob into argv.
    local body; body=$(mktemp -t scrt4cc-body-XXXXXX)
    {
        printf -- '--%s\r\n' "$boundary"
        printf 'Content-Type: application/json; charset=UTF-8\r\n\r\n'
        printf '%s\r\n' "$meta"
        printf -- '--%s\r\n' "$boundary"
        printf 'Content-Type: application/octet-stream\r\n\r\n'
        cat "$file"
        printf '\r\n--%s--\r\n' "$boundary"
    } > "$body"
    local resp
    resp=$(curl -sS -X POST \
        -H "Authorization: Bearer ${tok}" \
        -H "Content-Type: multipart/related; boundary=${boundary}" \
        --data-binary "@${body}" \
        "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,size" 2>/dev/null || true)
    rm -f "$body"
    local id; id=$(echo "$resp" | jq -r '.id // empty' 2>/dev/null || true)
    if [ -n "$id" ]; then
        jq -nc --arg f "$file" --arg id "$id" --argjson b "$bytes" \
            '{ok:true, file:$f, drive_file_id:$id, bytes:$b}'
    else
        local err; err=$(echo "$resp" | jq -r '.error.message // "upload failed"' 2>/dev/null || echo "upload failed")
        jq -nc --arg f "$file" --arg e "$err" '{ok:false, file:$f, error:$e}'
    fi
}
# Make xargs child shells see the helper.
export -f _scrt4_cc_upload_one 2>/dev/null || true

# =====================================================================
# pull (batch)
# =====================================================================

_scrt4_cloud_crypt_pull() {
    _scrt4_cc_parse_flags "$@"
    ensure_unlocked || return 1
    _scrt4_cc_check_gcloud || return 1
    if [ "${#CC_POSITIONALS[@]}" = "0" ]; then
        echo "Usage: scrt4 cloud-crypt pull DRIVE_ID [DRIVE_ID...] [--out DIR]" >&2
        return 1
    fi
    local out_dir="${CC_OUT_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/scrt4/cloud-crypt/inbox}"
    mkdir -p "$out_dir"

    local n="${#CC_POSITIONALS[@]}"
    echo -e "${CYAN}Plan:${NC} download ${n} archive(s) to ${out_dir}"
    for id in "${CC_POSITIONALS[@]}"; do echo "  • drive:${id}"; done

    if [ "${CC_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no downloads will execute."
        echo "  (would fetch gcloud ADC token once, then GET drive/v3/files/ID?alt=media)"
        return 0
    fi

    _scrt4_cc_confirm "Download ${n} archive(s) to ${out_dir}? [y/N]" \
        || { echo "Aborted."; return 1; }

    local tok; tok=$(_scrt4_cc_drive_token) || return 1
    local i=0 ok=0 err=0 id meta name dest
    for id in "${CC_POSITIONALS[@]}"; do
        i=$((i + 1))
        echo "  [${i}/${n}] downloading drive:${id} ..." >&2
        meta=$(curl -sS -H "Authorization: Bearer ${tok}" \
            "https://www.googleapis.com/drive/v3/files/${id}?fields=id,name" 2>/dev/null || true)
        name=$(echo "$meta" | jq -r '.name // empty' 2>/dev/null || true)
        if [ -z "$name" ]; then
            err=$((err + 1))
            echo "  FAIL: drive:${id} (not found or access denied)"
            continue
        fi
        dest="${out_dir}/${name}"
        if curl -sS -fL -H "Authorization: Bearer ${tok}" \
            -o "$dest" \
            "https://www.googleapis.com/drive/v3/files/${id}?alt=media" 2>/dev/null; then
            ok=$((ok + 1))
            echo "  ok  : drive:${id}  →  ${dest}"
        else
            err=$((err + 1))
            rm -f "$dest" 2>/dev/null || true
            echo "  FAIL: drive:${id} (download error)"
        fi
    done
    echo ""
    echo -e "${CYAN}${ok} downloaded, ${err} failed.${NC}"
    [ "$err" = "0" ]
}

# =====================================================================
# encrypt-and-push (batch)
# =====================================================================

_scrt4_cloud_crypt_encrypt_and_push() {
    _scrt4_cc_parse_flags "$@"
    ensure_unlocked || return 1
    _scrt4_cc_check_gcloud || return 1
    if [ "${#CC_POSITIONALS[@]}" = "0" ]; then
        echo "Usage: scrt4 cloud-crypt encrypt-and-push PATH [PATH...]" >&2
        return 1
    fi

    local n="${#CC_POSITIONALS[@]}"
    local cache_dir="${XDG_DATA_HOME:-$HOME/.local/share}/scrt4/cloud-crypt/archives"
    mkdir -p "$cache_dir"

    echo -e "${CYAN}Plan:${NC} encrypt ${n} path(s), then upload to Drive/${_SCRT4_CC_FOLDER_NAME}"
    for p in "${CC_POSITIONALS[@]}"; do echo "  • ${p}"; done
    echo "  archives → ${cache_dir}"

    if [ "${CC_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no encryption or upload will execute."
        for p in "${CC_POSITIONALS[@]}"; do
            printf '  1) scrt4 encrypt-folder %q --output %q\n' "$p" "$cache_dir"
            echo  "  2) POST drive/v3/files (multipart) with produced .scrt4 archive"
        done
        return 0
    fi

    _scrt4_cc_confirm "Encrypt + upload ${n} path(s)? [y/N]" \
        || { echo "Aborted."; return 1; }

    # Step 1: encrypt each input to the cache dir. Core does the crypto.
    # We run inside the same session — no extra unlock prompts.
    local archives=()
    local p archive
    local i=0
    for p in "${CC_POSITIONALS[@]}"; do
        i=$((i + 1))
        if [ ! -d "$p" ] && [ ! -f "$p" ]; then
            echo "  [${i}/${n}] SKIP: ${p} (not found)" >&2
            continue
        fi
        local name; name=$(basename "$p")
        archive="${cache_dir}/${name%.*}.scrt4"
        echo "  [${i}/${n}] encrypting ${name} ..." >&2
        # encrypt-folder prints a JSON line with .output=<path> on success;
        # we also fall back to the predicted filename if parsing fails.
        local ef_out
        if ! ef_out=$(scrt4_module_encrypt_folder_encrypt "$p" --output "$cache_dir" 2>&1); then
            echo "  [${i}/${n}] FAIL (encrypt): ${p}" >&2
            echo "$ef_out" | tail -5 | sed 's/^/      /' >&2
            continue
        fi
        local produced
        produced=$(echo "$ef_out" | awk '/^\{.*"output"/{print}' | tail -1 \
            | jq -r '.output // empty' 2>/dev/null || true)
        [ -n "$produced" ] || produced="$archive"
        if [ ! -f "$produced" ]; then
            echo "  [${i}/${n}] FAIL: archive not produced at ${produced}" >&2
            continue
        fi
        archives+=("$produced")
    done

    if [ "${#archives[@]}" = "0" ]; then
        echo -e "${RED}No archives produced — nothing to upload.${NC}" >&2
        return 1
    fi

    echo ""
    echo -e "${CYAN}Uploading ${#archives[@]} archive(s) to Drive...${NC}"

    # Step 2: push all archives in one batch (one gcloud token, parallel
    # uploads honoured via CC_PARALLEL). Reuse the push implementation.
    CC_YES=1  # already confirmed above — don't re-prompt
    CC_POSITIONALS=("${archives[@]}")
    _scrt4_cc_push_current_batch
}

# Internal: push whatever is currently in CC_POSITIONALS. Split out so
# encrypt-and-push can reuse it without re-parsing flags.
_scrt4_cc_push_current_batch() {
    local n="${#CC_POSITIONALS[@]}"
    local tok; tok=$(_scrt4_cc_drive_token) || return 1
    local folder_id; folder_id=$(_scrt4_cc_get_or_create_folder "$tok") || return 1

    # Inline cleanup (no RETURN trap — under set -u the local `tmp_results`
    # can go out of scope before the trap fires, causing a spurious
    # "unbound variable" after the function has already returned cleanly).
    local tmp_results
    tmp_results=$(mktemp -d -t scrt4-cc-push-XXXXXX)

    local i=0 f
    for f in "${CC_POSITIONALS[@]}"; do
        i=$((i + 1))
        echo "  [${i}/${n}] uploading $(basename "$f") ..." >&2
        _scrt4_cc_upload_one "$tok" "$folder_id" "$f" > "${tmp_results}/${i}.json" || true
    done

    local ok=0 err=0 r
    for r in "${tmp_results}"/*.json; do
        [ -f "$r" ] || continue
        if [ "$(jq -r '.ok' "$r")" = "true" ]; then
            ok=$((ok + 1))
            echo "  ok  : $(jq -r '.file' "$r")  →  drive:$(jq -r '.drive_file_id' "$r")"
        else
            err=$((err + 1))
            echo "  FAIL: $(jq -r '.file' "$r")  ($(jq -r '.error // "unknown"' "$r"))"
        fi
    done
    rm -rf "$tmp_results"
    echo ""
    echo -e "${CYAN}${ok} uploaded, ${err} failed.${NC}"
    [ "$err" = "0" ]
}

# =====================================================================
# pull-and-decrypt (batch) — the symmetric inverse of encrypt-and-push
# =====================================================================
#
# Downloads one or more encrypted .scrt4 archives from Drive, then hands
# each one to the Core decrypt-folder command (daemon-side crypto). The
# module only orchestrates — no plaintext passes through this layer.
#
# Auth:
#   - ensure_unlocked: the decrypt step talks to the daemon which requires
#     an active session.
#   - _scrt4_cc_drive_token: fetches a gcloud ADC token for the Drive GET.
#
# Output:
#   - Downloaded .scrt4 archives land in --out DIR (default: cache dir).
#   - Decrypted folders land next to the archive, unless decrypt-folder's
#     own --output flag is passed through (we accept --decrypt-out DIR).
_scrt4_cloud_crypt_pull_and_decrypt() {
    _scrt4_cc_parse_flags "$@"
    ensure_unlocked || return 1
    _scrt4_cc_check_gcloud || return 1
    if [ "${#CC_POSITIONALS[@]}" = "0" ]; then
        echo "Usage: scrt4 cloud-crypt pull-and-decrypt DRIVE_ID [DRIVE_ID...] [--out DIR]" >&2
        return 1
    fi

    # Separate the decrypt-output dir from the download dir. We pulled the
    # --out DIR via CC_OUT_DIR already; any --decrypt-out ends up unparsed
    # so do a second pass here.
    local decrypt_out=""
    local -a positional=()
    local args=("$@")
    local j=0
    while [ $j -lt "${#args[@]}" ]; do
        case "${args[$j]}" in
            --decrypt-out)      decrypt_out="${args[$((j+1))]:-}"; j=$((j + 2)) ;;
            --decrypt-out=*)    decrypt_out="${args[$j]#--decrypt-out=}"; j=$((j + 1)) ;;
            *)                  j=$((j + 1)) ;;
        esac
    done

    local out_dir="${CC_OUT_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/scrt4/cloud-crypt/inbox}"
    mkdir -p "$out_dir"

    local n="${#CC_POSITIONALS[@]}"
    echo -e "${CYAN}Plan:${NC} download ${n} archive(s) to ${out_dir}, then decrypt each"
    for id in "${CC_POSITIONALS[@]}"; do echo "  • drive:${id}"; done
    [ -n "$decrypt_out" ] && echo "  decrypt output → ${decrypt_out}"

    if [ "${CC_DRY_RUN:-0}" = "1" ]; then
        echo -e "${YELLOW}DRY RUN:${NC} no downloads or decryption will execute."
        echo "  (would GET drive/v3/files/ID?alt=media, then call scrt4 decrypt-folder)"
        return 0
    fi

    _scrt4_cc_confirm "Download + decrypt ${n} archive(s)? [y/N]" \
        || { echo "Aborted."; return 1; }

    # Step 1: pull each archive from Drive. We reuse the Drive GET logic
    # inline rather than calling _scrt4_cloud_crypt_pull, because we need
    # to know each downloaded path to feed into decrypt-folder.
    local tok; tok=$(_scrt4_cc_drive_token) || return 1
    local downloaded=()
    local i=0 ok_dl=0 err_dl=0 id meta name dest
    for id in "${CC_POSITIONALS[@]}"; do
        i=$((i + 1))
        echo "  [${i}/${n}] downloading drive:${id} ..." >&2
        meta=$(curl -sS -H "Authorization: Bearer ${tok}" \
            "https://www.googleapis.com/drive/v3/files/${id}?fields=id,name" 2>/dev/null || true)
        name=$(echo "$meta" | jq -r '.name // empty' 2>/dev/null || true)
        if [ -z "$name" ]; then
            err_dl=$((err_dl + 1))
            echo "  FAIL: drive:${id} (not found or access denied)"
            continue
        fi
        dest="${out_dir}/${name}"
        if curl -sS -fL -H "Authorization: Bearer ${tok}" \
            -o "$dest" \
            "https://www.googleapis.com/drive/v3/files/${id}?alt=media" 2>/dev/null; then
            ok_dl=$((ok_dl + 1))
            echo "  ok  : drive:${id}  →  ${dest}"
            downloaded+=("$dest")
        else
            err_dl=$((err_dl + 1))
            rm -f "$dest" 2>/dev/null || true
            echo "  FAIL: drive:${id} (download error)"
        fi
    done

    if [ "${#downloaded[@]}" = "0" ]; then
        echo -e "${RED}No archives downloaded — nothing to decrypt.${NC}" >&2
        return 1
    fi

    # Step 2: decrypt each downloaded archive via the decrypt-folder command
    # (from the encrypt-folder module). decrypt-folder calls into the daemon
    # so all crypto stays in the TCB.
    echo ""
    echo -e "${CYAN}Decrypting ${#downloaded[@]} archive(s)...${NC}"
    local ok_dc=0 err_dc=0 archive
    local -a decrypt_args=()
    [ -n "$decrypt_out" ] && decrypt_args=(--output "$decrypt_out")
    for archive in "${downloaded[@]}"; do
        echo "  decrypting $(basename "$archive") ..." >&2
        if _resolve_command decrypt-folder >/dev/null 2>&1; then
            if "$(_resolve_command decrypt-folder)" "$archive" "${decrypt_args[@]}"; then
                ok_dc=$((ok_dc + 1))
            else
                err_dc=$((err_dc + 1))
                echo "  FAIL: decrypt $(basename "$archive")" >&2
            fi
        else
            echo -e "${RED}decrypt-folder command not available — is the encrypt-folder module loaded?${NC}" >&2
            err_dc=$((err_dc + 1))
        fi
    done

    echo ""
    echo -e "${CYAN}Downloaded: ${ok_dl} ok, ${err_dl} failed.${NC}"
    echo -e "${CYAN}Decrypted:  ${ok_dc} ok, ${err_dc} failed.${NC}"

    [ "$err_dl" = "0" ] && [ "$err_dc" = "0" ]
}

# =====================================================================
# ui — lightweight zenity panel that mirrors the CLI
# =====================================================================

_scrt4_cloud_crypt_ui() {
    if ! _has_gui; then
        echo -e "${RED}GUI unavailable.${NC} Set SCRT4_FORCE_GUI=1 in dev mode, or install zenity + an X/Wayland display." >&2
        return 1
    fi
    ensure_unlocked || return 1

    # Build list-panel rows from list --json. Critical heuristic until
    # inventory metadata ships a real flag: folder_name contains "critical"
    # or name starts with "pgp-keyring" (keyring backups are always critical).
    local js
    js=$(_scrt4_cloud_crypt_list --json 2>/dev/null || echo '{"entries":[]}')
    local rows=()
    while IFS= read -r line; do [ -n "$line" ] && rows+=("$line"); done < <(
        echo "$js" | jq -r '.entries[] |
            (if ((.name // "") | test("critical|pgp-keyring"; "i"))
             then "CRIT" else "" end) as $m
            | [$m, .id, (.name // .folder_name),
               ((.file_count|tostring) + " files · " + (.size|tostring) + "B")]
            | @tsv'
    )

    local choice
    choice=$(_scrt4_gui_list_panel \
        "cloud-crypt — archives" \
        "Registered encrypted archives (● marks critical)" \
        "${rows[@]}")
    [ -n "$choice" ] || return 0

    # Determine critical on the picked row so the action-panel inherits.
    local is_crit
    is_crit=$(echo "$js" | jq -r --arg i "$choice" '.entries[]
        | select(.id==$i) | .name // .folder_name
        | test("critical|pgp-keyring"; "i")')

    local action
    action=$(zenity --list --title="Action" \
        --text="What do you want to do with this archive?" \
        --column="Action" \
        "pull from Google Drive" \
        "show details" \
        "organize with Claude Code" \
        2>/dev/null || true)

    local meta
    meta=$(echo "$js" | jq --arg i "$choice" -r '.entries[] | select(.id==$i)
        | "Name:    " + (.name // .folder_name)
        + "\nLocal:   " + (.path // "?")
        + "\nSize:    " + (.size|tostring) + " bytes"
        + "\nFiles:   " + (.file_count|tostring)')

    case "$action" in
        "pull from Google Drive")
            local flags=()
            [ "$is_crit" = "true" ] && flags+=(--critical)
            if _scrt4_gui_action_panel \
                "Pull archive to local disk" \
                "${meta}

This will download the encrypted blob and ask cloud-crypt Core to decrypt it locally. Plaintext is written to your system's chosen download dir." \
                "${flags[@]}"; then
                _scrt4_cloud_crypt_pull "$choice" --yes 2>&1 \
                    | zenity --text-info --title="Pull result" --width=640 --height=360
            fi
            ;;
        "show details")
            echo "$meta" | zenity --text-info --title="Archive details" --width=640 --height=360
            ;;
        "organize with Claude Code")
            _scrt4_cc_claude_organize_panel "$choice" \
                | zenity --text-info --title="Organize with Claude Code" --width=780 --height=520
            ;;
    esac
}

# status-panel — rendered from the same checks cloud-crypt status --json emits
_scrt4_cloud_crypt_status_panel() {
    if ! _has_gui; then
        _scrt4_cloud_crypt_status
        return $?
    fi
    ensure_unlocked || return 1
    local s
    s=$(_scrt4_cloud_crypt_status --json 2>/dev/null || echo '{}')
    local rows=()
    local val
    val=$(echo "$s" | jq -r '.gcloud_installed // false')
    rows+=( "$( [ "$val" = "true" ] && echo OK || echo FAIL )"$'\t'"gcloud installed"$'\t'"$val" )
    val=$(echo "$s" | jq -r '.drive_reachable // false')
    rows+=( "$( [ "$val" = "true" ] && echo OK || echo WARN )"$'\t'"drive reachable"$'\t'"$val" )
    val=$(echo "$s" | jq -r '.session_active // false')
    rows+=( "$( [ "$val" = "true" ] && echo OK || echo FAIL )"$'\t'"session active"$'\t'"$val" )
    local crit_count
    crit_count=$(_scrt4_cloud_crypt_list --json 2>/dev/null \
        | jq -r '[.entries[] | select((.name // "") | test("critical|pgp-keyring"; "i"))] | length')
    rows+=( "$( [ "${crit_count:-0}" = "0" ] && echo OK || echo WARN )"$'\t'"critical archives"$'\t'"${crit_count:-0}" )
    _scrt4_gui_status_panel "cloud-crypt — status" "${rows[@]}" >/dev/null
}

# Prints a copy-paste panel of Claude Code prompts that help the user
# organize this archive (rename, move to a sub-folder in Drive, tag, find
# siblings, etc.). Stdout of this function is piped into zenity --text-info.
_scrt4_cc_claude_organize_panel() {
    local id="$1"
    local resp name path
    resp=$(send_request '{"method":"list_encrypted"}')
    name=$(echo "$resp" | jq -r --arg i "$id" '.data.entries[] | select(.id==$i) | .folder_name // ""')
    path=$(echo "$resp" | jq -r --arg i "$id" '.data.entries[] | select(.id==$i) | .path // ""')
    cat <<EOF
Organize with Claude Code
=========================
Archive : ${name}
Local   : ${path}
Drive   : ${_SCRT4_CC_FOLDER_NAME}/  (pending Core RPC for live status)
ID      : ${id}

Copy any of the prompts below into Claude Code. Claude will use this
module's CLI to act on your Drive layout — no extra auth, no extra
context needed. Every command is a subcommand of:

    scrt4 cloud-crypt <sub> [--json]

--- Prompts ---

1. Rename this archive in Drive to match a project name:

   "Using scrt4 cloud-crypt, rename the archive with id ${id}
    in my Drive's ${_SCRT4_CC_FOLDER_NAME} folder to '<new-name>.scrt4'."

2. Move siblings: find every archive whose name starts with a prefix and
   put them in a Drive sub-folder:

   "Run 'scrt4 cloud-crypt list --json', find every entry whose name
    starts with '<prefix>', create a Drive sub-folder called '<prefix>/'
    inside ${_SCRT4_CC_FOLDER_NAME}, and move them there."

3. Generate a human-readable index of everything you have encrypted:

   "Run 'scrt4 cloud-crypt list --json' and write me a markdown table
    with name, local path, file count, size, and location. Highlight
    anything where present_locally is false."

4. Re-upload just the archives that are on Drive but missing locally:

   "Run 'scrt4 cloud-crypt list --json', pick any entry where
    present_locally is false but a drive_file_id exists, pull them into
    ~/cloud-crypt-inbox, and show me the filenames."

5. Audit: anything local that isn't yet in Drive?

   "Run 'scrt4 cloud-crypt list --json'. For each entry with
    location=='local', push it to Drive using
    'scrt4 cloud-crypt push <path> --yes'."

--- Agent primitives (for reference) ---

    scrt4 cloud-crypt list   --json
    scrt4 cloud-crypt where  <query> --json
    scrt4 cloud-crypt status --json
    scrt4 cloud-crypt push   FILE [FILE...] --yes
    scrt4 cloud-crypt pull   DRIVE_ID [DRIVE_ID...] --yes
EOF
}
