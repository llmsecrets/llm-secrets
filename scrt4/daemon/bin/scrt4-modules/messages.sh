# shellcheck shell=bash
# scrt4-module: messages
# version: 1
# api: 1
# tcb: false
# deps: jq python3 zenity
# commands: messages
# requires:
# reveals: personal_google_workspace
#
# Messages — unified action-item inbox across WhatsApp, Telegram, and Gmail.
#
#   scrt4 messages                     Open the zenity GUI (default)
#   scrt4 messages scan                Extract new action items from whitelisted sources
#   scrt4 messages view                Alias for the default (open GUI)
#   scrt4 messages list [--new|--all]  CLI listing (scriptable)
#   scrt4 messages promote ID...       Mark as promoted and push to CRM
#   scrt4 messages dismiss ID...       Mark as dismissed
#   scrt4 messages whitelist add ENTRY
#   scrt4 messages whitelist remove ENTRY
#   scrt4 messages whitelist list
#   scrt4 messages help
#
# Whitelist entry grammar:
#   whatsapp:CHAT_DIR_NAME            e.g. whatsapp:Cody Pearce
#   telegram:CHAT_DIR_NAME            e.g. telegram:Ajna __ Lendvest
#   gmail:sender:EMAIL                e.g. gmail:sender:brent@selborneconsulting.com
#   gmail:label:LABEL                 e.g. gmail:label:action-required
#
# Data flow (no coupling to archivers — the module just reads their output):
#   ~/.whatsapp-archive/chats/<name>/live.jsonl    (Baileys live capture)
#   ~/.telegram-archive/chats/<name>/live.jsonl    (Telethon live capture)
#   Gmail API /users/me/messages (live, newer_than:30d, whitelist-filtered)
#
# Local state (under $CONFIG_DIR/messages/):
#   whitelist.txt             one entry per line
#   action_items.jsonl        append-only log, one action item per line
#   state.json                last-scan timestamp per source
#
# Extraction heuristic (ported from the ingest-tasks skill):
#   - starts with an imperative verb (pay, call, buy, create, send, review...)
#   - starts with @name delegation
#   - numbered list (1) 2) 1.)
#   - AND under 500 chars, AND not URL-only, AND not media-only
#
# Gmail auth: uses personal_google_workspace (OAuth refresh token) — NOT the
# service account. If the secret isn't in the vault, Gmail scan is skipped
# cleanly with a warning. WA and TG scans do not require any secret.

scrt4_module_messages_register() {
    _register_command messages scrt4_module_messages_dispatch
}

scrt4_module_messages_dispatch() {
    case "${1:-}" in
        help|-h|--help) _scrt4_messages_help ;;
        scan)      shift; _scrt4_messages_scan "$@" ;;
        view|gui)  shift; _scrt4_messages_gui "$@" ;;
        list)      shift; _scrt4_messages_list "$@" ;;
        promote)   shift; _scrt4_messages_promote "$@" ;;
        dismiss)   shift; _scrt4_messages_dismiss "$@" ;;
        whitelist) shift; _scrt4_messages_whitelist_cmd "$@" ;;
        "") _scrt4_messages_gui ;;
        *) _scrt4_messages_help; return 2 ;;
    esac
}

_scrt4_messages_help() {
    cat <<'EOF'
scrt4 messages — unified action-item inbox across WhatsApp, Telegram, Gmail

USAGE:
    scrt4 messages                       Open the zenity GUI (default)
    scrt4 messages scan                  Extract action items from whitelisted sources
    scrt4 messages list [--new|--all]    Print action items (for scripts)
    scrt4 messages promote ID...         Mark as promoted and push to CRM
    scrt4 messages dismiss ID...         Mark as dismissed
    scrt4 messages whitelist add ENTRY
    scrt4 messages whitelist remove ENTRY
    scrt4 messages whitelist list

WHITELIST GRAMMAR:
    whatsapp:CHAT_NAME             e.g. whatsapp:Cody Pearce
    telegram:CHAT_NAME             e.g. telegram:Ajna __ Lendvest
    gmail:sender:EMAIL             e.g. gmail:sender:brent@selborneconsulting.com
    gmail:label:LABEL              e.g. gmail:label:action-required

EXAMPLES:
    scrt4 messages whitelist add "whatsapp:Cody Pearce"
    scrt4 messages whitelist add "gmail:sender:brent@selborneconsulting.com"
    scrt4 messages scan
    scrt4 messages               # opens the GUI

SECRETS USED:
    personal_google_workspace          (optional — Gmail scan is skipped if absent)
EOF
}

# ── Paths ──────────────────────────────────────────────────────────────

_scrt4_messages_configdir() {
    local d="${CONFIG_DIR}/messages"
    mkdir -p "$d"
    echo "$d"
}
_scrt4_messages_whitelist_path() { echo "$(_scrt4_messages_configdir)/whitelist.txt"; }
_scrt4_messages_items_path()     { echo "$(_scrt4_messages_configdir)/action_items.jsonl"; }
_scrt4_messages_state_path()     { echo "$(_scrt4_messages_configdir)/state.json"; }

_scrt4_messages_ensure_files() {
    local wl items state
    wl=$(_scrt4_messages_whitelist_path)
    items=$(_scrt4_messages_items_path)
    state=$(_scrt4_messages_state_path)
    [ -f "$wl" ]    || : > "$wl"
    [ -f "$items" ] || : > "$items"
    [ -f "$state" ] || echo '{}' > "$state"
}

# ── Whitelist CLI ──────────────────────────────────────────────────────

_scrt4_messages_whitelist_cmd() {
    _scrt4_messages_ensure_files
    case "${1:-}" in
        add)    shift; _scrt4_messages_whitelist_add "$@" ;;
        remove|rm) shift; _scrt4_messages_whitelist_remove "$@" ;;
        list|show|ls|"") _scrt4_messages_whitelist_list ;;
        *) echo "usage: scrt4 messages whitelist add|remove|list [ENTRY]" >&2; return 2 ;;
    esac
}

_scrt4_messages_whitelist_add() {
    local entry="${1:-}"
    if [ -z "$entry" ]; then
        echo "usage: scrt4 messages whitelist add ENTRY" >&2
        echo "  e.g. scrt4 messages whitelist add 'whatsapp:Cody Pearce'" >&2
        return 2
    fi
    if ! _scrt4_messages_whitelist_validate "$entry"; then
        return 2
    fi
    local wl
    wl=$(_scrt4_messages_whitelist_path)
    if grep -Fxq -- "$entry" "$wl" 2>/dev/null; then
        echo "already present: $entry"
        return 0
    fi
    echo "$entry" >> "$wl"
    echo "added: $entry"
}

_scrt4_messages_whitelist_remove() {
    local entry="${1:-}"
    [ -z "$entry" ] && { echo "usage: scrt4 messages whitelist remove ENTRY" >&2; return 2; }
    local wl
    wl=$(_scrt4_messages_whitelist_path)
    if ! grep -Fxq -- "$entry" "$wl" 2>/dev/null; then
        echo "not in whitelist: $entry"
        return 0
    fi
    local tmp; tmp=$(mktemp)
    grep -Fxv -- "$entry" "$wl" > "$tmp" || true
    mv "$tmp" "$wl"
    echo "removed: $entry"
}

_scrt4_messages_whitelist_list() {
    local wl
    wl=$(_scrt4_messages_whitelist_path)
    if [ ! -s "$wl" ]; then
        echo "(whitelist is empty — use 'scrt4 messages whitelist add ENTRY')"
        return 0
    fi
    cat "$wl"
}

_scrt4_messages_whitelist_validate() {
    local e="$1"
    case "$e" in
        whatsapp:?*|telegram:?*|gmail:sender:?*|gmail:label:?*) return 0 ;;
    esac
    echo "error: invalid whitelist entry: $e" >&2
    echo "  valid: whatsapp:NAME | telegram:NAME | gmail:sender:EMAIL | gmail:label:LABEL" >&2
    return 1
}

# ── Scan — all three services ──────────────────────────────────────────

_scrt4_messages_scan() {
    _scrt4_messages_ensure_files
    echo "[scan] starting..."
    local wa_count tg_count gm_count
    wa_count=$(_scrt4_messages_scan_whatsapp)
    tg_count=$(_scrt4_messages_scan_telegram)
    gm_count=$(_scrt4_messages_scan_gmail)

    local state
    state=$(_scrt4_messages_state_path)
    local now
    now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    jq --arg t "$now" '. + {last_scan: $t}' "$state" > "$state.tmp" && mv "$state.tmp" "$state"

    local total=$((wa_count + tg_count + gm_count))
    echo "[scan] done — new items: whatsapp=$wa_count telegram=$tg_count gmail=$gm_count (total $total)"
}

# Generic archive scanner used by WA + TG. $1 = source name ("whatsapp"/"telegram"),
# $2 = root dir (e.g. ~/.whatsapp-archive/chats). Prints the count of NEW items added.
_scrt4_messages_scan_jsonl_archive() {
    local source_name="$1"
    local root="$2"
    if [ ! -d "$root" ]; then
        echo 0
        return 0
    fi
    local wl items
    wl=$(_scrt4_messages_whitelist_path)
    items=$(_scrt4_messages_items_path)

    # Collect whitelisted chat dir names for this source. Tab-separated
    # to tolerate spaces and punctuation in chat names.
    local whitelisted
    whitelisted=$(awk -F: -v src="$source_name" '
        $1 == src && NF >= 2 {
            sub("^" src ":", "", $0)
            print $0
        }' "$wl")
    if [ -z "$whitelisted" ]; then
        echo 0
        return 0
    fi

    # One python call per source — reads each whitelisted chat's live.jsonl,
    # applies extraction, prints one JSON per candidate item. Bash then
    # appends new items to action_items.jsonl with dedup.
    local tmp_wl; tmp_wl=$(mktemp)
    printf '%s\n' "$whitelisted" > "$tmp_wl"
    local added
    added=$(python3 - "$source_name" "$root" "$items" "$tmp_wl" <<'PYEOF'
import sys, os, json, hashlib, re
from datetime import datetime, timezone, timedelta

source = sys.argv[1]
root   = sys.argv[2]
items_path = sys.argv[3]
wl_path    = sys.argv[4]
with open(wl_path) as f:
    chats = [c.strip() for c in f.read().splitlines() if c.strip()]

cutoff = datetime.now(timezone.utc) - timedelta(days=30)

# Extraction heuristic.
VERBS = (
    r"pay|call|buy|create|make|send|review|find|message|follow up|deploy|"
    r"add|edit|fix|text|go to|meet|sign up|design|check|update|backup|"
    r"finalize|contact|reach out|outreach|run|use|have|clean|write|email|"
    r"schedule|prepare"
)
RE_VERB = re.compile(rf"^\s*({VERBS})\b", re.IGNORECASE)
RE_ATNAME = re.compile(r"^\s*@[A-Za-z][A-Za-z0-9_]*")
RE_NUMBERED = re.compile(r"^\s*[0-9]+[.)]\s")
RE_URL_ONLY = re.compile(r"^\s*https?://[^\s]+\s*$")

def looks_like_task(text: str) -> bool:
    if not text: return False
    if len(text) > 500: return False
    if text.strip() == "<Media omitted>": return False
    if RE_URL_ONLY.match(text): return False
    if RE_VERB.match(text): return True
    if RE_ATNAME.match(text): return True
    if RE_NUMBERED.match(text): return True
    return False

def parse_date(s: str):
    if not s: return None
    try:
        s = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

# Load existing ids for dedup
existing = set()
if os.path.exists(items_path):
    with open(items_path) as f:
        for line in f:
            try:
                existing.add(json.loads(line)["id"])
            except Exception:
                pass

added = 0
for chat in chats:
    chat_dir = os.path.join(root, chat)
    if not os.path.isdir(chat_dir):
        continue
    jsonl = os.path.join(chat_dir, "live.jsonl")
    if not os.path.isfile(jsonl):
        continue
    with open(jsonl, encoding="utf-8", errors="replace") as f:
        for raw in f:
            raw = raw.strip()
            if not raw: continue
            try:
                m = json.loads(raw)
            except Exception:
                continue
            text = m.get("text") or ""
            if not looks_like_task(text):
                continue
            dt = parse_date(m.get("date", ""))
            if dt is None or dt < cutoff:
                continue
            msgid = str(m.get("id", ""))
            if not msgid:
                continue
            stable = hashlib.sha1(f"{source}:{chat}:{msgid}".encode()).hexdigest()[:16]
            aid = f"ai_{stable}"
            if aid in existing:
                continue
            sender = m.get("pushName") or m.get("from") or ""
            if m.get("fromMe"):
                sender = "Me"
            out = {
                "id": aid,
                "source": source,
                "thread": chat,
                "from": sender,
                "date": m.get("date", ""),
                "text": text,
                "raw_text": text,
                "status": "new",
                "promoted_at": None,
                "crm_task_id": None,
            }
            with open(items_path, "a", encoding="utf-8") as out_f:
                out_f.write(json.dumps(out, ensure_ascii=False) + "\n")
            existing.add(aid)
            added += 1

print(added)
PYEOF
    )
    rm -f "$tmp_wl"
    # Python may print nothing on error; guard with default 0 and take last line.
    echo "${added:-0}" | tail -n1
}

_scrt4_messages_scan_whatsapp() {
    _scrt4_messages_scan_jsonl_archive whatsapp "$HOME/.whatsapp-archive/chats"
}

_scrt4_messages_scan_telegram() {
    _scrt4_messages_scan_jsonl_archive telegram "$HOME/.telegram-archive/chats"
}

_scrt4_messages_scan_gmail() {
    local wl items
    wl=$(_scrt4_messages_whitelist_path)
    items=$(_scrt4_messages_items_path)

    local senders labels
    senders=$(awk -F: '$1=="gmail" && $2=="sender" && NF>=3 {for(i=3;i<=NF;i++){printf "%s%s",(i==3?"":":"),$i} print ""}' "$wl")
    labels=$(awk -F: '$1=="gmail" && $2=="label"  && NF>=3 {for(i=3;i<=NF;i++){printf "%s%s",(i==3?"":":"),$i} print ""}' "$wl")

    if [ -z "$senders" ] && [ -z "$labels" ]; then
        echo 0
        return 0
    fi

    local creds
    creds=$(_module_reveal personal_google_workspace 2>/dev/null) || {
        echo "[scan] gmail: personal_google_workspace not in vault, skipping" >&2
        echo 0
        return 0
    }

    # Stage creds + senders + labels in a temp file (0600) so the secret
    # never touches argv / ps output. Python reads it and unlinks immediately.
    local tmp_cfg; tmp_cfg=$(mktemp)
    chmod 600 "$tmp_cfg"
    {
        printf '%s\n' "$creds"
        printf '%s\n' "---SENDERS---"
        printf '%s\n' "$senders"
        printf '%s\n' "---LABELS---"
        printf '%s\n' "$labels"
    } > "$tmp_cfg"

    local added
    added=$(python3 - "$items" "$tmp_cfg" <<'PYEOF'
import sys, os, json, hashlib, re, urllib.request, urllib.parse
from datetime import datetime, timezone, timedelta

items_path = sys.argv[1]
cfg_path   = sys.argv[2]

with open(cfg_path) as f:
    blob = f.read()
# Unlink the config file immediately — secret stays only in process memory.
try: os.unlink(cfg_path)
except Exception: pass

# Split the blob back into its sections.
creds_raw, _, rest = blob.partition("---SENDERS---\n")
senders_raw, _, labels_raw = rest.partition("---LABELS---\n")
creds_raw = creds_raw.rstrip("\n")

def pick(pat):
    m = re.search(pat, creds_raw)
    return m.group(1).strip() if m else ""

client_id     = pick(r"client_id[:=]\s*([^,}\s]+)")
client_secret = pick(r"client_secret[:=]\s*([^,}\s]+)")
refresh_token = pick(r"refresh_token[:=]\s*([^,}\s]+)")
token_uri     = pick(r"token_uri[:=]\s*([^,}\s]+)") or "https://oauth2.googleapis.com/token"

if not (client_id and client_secret and refresh_token):
    print("[scan] gmail: could not parse personal_google_workspace (missing fields)", file=sys.stderr)
    print(0); sys.exit(0)

data = urllib.parse.urlencode({
    "client_id": client_id,
    "client_secret": client_secret,
    "refresh_token": refresh_token,
    "grant_type": "refresh_token",
}).encode()

try:
    req = urllib.request.Request(token_uri, data=data, method="POST")
    access_token = json.loads(urllib.request.urlopen(req, timeout=15).read())["access_token"]
except Exception as e:
    print(f"[scan] gmail: token exchange failed: {e}", file=sys.stderr)
    print(0); sys.exit(0)

senders = [s.strip() for s in senders_raw.splitlines() if s.strip()]
labels  = [l.strip() for l in labels_raw.splitlines() if l.strip()]

# Build queries. senders OR'd together with newer_than:30d;
# labels handled as separate queries (labels with spaces don't OR cleanly in Gmail search).
queries = []
if senders:
    from_q = " OR ".join(f"from:{s}" for s in senders)
    queries.append(f"newer_than:30d ({from_q})")
for lab in labels:
    queries.append(f'newer_than:30d label:"{lab}"')

def api_get(url):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {access_token}"})
    return json.loads(urllib.request.urlopen(req, timeout=20).read())

def list_ids(q):
    ids, token = [], None
    while True:
        params = {"q": q, "maxResults": "100"}
        if token: params["pageToken"] = token
        url = "https://gmail.googleapis.com/gmail/v1/users/me/messages?" + urllib.parse.urlencode(params)
        try:
            resp = api_get(url)
        except Exception as e:
            print(f"[scan] gmail: list failed: {e}", file=sys.stderr)
            return ids
        for m in resp.get("messages", []):
            ids.append(m["id"])
        token = resp.get("nextPageToken")
        if not token: break
    return ids

# Load existing ids for dedup
existing = set()
if os.path.exists(items_path):
    with open(items_path) as f:
        for line in f:
            try: existing.add(json.loads(line)["id"])
            except Exception: pass

msg_ids = set()
for q in queries:
    for mid in list_ids(q):
        msg_ids.add(mid)

added = 0
for mid in msg_ids:
    stable = hashlib.sha1(f"gmail::{mid}".encode()).hexdigest()[:16]
    aid = f"ai_{stable}"
    if aid in existing:
        continue
    try:
        url = (f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}"
               "?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date")
        m = api_get(url)
    except Exception:
        continue
    headers = {h["name"].lower(): h["value"] for h in m.get("payload", {}).get("headers", [])}
    out = {
        "id": aid,
        "source": "gmail",
        "thread": headers.get("from", ""),
        "from": headers.get("from", ""),
        "date": headers.get("date", ""),
        "text": headers.get("subject", "") or m.get("snippet", "")[:200],
        "raw_text": m.get("snippet", ""),
        "status": "new",
        "promoted_at": None,
        "crm_task_id": None,
    }
    with open(items_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(out, ensure_ascii=False) + "\n")
    existing.add(aid)
    added += 1

print(added)
PYEOF
    )
    # Best-effort unlink (python already unlinked; rm -f won't complain).
    rm -f "$tmp_cfg"
    unset creds
    echo "${added:-0}" | tail -n1
}

# ── CLI listing ────────────────────────────────────────────────────────

_scrt4_messages_list() {
    _scrt4_messages_ensure_files
    local filter="new"
    case "${1:-}" in
        --new)       filter="new" ;;
        --all)       filter="all" ;;
        --promoted)  filter="promoted" ;;
        --dismissed) filter="dismissed" ;;
        "") ;;
        *) echo "usage: scrt4 messages list [--new|--all|--promoted|--dismissed]" >&2; return 2 ;;
    esac
    local items
    items=$(_scrt4_messages_items_path)
    if [ ! -s "$items" ]; then
        echo "(no action items — run 'scrt4 messages scan')"
        return 0
    fi
    python3 - "$items" "$filter" <<'PYEOF'
import sys, json
items_path, filt = sys.argv[1], sys.argv[2]
rows = []
with open(items_path) as f:
    for line in f:
        try:
            it = json.loads(line)
        except Exception:
            continue
        if filt != "all" and it.get("status") != filt:
            continue
        rows.append(it)
if not rows:
    print(f"(no items matching --{filt})")
    sys.exit(0)
for it in rows:
    print(f"{it['id']}  [{it['source']:9}] {it['date'][:10]} {it['thread'][:24]:24} | {it['text'][:80]}")
PYEOF
}

# ── Promote / dismiss ──────────────────────────────────────────────────

_scrt4_messages_promote() {
    _scrt4_messages_ensure_files
    if [ $# -eq 0 ]; then
        echo "usage: scrt4 messages promote ID [ID...]" >&2
        return 2
    fi
    local items; items=$(_scrt4_messages_items_path)
    local have_crm=1
    command -v crm >/dev/null 2>&1 || have_crm=0
    local id task_text promoted=0
    for id in "$@"; do
        task_text=$(python3 - "$items" "$id" <<'PYEOF'
import sys, json
p, i = sys.argv[1], sys.argv[2]
with open(p) as f:
    for line in f:
        try: it = json.loads(line)
        except Exception: continue
        if it.get("id") == i:
            print(it.get("text",""))
            sys.exit(0)
sys.exit(1)
PYEOF
        ) || { echo "  [skip] $id not found" >&2; continue; }
        local crm_task_id=""
        if [ "$have_crm" = "1" ] && [ -n "$task_text" ]; then
            if crm task add "$task_text" --flair suggested >/dev/null 2>&1; then
                crm_task_id="promoted"
            else
                echo "  [warn] $id: crm task add failed — marking local status only" >&2
            fi
        fi
        _scrt4_messages_set_status "$id" promoted "$crm_task_id"
        promoted=$((promoted+1))
        echo "  promoted: $id — $task_text"
    done
    echo "[promote] $promoted item(s) promoted"
}

_scrt4_messages_dismiss() {
    _scrt4_messages_ensure_files
    if [ $# -eq 0 ]; then
        echo "usage: scrt4 messages dismiss ID [ID...]" >&2
        return 2
    fi
    local dismissed=0 id
    for id in "$@"; do
        if _scrt4_messages_set_status "$id" dismissed ""; then
            echo "  dismissed: $id"
            dismissed=$((dismissed+1))
        else
            echo "  [skip] $id not found" >&2
        fi
    done
    echo "[dismiss] $dismissed item(s) dismissed"
}

# _scrt4_messages_set_status ID new_status crm_task_id
_scrt4_messages_set_status() {
    local items target_id new_status crm_task
    items=$(_scrt4_messages_items_path)
    target_id="$1"
    new_status="$2"
    crm_task="${3:-}"
    python3 - "$items" "$target_id" "$new_status" "$crm_task" <<'PYEOF'
import sys, json, os
from datetime import datetime, timezone
items_path, tid, status, crm = sys.argv[1:5]
found = False
tmp = items_path + ".tmp"
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
with open(items_path) as fin, open(tmp, "w", encoding="utf-8") as fout:
    for line in fin:
        try: it = json.loads(line)
        except Exception:
            fout.write(line); continue
        if it.get("id") == tid:
            it["status"] = status
            if status == "promoted":
                it["promoted_at"] = now
                if crm: it["crm_task_id"] = crm
            found = True
        fout.write(json.dumps(it, ensure_ascii=False) + "\n")
os.replace(tmp, items_path)
sys.exit(0 if found else 1)
PYEOF
}

# ── zenity GUI ─────────────────────────────────────────────────────────

_scrt4_messages_gui() {
    if ! command -v zenity >/dev/null 2>&1; then
        echo "error: zenity not installed — install it or use the CLI subcommands" >&2
        return 2
    fi
    _scrt4_messages_ensure_files

    local show="new"
    while :; do
        local tmp_rows; tmp_rows=$(mktemp)
        _scrt4_messages_rows_for_gui "$show" > "$tmp_rows"
        if [ ! -s "$tmp_rows" ]; then
            local prompt="No items matching status=$show.\n\nRescan sources?"
            if zenity --question --no-wrap --title="scrt4 messages" --text="$prompt" \
                      --ok-label="Rescan" --cancel-label="Close" --extra-button="Whitelist" \
                      2>/dev/null; then
                _scrt4_messages_scan >/dev/null 2>&1 || true
                rm -f "$tmp_rows"
                continue
            fi
            local status=$?
            if [ "$status" = "1" ]; then
                # Either cancel or extra button — check stderr path not used, bail
                :
            fi
            rm -f "$tmp_rows"
            return 0
        fi

        local title
        if [ "$show" = "new" ]; then
            title="scrt4 messages — $(wc -l <"$tmp_rows") new item(s)"
        else
            title="scrt4 messages — $(wc -l <"$tmp_rows") item(s) [$show]"
        fi

        # zenity --list --checklist — column 1 is the pick checkbox, column 2 is
        # the hidden ID (printed on OK), the rest are display.
        local selected
        selected=$(awk -F'\t' '
            BEGIN { OFS="\n" }
            { print "FALSE", $1, $2, $3, $4, $5, $6 }
        ' "$tmp_rows" \
          | zenity --list --checklist --multiple --width=1100 --height=600 \
                --title="$title" \
                --text="Pick items, click an action. Rescan pulls fresh WA/TG/Gmail data." \
                --column="" --column="ID" --column="Date" --column="Src" --column="From" --column="Thread" --column="Action" \
                --hide-column=2 --print-column=2 --separator="|" \
                --ok-label="Act on Selected" \
                --cancel-label="Close" \
                --extra-button="Rescan" \
                --extra-button="Show All" \
                --extra-button="Show New" \
                --extra-button="Whitelist" \
                2>/dev/null)
        local rc=$?
        rm -f "$tmp_rows"

        if [ $rc -ne 0 ]; then
            case "$selected" in
                Rescan)
                    _scrt4_messages_scan >/dev/null 2>&1 || true
                    continue
                    ;;
                "Show All")  show="all"; continue ;;
                "Show New")  show="new"; continue ;;
                Whitelist)
                    _scrt4_messages_gui_whitelist
                    continue
                    ;;
                "") return 0 ;;    # Close
                *)  return 0 ;;
            esac
        fi

        [ -z "$selected" ] && continue

        local ids
        ids=$(printf '%s' "$selected" | tr '|' '\n' | grep -v '^$')
        local n; n=$(printf '%s\n' "$ids" | wc -l)
        local preview
        preview=$(_scrt4_messages_preview_for_ids "$ids")

        local action
        action=$(zenity --question --no-wrap --title="Action on $n item(s)" \
                --text="$preview" \
                --ok-label="Promote to CRM" \
                --cancel-label="Back" \
                --extra-button="Dismiss" \
                2>/dev/null)
        local qrc=$?
        if [ $qrc -eq 0 ]; then
            # shellcheck disable=SC2086
            _scrt4_messages_promote $ids >/dev/null 2>&1 || true
            zenity --info --no-wrap --text="Promoted $n item(s)." 2>/dev/null || true
        elif [ "$action" = "Dismiss" ]; then
            # shellcheck disable=SC2086
            _scrt4_messages_dismiss $ids >/dev/null 2>&1 || true
            zenity --info --no-wrap --text="Dismissed $n item(s)." 2>/dev/null || true
        fi
        # back to main loop
    done
}

# Tab-separated rows for the GUI: id \t date \t src \t from \t thread \t text
_scrt4_messages_rows_for_gui() {
    local status="$1"
    local items; items=$(_scrt4_messages_items_path)
    python3 - "$items" "$status" <<'PYEOF'
import sys, json
p, filt = sys.argv[1], sys.argv[2]
with open(p) as f:
    for line in f:
        try: it = json.loads(line)
        except Exception: continue
        if filt == "new" and it.get("status") != "new": continue
        def clip(s, n): return (s or "")[:n].replace("\t"," ").replace("|"," ")
        print("\t".join([
            it["id"],
            clip(it.get("date",""),10),
            clip(it.get("source",""),8),
            clip(it.get("from",""),20),
            clip(it.get("thread",""),24),
            clip(it.get("text",""),90),
        ]))
PYEOF
}

_scrt4_messages_preview_for_ids() {
    local ids="$1"
    local items; items=$(_scrt4_messages_items_path)
    local tmp_ids; tmp_ids=$(mktemp)
    printf '%s\n' "$ids" > "$tmp_ids"
    python3 - "$items" "$tmp_ids" <<'PYEOF'
import sys, json
items_path = sys.argv[1]
ids_path   = sys.argv[2]
with open(ids_path) as f:
    ids = [x.strip() for x in f.read().splitlines() if x.strip()]
want = set(ids)
found = []
with open(items_path) as f:
    for line in f:
        try: it = json.loads(line)
        except Exception: continue
        if it.get("id") in want:
            found.append(it)
if not found:
    print("No items selected.")
    sys.exit(0)
print(f"Act on {len(found)} selected item(s):\n")
for it in found:
    txt = (it.get("text","") or "")[:100]
    print(f"  [{it.get('source','')}] {it.get('thread','')[:20]} — {txt}")
PYEOF
    rm -f "$tmp_ids"
}

_scrt4_messages_gui_whitelist() {
    local wl; wl=$(_scrt4_messages_whitelist_path)
    local current
    current=$(cat "$wl" 2>/dev/null || true)
    local edited
    edited=$(zenity --text-info --editable --width=700 --height=500 \
             --title="scrt4 messages — whitelist" \
             --filename="$wl" 2>/dev/null) || return 0
    printf '%s' "$edited" > "$wl"
    zenity --info --no-wrap --text="Whitelist updated." 2>/dev/null || true
}
