#!/usr/bin/env bash
# scrt4-zenity-macos.sh — minimal zenity → osascript shim for scrt4 on macOS.
#
# Installed as ${INSTALL_DIR}/zenity so scrt4-core and modules keep calling
# `zenity …` unchanged. Maps the flag subset scrt4 uses onto osascript
# (AppleScript), which ships built-in on every Mac and renders native Cocoa
# dialogs — no XQuartz, no brew gtk+3, no extra installs.
#
# Priority paths (fully supported):
#   --entry          single-line text input        → display dialog + default answer
#   --question       Yes/No prompt                 → display dialog + buttons
#   --info           info message                  → display dialog (OK)
#   --error          error message                 → display alert as critical
#   --text-info      multi-line viewer/editor      → TextEdit round-trip (editable)
#                                                  → osascript "display dialog" scrollable (non-editable)
#   --progress       progress surrogate            → display notification (non-blocking)
#
# Module-path (best-effort, covers every scrt4 call site):
#   --list           pick one / --checklist --multiple → choose from list
#   --file-selection --directory / --file-filter=     → choose file / folder
#   --forms --add-password=                           → display dialog + hidden answer
#
# Exit codes follow zenity's convention:
#   0 — user confirmed (OK / chosen); stdout carries the result
#   1 — user cancelled
#   5 — timeout (not used here; reserved)
#
# Flag parsing is deliberately loose: unknown flags are ignored with a warning
# to stderr, never fatal. Pango markup (<span …>…</span>) is stripped since
# AppleScript dialogs are plain-text.

set -eu

# ── Helpers ──────────────────────────────────────────────────────────

# Escape a string for inclusion inside AppleScript double-quoted strings.
# Order matters: backslash first, then the literal double quote.
as_escape() {
    # shellcheck disable=SC2001
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# Strip Pango markup (<span …>…</span>, <b>, <i>, etc.). AppleScript
# display-dialog does not render rich text; keep the visible glyphs.
strip_pango() {
    # shellcheck disable=SC2001
    printf '%s' "$1" | sed -E 's/<\/?[a-zA-Z][^>]*>//g'
}

# Turn literal "\n" escape sequences into real newlines so the dialog text
# wraps correctly. scrt4-core uses backslash-n liberally in --text= strings.
nl_expand() {
    printf '%b' "$1"
}

# Run osascript with one AppleScript string. Stdout flows through; we catch
# "User canceled." and map it to exit 1 (zenity convention).
run_osascript() {
    local script="$1" out rc
    if out=$(/usr/bin/osascript -e "$script" 2>&1); then
        printf '%s' "$out"
        return 0
    else
        rc=$?
        case "$out" in
            *"User canceled"*|*"User cancelled"*|*"-128"*) return 1 ;;
            *)
                printf 'scrt4-zenity: osascript error: %s\n' "$out" >&2
                return "$rc"
                ;;
        esac
    fi
}

# ── Flag parser ──────────────────────────────────────────────────────
#
# All modes share the same --key=value convention. We collect flags into
# a set of variables and let each mode-handler read what it needs.

MODE=""
TITLE="scrt4"
TEXT=""
OK_LABEL=""
CANCEL_LABEL=""
EXTRA_BUTTON=""
ENTRY_TEXT=""
FILENAME=""
EDITABLE=0
MULTIPLE=0
CHECKLIST=0
DIRECTORY=0
HIDE_HEADER=0
declare -a COLUMNS=()
declare -a FILE_FILTERS=()
declare -a FORM_FIELDS=()        # type:label pairs for --forms
PASSWORD_LABEL=""                # convenience for the common --add-password case

for arg in "$@"; do
    case "$arg" in
        # Mode flags (mutually exclusive, first one wins)
        --entry|--question|--info|--error|--warning|--text-info|--progress|--list|--file-selection|--forms|--notification)
            [ -z "$MODE" ] && MODE="${arg#--}"
            ;;

        # Common option flags
        --title=*)          TITLE=$(nl_expand "${arg#--title=}") ;;
        --text=*)           TEXT=$(strip_pango "$(nl_expand "${arg#--text=}")") ;;
        --ok-label=*)       OK_LABEL="${arg#--ok-label=}" ;;
        --cancel-label=*)   CANCEL_LABEL="${arg#--cancel-label=}" ;;
        --extra-button=*)   EXTRA_BUTTON="${arg#--extra-button=}" ;;
        --entry-text=*)     ENTRY_TEXT="${arg#--entry-text=}" ;;
        --filename=*)       FILENAME="${arg#--filename=}" ;;
        --editable)         EDITABLE=1 ;;
        --multiple)         MULTIPLE=1 ;;
        --checklist)        CHECKLIST=1 ;;
        --directory)        DIRECTORY=1 ;;
        --hide-header)      HIDE_HEADER=1 ;;
        --file-filter=*)    FILE_FILTERS+=("${arg#--file-filter=}") ;;
        --column=*)         COLUMNS+=("${arg#--column=}") ;;

        # --forms multi-value inputs
        --add-entry=*)      FORM_FIELDS+=("entry:${arg#--add-entry=}") ;;
        --add-password=*)
            FORM_FIELDS+=("password:${arg#--add-password=}")
            PASSWORD_LABEL="${arg#--add-password=}"
            ;;

        # Ignored-but-known (don't whine about these)
        --width=*|--height=*|--font=*|--auto-close|--pulsate|--no-wrap|--icon-name=*|--window-icon=*|--timeout=*)
            ;;

        # Literal arguments (used by --list as column data from stdin
        # normally, so positional rows are handled there)
        --)
            ;;

        *)
            case "$arg" in
                --*) printf 'scrt4-zenity: ignoring unrecognized flag: %s\n' "$arg" >&2 ;;
                *)   : ;;   # positional — only --list consumes these
            esac
            ;;
    esac
done

# Strip the leading flag block so handlers can re-read positional args if
# they need to (used by --list).
POSITIONAL=()
for arg in "$@"; do
    case "$arg" in
        --*) ;;
        *) POSITIONAL+=("$arg") ;;
    esac
done

# ── Mode: --entry ────────────────────────────────────────────────────
#
# Single-line prompt. Stdout = user text. Exit 1 on cancel.
mode_entry() {
    local t_title t_text t_default
    t_title=$(as_escape "$TITLE")
    t_text=$(as_escape "${TEXT:-Enter value:}")
    t_default=$(as_escape "$ENTRY_TEXT")
    local script
    script=$(cat <<APPLESCRIPT
set dlg to display dialog "${t_text}" default answer "${t_default}" with title "${t_title}" buttons {"Cancel", "OK"} default button "OK" cancel button "Cancel"
return text returned of dlg
APPLESCRIPT
)
    run_osascript "$script"
}

# ── Mode: --question ─────────────────────────────────────────────────
#
# Yes/No dialog. Exit 0 = OK (yes), 1 = Cancel (no). --extra-button= adds
# a third button; when pressed, exit 1 and the label goes to stdout so the
# caller can branch on it (this is how scrt4-core detects "Whitelist").
mode_question() {
    local t_title t_text ok cancel extra
    t_title=$(as_escape "$TITLE")
    t_text=$(as_escape "${TEXT:-}")
    ok=$(as_escape "${OK_LABEL:-OK}")
    cancel=$(as_escape "${CANCEL_LABEL:-Cancel}")
    extra=$(as_escape "$EXTRA_BUTTON")

    local buttons default_btn script
    if [ -n "$EXTRA_BUTTON" ]; then
        buttons="{\"${extra}\", \"${cancel}\", \"${ok}\"}"
    else
        buttons="{\"${cancel}\", \"${ok}\"}"
    fi
    default_btn="\"${ok}\""

    script=$(cat <<APPLESCRIPT
set dlg to display dialog "${t_text}" with title "${t_title}" buttons ${buttons} default button ${default_btn} cancel button "${cancel}"
return button returned of dlg
APPLESCRIPT
)
    local result rc
    if result=$(run_osascript "$script"); then
        if [ -n "$EXTRA_BUTTON" ] && [ "$result" = "$EXTRA_BUTTON" ]; then
            # Extra button = zenity's exit 1 + label on stdout.
            printf '%s\n' "$EXTRA_BUTTON"
            return 1
        fi
        # Default OK → exit 0 silently.
        return 0
    else
        rc=$?
        return "$rc"
    fi
}

# ── Mode: --info / --warning ─────────────────────────────────────────
mode_info() {
    local t_title t_text ok
    t_title=$(as_escape "$TITLE")
    t_text=$(as_escape "${TEXT:-}")
    ok=$(as_escape "${OK_LABEL:-OK}")
    local script
    script=$(cat <<APPLESCRIPT
display dialog "${t_text}" with title "${t_title}" buttons {"${ok}"} default button "${ok}"
APPLESCRIPT
)
    run_osascript "$script" >/dev/null
}

# ── Mode: --error ────────────────────────────────────────────────────
mode_error() {
    local t_title t_text
    t_title=$(as_escape "$TITLE")
    t_text=$(as_escape "${TEXT:-}")
    local script
    script=$(cat <<APPLESCRIPT
display alert "${t_title}" message "${t_text}" as critical
APPLESCRIPT
)
    run_osascript "$script" >/dev/null
}

# ── Mode: --text-info ────────────────────────────────────────────────
#
# Two shapes:
#   --editable --filename=FILE  → open FILE in TextEdit, wait until user
#                                  closes that document, then cat FILE.
#                                  Stdout = edited content.
#   --editable (stdin data)     → write stdin to a temp file, same flow,
#                                  stdout = edited content.
#   non-editable (stdin data)   → show scrollable read-only dialog.
#
# TextEdit is used so users get a real multi-line text editor. We poll the
# application for the document being closed — this is the only reliable
# way to wait for editing to finish without tying up the whole TextEdit
# process (`open -W -a TextEdit` waits for TextEdit itself to quit, which
# deadlocks when other documents are open).
mode_text_info() {
    local t_title
    t_title=$(as_escape "$TITLE")

    if [ "$EDITABLE" = "1" ]; then
        # Resolve the file we'll edit.
        local file="$FILENAME"
        if [ -z "$file" ]; then
            file=$(mktemp -t scrt4-zenity-text.XXXXXX)
            # Consume stdin into the temp file so the user sees it in TextEdit.
            cat > "$file"
        fi

        local abs_path
        abs_path=$(cd "$(dirname "$file")" && pwd)/$(basename "$file")
        local t_path
        t_path=$(as_escape "$abs_path")

        local script
        script=$(cat <<APPLESCRIPT
tell application "TextEdit"
    activate
    open POSIX file "${t_path}"
    delay 0.2
    -- Wait for the document at this POSIX path to be closed by the user.
    repeat
        set stillOpen to false
        try
            set docs to every document
            repeat with d in docs
                try
                    if (POSIX path of (get path of d) is "${t_path}") then
                        set stillOpen to true
                        exit repeat
                    end if
                end try
            end repeat
        end try
        if not stillOpen then exit repeat
        delay 0.5
    end repeat
end tell
APPLESCRIPT
)
        run_osascript "$script" >/dev/null || true

        # Emit the (possibly edited) file contents. zenity with --editable
        # writes the edited body to stdout on OK; cancel → empty output.
        cat "$file"
        # If we created the temp file, leave it for the caller to clean up
        # (scrt4-core uses mktemp + rm -f pattern).
        return 0
    fi

    # Non-editable: read stdin into a variable and show it scrollable.
    local body
    body=$(cat)
    local t_body
    t_body=$(as_escape "$body")
    local script
    script=$(cat <<APPLESCRIPT
display dialog "${t_body}" with title "${t_title}" buttons {"OK"} default button "OK" with title "${t_title}"
APPLESCRIPT
)
    run_osascript "$script" >/dev/null
}

# ── Mode: --progress --pulsate --auto-close ──────────────────────────
#
# zenity's progress dialog takes stdin lines:
#   "#text"  → update label
#   "NN"     → percentage (not used by scrt4 — only --pulsate)
#   close    → done
#
# On macOS we show a one-shot Notification Center banner on start and
# swallow stdin. The actual auth flow in scrt4 has its own confirmation
# path (Touch ID / WebAuthn prompt), so missing an animated spinner here
# is purely cosmetic.
mode_progress() {
    local t_title t_text
    t_title=$(as_escape "$TITLE")
    t_text=$(as_escape "$TEXT")
    # Fire a one-shot notification so the user sees something happen.
    /usr/bin/osascript -e "display notification \"${t_text}\" with title \"${t_title}\"" 2>/dev/null || true
    # Consume stdin and exit 0 when it closes.
    cat >/dev/null
    return 0
}

# ── Mode: --list ─────────────────────────────────────────────────────
#
# zenity --list pipes tab- or newline-separated rows on stdin. Columns are
# named via repeated --column= flags. --checklist/--multiple lets the user
# pick several; the selected values (one per picked row, from the hidden
# "id" column which is column 2 when the checkbox column is column 1) come
# back on stdout separated by "|".
#
# On macOS we use `choose from list`. It's a single-column picker, so we
# collapse the display columns into a " — " joined string and map the
# chosen label back to the hidden id column when --checklist is in play.
mode_list() {
    # Read rows from stdin.
    local -a rows=()
    local line
    while IFS= read -r line; do
        rows+=("$line")
    done

    local checkbox_offset=0
    [ "$CHECKLIST" = "1" ] && checkbox_offset=1

    # Build labels (what the user sees) and ids (what we print on OK).
    local -a labels=() ids=()
    for row in "${rows[@]}"; do
        # Rows arrive as runs of (checkbox value), (id), (col1), (col2), …
        # separated by tab. Split, pick id = col[checkbox_offset], label =
        # remaining display columns joined with " — ".
        IFS=$'\t' read -r -a fields <<< "$row"
        local id="${fields[$checkbox_offset]:-}"
        local display=""
        local i="$((checkbox_offset + 1))"
        while [ "$i" -lt "${#fields[@]}" ]; do
            if [ -n "$display" ]; then
                display="${display} — ${fields[$i]}"
            else
                display="${fields[$i]}"
            fi
            i=$((i + 1))
        done
        [ -z "$display" ] && display="$id"
        labels+=("$display")
        ids+=("$id")
    done

    # Serialize labels into an AppleScript list literal.
    local as_list="{"
    local j=0
    for lab in "${labels[@]}"; do
        [ "$j" -gt 0 ] && as_list="${as_list}, "
        as_list="${as_list}\"$(as_escape "$lab")\""
        j=$((j + 1))
    done
    as_list="${as_list}}"

    local t_title t_prompt multi
    t_title=$(as_escape "$TITLE")
    t_prompt=$(as_escape "${TEXT:-Choose:}")
    multi="false"
    [ "$MULTIPLE" = "1" ] && multi="true"

    local script
    script=$(cat <<APPLESCRIPT
set picks to choose from list ${as_list} with title "${t_title}" with prompt "${t_prompt}" multiple selections allowed ${multi} OK button name "OK" cancel button name "Cancel"
if picks is false then
    error "User canceled" number -128
end if
set AppleScript's text item delimiters to linefeed
set out to picks as string
set AppleScript's text item delimiters to ""
return out
APPLESCRIPT
)
    local chosen
    if ! chosen=$(run_osascript "$script"); then
        return 1
    fi

    # Map chosen labels back to the hidden id column.
    local out="" first=1
    while IFS= read -r picked; do
        [ -z "$picked" ] && continue
        local idx=0
        for lab in "${labels[@]}"; do
            if [ "$lab" = "$picked" ]; then
                if [ "$first" = "1" ]; then
                    out="${ids[$idx]}"
                    first=0
                else
                    out="${out}|${ids[$idx]}"
                fi
                break
            fi
            idx=$((idx + 1))
        done
    done <<< "$chosen"

    printf '%s\n' "$out"
}

# ── Mode: --file-selection ───────────────────────────────────────────
mode_file_selection() {
    local t_title
    t_title=$(as_escape "${TITLE:-Choose}")

    local script
    if [ "$DIRECTORY" = "1" ]; then
        script=$(cat <<APPLESCRIPT
set f to choose folder with prompt "${t_title}"
return POSIX path of f
APPLESCRIPT
)
    else
        script=$(cat <<APPLESCRIPT
set f to choose file with prompt "${t_title}"
return POSIX path of f
APPLESCRIPT
)
    fi
    local path
    if ! path=$(run_osascript "$script"); then
        return 1
    fi
    # AppleScript POSIX paths end with "/" for directories.
    printf '%s\n' "$path"
}

# ── Mode: --forms ────────────────────────────────────────────────────
#
# Full zenity --forms support isn't practical in osascript (multi-field
# layouts aren't native). We cover the one shape scrt4 actually uses:
# --add-password="Recovery password" + (optional) a second --add-password
# for confirmation. Result lines are joined with "|" to match zenity.
mode_forms() {
    local t_title t_text
    t_title=$(as_escape "$TITLE")
    t_text=$(as_escape "${TEXT:-Enter values}")

    local -a values=()
    for field in "${FORM_FIELDS[@]}"; do
        local kind="${field%%:*}"
        local label="${field#*:}"
        local t_label t_prompt script
        t_label=$(as_escape "$label")
        t_prompt=$(as_escape "${TEXT:-$label}")
        if [ "$kind" = "password" ]; then
            script=$(cat <<APPLESCRIPT
set dlg to display dialog "${t_label}" default answer "" with title "${t_title}" with hidden answer buttons {"Cancel", "OK"} default button "OK" cancel button "Cancel"
return text returned of dlg
APPLESCRIPT
)
        else
            script=$(cat <<APPLESCRIPT
set dlg to display dialog "${t_label}" default answer "" with title "${t_title}" buttons {"Cancel", "OK"} default button "OK" cancel button "Cancel"
return text returned of dlg
APPLESCRIPT
)
        fi
        local v
        if ! v=$(run_osascript "$script"); then
            return 1
        fi
        values+=("$v")
    done

    local out="" first=1
    for v in "${values[@]}"; do
        if [ "$first" = "1" ]; then
            out="$v"
            first=0
        else
            out="${out}|${v}"
        fi
    done
    printf '%s\n' "$out"
}

# ── Mode: --notification ─────────────────────────────────────────────
mode_notification() {
    local t_title t_text
    t_title=$(as_escape "$TITLE")
    t_text=$(as_escape "$TEXT")
    /usr/bin/osascript -e "display notification \"${t_text}\" with title \"${t_title}\"" 2>/dev/null || true
}

# ── Dispatch ─────────────────────────────────────────────────────────

case "$MODE" in
    entry)           mode_entry ;;
    question)        mode_question ;;
    info|warning)    mode_info ;;
    error)           mode_error ;;
    text-info)       mode_text_info ;;
    progress)        mode_progress ;;
    list)            mode_list ;;
    file-selection)  mode_file_selection ;;
    forms)           mode_forms ;;
    notification)    mode_notification ;;
    "")
        printf 'scrt4-zenity: no mode flag supplied (expected one of --entry, --question, --info, --error, --text-info, --progress, --list, --file-selection, --forms)\n' >&2
        exit 2
        ;;
    *)
        printf 'scrt4-zenity: mode --%s is not implemented by this shim\n' "$MODE" >&2
        exit 2
        ;;
esac
