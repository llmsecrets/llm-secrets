# shellcheck shell=bash
# scrt4-module: import-env
# version: 1
# api: 1
# tcb: false
# deps:
# commands: import
# requires:
#
# Import secrets from a .env file. Parses KEY=value lines (handling
# `export KEY=value`, surrounding quotes, and # comments) and bulk-adds
# them via the daemon's add_secrets handler.
#
# Ported from daemon/bin/scrt4 (v0.1.0 monolith) cmd_import. The Python
# parser is preserved verbatim — it handles all the .env edge cases the
# bash side would get wrong.

scrt4_module_import_env_register() {
    _register_command import scrt4_module_import_env_cmd
}

scrt4_module_import_env_cmd() {
    local file=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --*) shift ;;
            *)   file="$1"; shift ;;
        esac
    done

    if [ -z "$file" ]; then
        if _has_gui; then
            file=$(zenity --file-selection \
                --title="LLM Secrets — Import .env File" \
                --file-filter="Env files|*.env *.env.* .env" \
                --file-filter="All files|*" \
                2>/dev/null) || { echo -e "${YELLOW}Cancelled.${NC}"; return 0; }
        else
            echo -e "${RED}Usage: scrt4 import <file.env>${NC}" >&2
            return 1
        fi
    fi

    if [ ! -f "$file" ]; then
        echo -e "${RED}File not found: ${file}${NC}" >&2
        return 1
    fi

    # Parse with Python — handles export prefixes, quoted values, comments,
    # and identifier validation. Stderr carries SKIPPED:/COUNT: telemetry.
    local parse_log="/tmp/scrt4-import-parse.$$.log"
    local json_secrets
    json_secrets=$(python3 -c '
import sys, json, re
secrets = {}
skipped = []
for line in open(sys.argv[1]):
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        continue
    if stripped.startswith("export "):
        stripped = stripped[7:].strip()
    if "=" in stripped:
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("\"", "'\''"):
            value = value[1:-1]
        if key and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            secrets[key] = value
            continue
    skipped.append(stripped)
for s in skipped:
    print(f"SKIPPED:{s}", file=sys.stderr)
print(f"COUNT:{len(secrets)}", file=sys.stderr)
print(json.dumps(secrets), end="")
' "$file" 2>"$parse_log")

    local parse_rc=$?
    if [ $parse_rc -ne 0 ]; then
        echo -e "${RED}Failed to parse file.${NC}" >&2
        rm -f "$parse_log"
        return 1
    fi

    while IFS= read -r logline; do
        if [[ "$logline" == SKIPPED:* ]]; then
            echo -e "${YELLOW}Skipping: ${logline#SKIPPED:}${NC}" >&2
        fi
    done < "$parse_log"

    local count
    count=$(grep '^COUNT:' "$parse_log" | head -1 | cut -d: -f2)
    rm -f "$parse_log"

    if [ "${count:-0}" -eq 0 ]; then
        echo -e "${YELLOW}No valid KEY=value lines found in ${file}.${NC}"
        return 0
    fi

    echo -e "${CYAN}Found ${count} secret(s) in $(basename "$file"). Importing...${NC}"

    ensure_unlocked || return 1

    local response
    response=$(send_request "{\"method\":\"add_secrets\",\"params\":{\"secrets\":$json_secrets}}")
    local success
    success=$(echo "$response" | jq -r '.success // false')

    if [ "$success" = "true" ]; then
        echo -e "${GREEN}Imported ${count} secret(s).${NC}"
        return 0
    else
        local err
        err=$(echo "$response" | jq -r '.error // "unknown"')
        echo -e "${RED}Import failed: ${err}${NC}" >&2
        return 1
    fi
}
