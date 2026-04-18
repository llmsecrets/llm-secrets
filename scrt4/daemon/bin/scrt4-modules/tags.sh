# shellcheck shell=bash
# scrt4-module: tags
# version: 1
# api: 1
# tcb: false
# deps:
# commands: tag, untag, tags
# requires:
#
# Tag management. Tags are stored in $CONFIG_DIR/tags.json (the same
# location as the v0.1.0 monolith). The bash side just reads/writes
# that file; no daemon protocol involved.
#
# Ported from daemon/bin/scrt4 (v0.1.0 monolith) cmd_tag / cmd_untag /
# cmd_tags.

scrt4_module_tags_register() {
    _register_command tag      scrt4_module_tags_tag
    _register_command untag    scrt4_module_tags_untag
    _register_command tags     scrt4_module_tags_list
}

# Tags file path. Uses CONFIG_DIR from core (~/.scrt4).
_tags_file() {
    echo "${CONFIG_DIR}/tags.json"
}

_load_tags_json() {
    local f
    f=$(_tags_file)
    if [ -f "$f" ]; then
        cat "$f"
    else
        echo '{}'
    fi
}

_save_tags_json() {
    local json="$1"
    mkdir -p "$CONFIG_DIR"
    printf '%s' "$json" > "$(_tags_file)"
}

scrt4_module_tags_tag() {
    if [ $# -lt 2 ]; then
        echo -e "${RED}Usage: scrt4 tag SECRET_NAME tag1 [tag2 ...]${NC}" >&2
        return 1
    fi
    local name="$1"; shift
    local tags_json
    tags_json=$(_load_tags_json)

    for t in "$@"; do
        tags_json=$(printf '%s' "$tags_json" | jq --arg k "$name" --arg t "$t" \
            '.[$k] = ((.[$k] // []) + [$t] | unique)')
    done

    _save_tags_json "$tags_json"
    local current
    current=$(printf '%s' "$tags_json" | jq -r --arg k "$name" '.[$k] | join(", ")')
    echo -e "${GREEN}${name}: ${current}${NC}"
}

scrt4_module_tags_untag() {
    if [ $# -lt 2 ]; then
        echo -e "${RED}Usage: scrt4 untag SECRET_NAME tag1 [tag2 ...]${NC}" >&2
        return 1
    fi
    local name="$1"; shift
    local tags_json
    tags_json=$(_load_tags_json)

    for t in "$@"; do
        tags_json=$(printf '%s' "$tags_json" | jq --arg k "$name" --arg t "$t" \
            'if .[$k] then .[$k] -= [$t] | if .[$k] == [] then del(.[$k]) else . end else . end')
    done

    _save_tags_json "$tags_json"
    local current
    current=$(printf '%s' "$tags_json" | jq -r --arg k "$name" '.[$k] // [] | join(", ")')
    if [ -z "$current" ]; then
        echo -e "${GREEN}${name}: (no tags)${NC}"
    else
        echo -e "${GREEN}${name}: ${current}${NC}"
    fi
}

scrt4_module_tags_list() {
    local tags_json
    tags_json=$(_load_tags_json)
    local count
    count=$(printf '%s' "$tags_json" | jq 'length')
    if [ "${count:-0}" -eq 0 ]; then
        echo -e "${YELLOW}No tags defined. Use: scrt4 tag SECRET_NAME tag1 tag2${NC}"
        return 0
    fi

    echo -e "${CYAN}Tags:${NC}"
    printf '%s' "$tags_json" | jq -r 'to_entries[] | "  \(.key): \(.value | join(", "))"'
}
