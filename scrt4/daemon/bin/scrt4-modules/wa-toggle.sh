# shellcheck shell=bash
# scrt4-module: wa-toggle
# version: 1
# api: 1
# tcb: false
# deps:
# commands: wa-state, wa-on, wa-off
# requires:
#
# Toggle WebAuthn step-up for view/reveal and unlock operations. The
# decision logic is daemon-side; this module just wraps the
# check_wa_state / enable_wa / disable_wa / enable_wa_unlock /
# disable_wa_unlock RPCs.
#
# tcb: false — the bash side does not gate anything itself. The
# corresponding daemon handlers ARE in TCB (see docs/TCB.md). Disabling
# WebAuthn step-up requires a successful WebAuthn ceremony first
# (`_wa_gate` in core), so an attacker without a valid passkey cannot
# escalate by turning off the gates. Re-enabling does not require
# auth — it only tightens the policy.
#
# Ported from daemon/bin/scrt4 (v0.1.0 monolith) cmd_wa_state /
# cmd_wa_off / cmd_wa_on.

scrt4_module_wa_toggle_register() {
    _register_command wa-state scrt4_module_wa_toggle_state
    _register_command wa-on    scrt4_module_wa_toggle_on
    _register_command wa-off   scrt4_module_wa_toggle_off
}

scrt4_module_wa_toggle_state() {
    local response
    response=$(send_request '{"method":"check_wa_state"}')

    local success
    success=$(echo "$response" | jq -r '.success // false')
    if [ "$success" != "true" ]; then
        local error
        error=$(echo "$response" | jq -r '.error // "Unknown error"')
        echo -e "${RED}${error}${NC}" >&2
        return 1
    fi

    local configured enabled unlock_enabled
    configured=$(echo "$response" | jq -r '.data.configured // false')
    enabled=$(echo "$response" | jq -r '.data.enabled // false')
    unlock_enabled=$(echo "$response" | jq -r '.data.unlock_enabled // false')

    if [ "$configured" = "true" ]; then
        echo -e "WebAuthn configured:   ${GREEN}yes${NC}"
    else
        echo -e "WebAuthn configured:   ${YELLOW}no${NC}"
    fi
    if [ "$enabled" = "true" ]; then
        echo -e "2FA for reveal/view:   ${GREEN}enabled${NC}"
    else
        echo -e "2FA for reveal/view:   ${YELLOW}disabled${NC}"
    fi
    if [ "$unlock_enabled" = "true" ]; then
        echo -e "2FA for unlock:        ${GREEN}enabled${NC}"
    else
        echo -e "2FA for unlock:        ${YELLOW}disabled${NC}"
    fi
}

scrt4_module_wa_toggle_off() {
    local method="disable_wa"
    local label="view/reveal"
    if [ "${1:-}" = "--unlock" ]; then
        method="disable_wa_unlock"
        label="unlock"
    fi

    # Require WebAuthn verification before disabling it.
    _wa_gate || return 1

    local response
    response=$(send_request "{\"method\":\"${method}\"}")
    local success
    success=$(echo "$response" | jq -r '.success // false')

    if [ "$success" = "true" ]; then
        echo -e "${GREEN}WebAuthn 2FA disabled for ${label}.${NC}"
    else
        local error
        error=$(echo "$response" | jq -r '.error // "Unknown error"')
        echo -e "${RED}${error}${NC}" >&2
        return 1
    fi
}

scrt4_module_wa_toggle_on() {
    local method="enable_wa"
    local label="view/reveal"
    if [ "${1:-}" = "--unlock" ]; then
        method="enable_wa_unlock"
        label="unlock"
    fi

    local response
    response=$(send_request "{\"method\":\"${method}\"}")
    local success
    success=$(echo "$response" | jq -r '.success // false')

    if [ "$success" = "true" ]; then
        echo -e "${GREEN}WebAuthn 2FA re-enabled for ${label}.${NC}"
    else
        local error
        error=$(echo "$response" | jq -r '.error // "Unknown error"')
        echo -e "${RED}${error}${NC}" >&2
        return 1
    fi
}
