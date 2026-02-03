# Bash completion for scrt
# Install: source this file or copy to /etc/bash_completion.d/

_scrt_completions() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Main commands
    commands="unlock status list run logout lock clear check-hello check help"

    case "$prev" in
        scrt)
            COMPREPLY=($(compgen -W "$commands" -- "$cur"))
            return 0
            ;;
        unlock)
            # TTL in seconds - suggest common values
            COMPREPLY=($(compgen -W "1800 3600 7200 14400 28800" -- "$cur"))
            return 0
            ;;
        run)
            # Suggest --scope or fall through to command completion
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--scope" -- "$cur"))
                return 0
            fi
            # Complete file names for commands
            COMPREPLY=($(compgen -c -- "$cur"))
            return 0
            ;;
        --scope)
            # Try to get secret names from daemon
            local secrets
            secrets=$(scrt list 2>/dev/null | tr '\n' ',' | sed 's/,$//')
            if [[ -n "$secrets" ]]; then
                COMPREPLY=($(compgen -W "$secrets" -- "$cur"))
            fi
            return 0
            ;;
        *)
            # If we're in a run command, complete file names
            for ((i=1; i < COMP_CWORD; i++)); do
                if [[ "${COMP_WORDS[i]}" == "run" ]]; then
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=($(compgen -W "--scope" -- "$cur"))
                    else
                        COMPREPLY=($(compgen -c -- "$cur"))
                    fi
                    return 0
                fi
            done
            ;;
    esac

    return 0
}

complete -F _scrt_completions scrt
