#!/usr/bin/env bash
#
# scrt4 v0.2 Docker wrapper — one-command access to the modular container.
#
# Usage:
#   curl -fsSL https://install.llmsecrets.com/v2 | sh
#
# The first run self-installs this wrapper to ~/.local/bin/scrt4 (no sudo
# needed), so every run after that is just:
#   scrt4
#
# What it does:
#   - First run: creates a named container `scrt4` from joshgottlieb/scrt4-hardened:v0.2-modular
#   - Every run after: reattaches to the same container
#   - Vault, Claude Code auth, shell history all persist in the container's
#     own filesystem. No named volumes, no bind mounts, no Docker engine
#     context headaches.
#
# Differences from v0.1.0 wrapper:
#   - Pulls :v0.2-modular tag (modular architecture) instead of :latest (monolith)
#   - Same vault format, same commands, backwards-compatible
#
# To reset:
#   docker rm -f scrt4   # wipes everything
#
# To switch back to v0.1.0:
#   docker rm -f scrt4
#   curl -fsSL https://install.llmsecrets.com | sh

main() {
    set -eu

    IMAGE="${SCRT4_IMAGE:-joshgottlieb/scrt4-hardened:v0.2-modular}"
    NAME="${SCRT4_NAME:-scrt4}"
    INSTALL_URL="https://install.llmsecrets.com/v2"

    if ! command -v docker >/dev/null 2>&1; then
        printf "scrt4: the 'docker' command was not found on PATH.\n" >&2
        printf '\n' >&2
        printf 'If Docker Desktop is already installed, make sure it is running:\n' >&2
        printf '  - Windows / macOS: open Docker Desktop from the Start menu / Applications\n' >&2
        printf '  - WSL Ubuntu: enable "WSL integration" for this distro under\n' >&2
        printf '    Docker Desktop -> Settings -> Resources -> WSL Integration,\n' >&2
        printf '    then open a fresh terminal\n' >&2
        printf '  - Linux: sudo systemctl start docker\n' >&2
        printf '\n' >&2
        printf 'If Docker is not installed yet, install it from:\n' >&2
        printf '  https://docs.docker.com/engine/install/\n' >&2
        exit 1
    fi

    if ! docker info >/dev/null 2>&1; then
        printf 'scrt4: the docker CLI is installed but cannot reach the Docker daemon.\n' >&2
        printf '\n' >&2
        printf 'Start Docker and try again:\n' >&2
        printf '  - Windows / macOS: open Docker Desktop and wait for the whale icon\n' >&2
        printf '    in the menu bar to stop animating\n' >&2
        printf '  - Linux: sudo systemctl start docker\n' >&2
        exit 1
    fi

    self_install() {
        if command -v scrt4 >/dev/null 2>&1; then
            return 0
        fi

        local broken_shadow=""
        local _old_ifs="$IFS"
        IFS=:
        local p
        for p in $PATH; do
            [ -z "$p" ] && continue
            if [ -f "$p/scrt4" ] && [ ! -x "$p/scrt4" ]; then
                broken_shadow="$p/scrt4"
                break
            fi
        done
        IFS="$_old_ifs"

        if [ -n "$broken_shadow" ]; then
            if chmod +x "$broken_shadow" 2>/dev/null; then
                printf '\n\033[0;32mFixed non-executable scrt4 at %s\033[0m\n' "$broken_shadow" >&2
                printf 'You can now type: \033[1mscrt4\033[0m\n\n' >&2
                return 0
            fi
            printf '\n\033[1;33mNote:\033[0m Found a non-executable scrt4 at %s\n' "$broken_shadow" >&2
            printf '(likely a leftover from an incomplete sudo install). Fix it with:\n' >&2
            printf '  sudo chmod +x %s\n\n' "$broken_shadow" >&2
            return 0
        fi

        if ! command -v curl >/dev/null 2>&1; then
            return 0
        fi

        local dir=""
        local candidate
        for candidate in /usr/local/bin /opt/homebrew/bin; do
            if [ -d "$candidate" ] && [ -w "$candidate" ]; then
                dir="$candidate"
                break
            fi
        done
        if [ -z "$dir" ]; then
            dir="${HOME}/.local/bin"
            mkdir -p "$dir" 2>/dev/null || return 0
        fi

        local target="$dir/scrt4"
        if ! curl -fsSL "$INSTALL_URL" -o "$target" 2>/dev/null; then
            return 0
        fi
        chmod +x "$target" 2>/dev/null || return 0

        printf '\n\033[0;32mInstalled scrt4 wrapper to %s\033[0m\n' "$target" >&2
        printf 'From now on, just type: \033[1mscrt4\033[0m\n' >&2

        case ":${PATH}:" in
            *":${dir}:"*)
                ;;
            *)
                local rc_file=""
                case "${SHELL:-}" in
                    */zsh)  rc_file="${HOME}/.zshrc" ;;
                    */bash) rc_file="${HOME}/.bashrc" ;;
                    *)
                        if   [ -f "${HOME}/.zshrc" ];   then rc_file="${HOME}/.zshrc"
                        elif [ -f "${HOME}/.bashrc" ];  then rc_file="${HOME}/.bashrc"
                        elif [ -f "${HOME}/.profile" ]; then rc_file="${HOME}/.profile"
                        fi
                        ;;
                esac
                # shellcheck disable=SC2016  # literal $PATH is intentional
                local path_line='export PATH="'"${dir}"':$PATH"'
                if [ -n "$rc_file" ] && ! grep -qsF "$path_line" "$rc_file" 2>/dev/null; then
                    {
                        printf '\n# Added by scrt4 installer\n'
                        printf '%s\n' "$path_line"
                    } >> "$rc_file" 2>/dev/null || true
                    printf '\n\033[1;33mAdded %s to your PATH in %s\033[0m\n' "$dir" "$rc_file" >&2
                    printf 'Open a new terminal (or run: source %s) then: \033[1mscrt4\033[0m\n' "$rc_file" >&2
                else
                    printf '\n\033[1;33mNote:\033[0m %s is not on your PATH yet.\n' "$dir" >&2
                    printf 'Add this to ~/.bashrc or ~/.zshrc:\n' >&2
                    # shellcheck disable=SC2016  # literal $PATH is intentional
                    printf '  export PATH="%s:$PATH"\n' "$dir" >&2
                fi
                ;;
        esac
        printf '\n' >&2
    }

    self_install

    if [ ! -t 0 ]; then
        if ( exec 0</dev/tty ) >/dev/null 2>&1; then
            exec 0</dev/tty
        else
            printf 'scrt4: stdin is not a TTY and /dev/tty is not accessible.\n' >&2
            printf 'Run the installer without a pipe:\n' >&2
            printf '  sudo curl -fsSL %s -o /usr/local/bin/scrt4\n' "$INSTALL_URL" >&2
            printf '  sudo chmod +x /usr/local/bin/scrt4\n' >&2
            printf '  scrt4\n' >&2
            exit 1
        fi
    fi

    print_banner() {
        local mode="$1"
        printf '\n' >&2
        printf '\033[0;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n' >&2
        if [ "$mode" = "first" ]; then
            printf '\033[0;36m scrt4 v0.2 hardened (modular) — first run\033[0m\n' >&2
        else
            printf '\033[0;36m scrt4 v0.2 hardened (modular) — reattaching to "%s"\033[0m\n' "$NAME" >&2
        fi
        printf '\033[0;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n' >&2
        printf '\n' >&2
        printf ' Vault, Claude Code auth, and shell history persist in this\n' >&2
        printf " container. Exit with Ctrl-D; re-run 'scrt4' to come back.\n" >&2
        printf '\n' >&2
        printf ' \033[1mCommon scrt4 commands (run inside the container):\033[0m\n' >&2
        printf '   scrt4 setup agent            # first-time WebAuthn enrollment (QR code)\n' >&2
        printf '   scrt4 unlock                 # authenticate (20h session by default)\n' >&2
        printf '   scrt4 unlock --cli           # unlock with QR in the terminal\n' >&2
        printf '   scrt4 status                 # check session\n' >&2
        printf '   scrt4 list                   # list secret names (never values)\n' >&2
        printf '   scrt4 add KEY=value          # add a secret\n' >&2
        printf "   scrt4 run 'cmd \$env[KEY]'    # run a command with secret injection\n" >&2
        printf '   scrt4 view                   # edit secrets in a GUI notepad\n' >&2
        printf '   scrt4 menu                   # interactive menu (GUI or text)\n' >&2
        printf '   scrt4 share --all            # send all secrets via Magic Wormhole\n' >&2
        printf '   scrt4 receive --code CODE    # receive secrets from another machine\n' >&2
        printf '   scrt4 backup-vault           # backup encrypted vault\n' >&2
        printf '   scrt4 backup-key             # show master key (requires auth)\n' >&2
        printf '   scrt4 backup-guide           # full recovery guide\n' >&2
        printf '   scrt4 help                   # full command list\n' >&2
        printf '   exit                         # leave the container (state preserved)\n' >&2
        printf '\n' >&2
        printf ' \033[1mClaude Code (preinstalled):\033[0m\n' >&2
        printf '   claude                       # start Claude Code\n' >&2
        printf '   oc                           # start in YOLO mode (--dangerously-skip-permissions)\n' >&2
        printf '   cc                           # YOLO mode, resume last session\n' >&2
        printf '\n' >&2
        printf ' \033[1mContainer lifecycle (run on the HOST, not inside):\033[0m\n' >&2
        printf '   scrt4                        # re-enter this container\n' >&2
        printf '   docker stop scrt4            # pause (state preserved)\n' >&2
        printf '   docker rm -f scrt4           # destroy and wipe everything\n' >&2
        printf '\n' >&2
        printf '\033[0;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n' >&2
        printf '\n' >&2
    }

    if docker inspect "$NAME" >/dev/null 2>&1; then
        docker start "$NAME" >/dev/null 2>&1 || true
        docker exec "$NAME" rm -f /tmp/scrt4-runtime/scrt4.sock 2>/dev/null || true
        print_banner reattach
        exec docker exec -it "$NAME" bash -l
    else
        printf 'scrt4: first run — pulling %s\n' "$IMAGE" >&2
        docker pull "$IMAGE" || {
            printf '\033[1;33mscrt4: pull failed; falling back to local image if present.\033[0m\n' >&2
        }
        printf 'scrt4: creating container "%s"\n' "$NAME" >&2
        print_banner first
        exec docker run -it --name "$NAME" "$IMAGE" shell
    fi
}

main "$@"
