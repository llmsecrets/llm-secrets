#!/usr/bin/env bash
#
# scrt4 Docker wrapper — one-command access to the hardened container.
#
# Usage:
#   curl -fsSL https://install.llmsecrets.com | sh
#
# The first run self-installs this wrapper to ~/.local/bin/scrt4 (no sudo
# needed), so every run after that is just:
#   scrt4
#
# What it does:
#   - First run: creates a named container `scrt4` from joshgottlieb/scrt4-hardened
#   - Every run after: reattaches to the same container
#   - Vault, Claude Code auth, shell history all persist in the container's
#     own filesystem. No named volumes, no bind mounts, no Docker engine
#     context headaches.
#
# To reset:
#   docker rm -f scrt4   # wipes everything

# Everything is wrapped in a function so that when this script is piped to
# `sh` (curl | sh), bash parses the whole body before executing any of it.
# That lets us safely `exec 0</dev/tty` later to grab a real terminal for
# `docker run -it` without the interpreter losing its script input.
main() {
    set -eu

    IMAGE="${SCRT4_IMAGE:-joshgottlieb/scrt4-hardened}"
    NAME="${SCRT4_NAME:-scrt4}"

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

    # Docker CLI is on PATH but the daemon may still be down — catch that
    # separately so users see "start Docker Desktop", not a raw
    # "Cannot connect to the Docker daemon" stack trace.
    if ! docker info >/dev/null 2>&1; then
        printf 'scrt4: the docker CLI is installed but cannot reach the Docker daemon.\n' >&2
        printf '\n' >&2
        printf 'Start Docker and try again:\n' >&2
        printf '  - Windows / macOS: open Docker Desktop and wait for the whale icon\n' >&2
        printf '    in the menu bar to stop animating\n' >&2
        printf '  - Linux: sudo systemctl start docker\n' >&2
        exit 1
    fi

    # First-run convenience: drop a copy of this wrapper somewhere on PATH so
    # the user can type `scrt4` instead of re-running the curl one-liner.
    # Silent on failure — this is a nice-to-have, not a hard requirement.
    #
    # Install-target priority:
    #   1. /usr/local/bin     (works on macOS w/ Homebrew, and any Linux where
    #                          it happens to be user-writable)
    #   2. /opt/homebrew/bin  (Apple Silicon Homebrew default)
    #   3. ~/.local/bin       (always-writable fallback; auto-added to rc file
    #                          if not already on PATH)
    self_install() {
        if command -v scrt4 >/dev/null 2>&1; then
            return 0
        fi

        # Detect a non-executable shadow file on PATH — a common leftover from
        # an incomplete `sudo curl -o /usr/local/bin/scrt4` that was missing
        # the follow-up chmod. Try to fix it in place; if we can't (root-owned
        # on Linux), tell the user exactly what to run.
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

        # Pick an install target: prefer a directory already on PATH and
        # user-writable, so the user can type `scrt4` immediately without
        # editing any shell rc.
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
        if ! curl -fsSL https://install.llmsecrets.com -o "$target" 2>/dev/null; then
            return 0
        fi
        chmod +x "$target" 2>/dev/null || return 0

        printf '\n\033[0;32mInstalled scrt4 wrapper to %s\033[0m\n' "$target" >&2
        printf 'From now on, just type: \033[1mscrt4\033[0m\n' >&2

        case ":${PATH}:" in
            *":${dir}:"*)
                # Already on PATH — nothing else to do.
                ;;
            *)
                # Pick a shell rc file and auto-append the PATH export so
                # the next shell picks it up without the user editing files.
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

    # When invoked via `curl … | sh`, stdin is the pipe from curl — not a TTY.
    # `docker run -it` / `docker exec -it` need a real TTY on fd 0, so reopen
    # stdin from the controlling terminal if it's available. If there is no
    # /dev/tty (non-interactive host, CI), print a helpful message and bail.
    if [ ! -t 0 ]; then
        # Probe /dev/tty in a subshell so its own redirect failure is contained.
        if ( exec 0</dev/tty ) >/dev/null 2>&1; then
            exec 0</dev/tty
        else
            printf 'scrt4: stdin is not a TTY and /dev/tty is not accessible.\n' >&2
            printf 'Run the installer without a pipe:\n' >&2
            printf '  sudo curl -fsSL https://install.llmsecrets.com -o /usr/local/bin/scrt4\n' >&2
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
            printf '\033[0;36m scrt4 hardened — first run\033[0m\n' >&2
        else
            printf '\033[0;36m scrt4 hardened — reattaching to container "%s"\033[0m\n' "$NAME" >&2
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
        # Container exists — start if stopped, clean stale daemon socket from
        # previous session (the daemon's socket file persists in the container FS
        # across restarts but the daemon itself does not; without cleanup the
        # scrt4 CLI sees the stale socket and never re-spawns the daemon), then
        # reattach in a fresh interactive bash.
        docker start "$NAME" >/dev/null 2>&1 || true
        docker exec "$NAME" rm -f /tmp/scrt4-runtime/scrt4.sock 2>/dev/null || true
        print_banner reattach
        exec docker exec -it "$NAME" bash -l
    else
        # Always pull before first-run. Without this, `docker rm -f scrt4 &&
        # scrt4` keeps reusing whatever stale image is cached locally — docker
        # does NOT auto-pull `:latest` when a tag already exists. Users ran
        # that recreate sequence to pick up a new fix, got the same bug, and
        # (reasonably) assumed the fix wasn't merged. It was; their image
        # just never updated. Pull is idempotent and fast when cached.
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
