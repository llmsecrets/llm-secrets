#!/usr/bin/env sh
#
# scrt4 uninstaller — removes anything the install.llmsecrets.com installers
# put on this machine (Docker v0.1 wrapper, Docker v0.2 wrapper, native binaries,
# systemd --user unit, launchd agent, macOS zenity shim).
#
# Usage:
#   # Interactive (will PROMPT before deleting the encrypted vault):
#   curl -fsSL https://install.llmsecrets.com/uninstall | sh
#
#   # Non-interactive — remove everything EXCEPT the vault (safe default for pipes):
#   curl -fsSL https://install.llmsecrets.com/uninstall | sh -s -- --yes
#
#   # Non-interactive — remove everything INCLUDING the vault (destroys secrets):
#   curl -fsSL https://install.llmsecrets.com/uninstall | sh -s -- --yes --purge
#
#   # Remove only the Docker wrappers / only the native install:
#   curl -fsSL https://install.llmsecrets.com/uninstall | sh -s -- --docker-only
#   curl -fsSL https://install.llmsecrets.com/uninstall | sh -s -- --native-only
#
# Vault deletion is IRREVERSIBLE. The vault is AES-256-GCM encrypted and the
# master key is wrapped with your FIDO2 authenticator — there is no recovery
# path without a `scrt4 backup` file. This script defaults to KEEPING the
# vault unless you explicitly pass --purge.
#
# Flags:
#   --yes             Don't prompt; remove binaries/services non-interactively.
#                     Still keeps the vault unless --purge is also passed.
#   --purge           Delete the encrypted vault directory (~/.scrt4). Requires
#                     --yes for non-interactive runs; interactive runs prompt.
#   --docker-only     Only remove the Docker wrapper + container, skip native.
#   --native-only     Only remove the native binaries/services, skip Docker.
#   --keep-vault      Explicit opt-in to keeping the vault (this is the default,
#                     but useful for scripts that want to be unambiguous).
#   -h, --help        Show this message.
#
# Env overrides:
#   SCRT4_NAME=scrt4              Container name (matches the installer default).
#   SCRT4_INSTALL_DIR=/path/to/bin  Where the native installer dropped binaries.
#                                   If unset, we check /usr/local/bin AND ~/.local/bin.

main() {
    set -eu

    NAME="${SCRT4_NAME:-scrt4}"
    ASSUME_YES=0
    PURGE_VAULT=0
    KEEP_VAULT_EXPLICIT=0
    DOCKER_ONLY=0
    NATIVE_ONLY=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --yes|-y)      ASSUME_YES=1 ;;
            --purge)       PURGE_VAULT=1 ;;
            --keep-vault)  KEEP_VAULT_EXPLICIT=1 ;;
            --docker-only) DOCKER_ONLY=1 ;;
            --native-only) NATIVE_ONLY=1 ;;
            -h|--help)     print_usage; exit 0 ;;
            *)
                printf 'scrt4-uninstall: unknown argument: %s\n' "$1" >&2
                printf '  Run with --help to see supported flags.\n' >&2
                exit 1
                ;;
        esac
        shift
    done

    if [ "$DOCKER_ONLY" = "1" ] && [ "$NATIVE_ONLY" = "1" ]; then
        printf 'scrt4-uninstall: --docker-only and --native-only are mutually exclusive.\n' >&2
        exit 1
    fi
    if [ "$PURGE_VAULT" = "1" ] && [ "$KEEP_VAULT_EXPLICIT" = "1" ]; then
        printf 'scrt4-uninstall: --purge and --keep-vault are contradictory.\n' >&2
        exit 1
    fi

    # If stdin is not a TTY (the usual curl|sh case) and no --yes was passed,
    # fall back to a read from /dev/tty. If that also fails (truly headless),
    # refuse rather than silently guessing.
    if [ "$ASSUME_YES" = "0" ] && [ ! -t 0 ] && [ ! -r /dev/tty ]; then
        printf 'scrt4-uninstall: running non-interactively without --yes.\n' >&2
        printf '  Add --yes to confirm, or re-run from a terminal.\n' >&2
        exit 1
    fi

    OS_UNAME=$(uname -s 2>/dev/null || echo unknown)
    case "$OS_UNAME" in
        Linux)  OS=linux  ;;
        Darwin) OS=darwin ;;
        *)      OS=other  ;;
    esac

    # Safety: if we're sitting inside a scrt4 source checkout, the user is
    # almost certainly a developer with a local `cargo build` result at
    # ~/.local/bin/scrt4-daemon (or similar). The installer-written manifest
    # would correctly skip those paths, but pre-manifest installs used
    # heuristics that could clobber a dev build. Warn loudly.
    detect_source_tree

    REMOVED_ANYTHING=0

    if [ "$NATIVE_ONLY" != "1" ]; then
        uninstall_docker
    fi
    if [ "$DOCKER_ONLY" != "1" ]; then
        uninstall_native
    fi

    handle_vault

    if [ "$REMOVED_ANYTHING" = "0" ]; then
        printf '\nscrt4-uninstall: nothing to do — no scrt4 install was detected on this machine.\n' >&2
    else
        printf '\n\033[0;32mscrt4-uninstall: done.\033[0m\n' >&2
    fi
}

print_usage() {
    cat <<'EOF'
scrt4 uninstaller

Usage:
  curl -fsSL https://install.llmsecrets.com/uninstall | sh
  curl -fsSL https://install.llmsecrets.com/uninstall | sh -s -- --yes
  curl -fsSL https://install.llmsecrets.com/uninstall | sh -s -- --yes --purge

Flags:
  --yes, -y        Don't prompt; proceed non-interactively (keeps the vault
                   unless --purge is also passed).
  --purge          Delete the encrypted vault at ~/.scrt4. IRREVERSIBLE.
  --keep-vault     Explicitly keep the vault (default behavior, but unambiguous).
  --docker-only    Remove only the Docker wrappers + container; leave native alone.
  --native-only    Remove only the native binaries + services; leave Docker alone.
  -h, --help       Show this message.

Env:
  SCRT4_NAME=scrt4             Docker container name (installer default).
  SCRT4_INSTALL_DIR=/path/bin  Native install dir. If unset, we check
                               /usr/local/bin and ~/.local/bin.

Vault safety:
  The vault at ~/.scrt4 is encrypted. Without --purge we keep it intact so
  you can reinstall and `scrt4 unlock` right back into your secrets. Pass
  --purge only if you want to throw the encrypted blob away (e.g. retiring
  the machine). There is no undo.
EOF
}

# ── Docker wrappers (scrt4-docker.sh + scrt4-v2-docker.sh) ──────────────
uninstall_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        return 0
    fi

    if ! docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$NAME"; then
        # No container by our default name. Also check for the self-installed
        # wrapper on PATH, which is the other half of the Docker install.
        :
    else
        if confirm "Remove Docker container '$NAME' (wipes vault + shell history in the container)?"; then
            docker rm -f "$NAME" >/dev/null 2>&1 || true
            printf 'scrt4-uninstall: removed Docker container %s\n' "$NAME" >&2
            REMOVED_ANYTHING=1
        else
            printf 'scrt4-uninstall: leaving Docker container %s intact\n' "$NAME" >&2
        fi
    fi

    # The Docker wrappers self-install themselves to ~/.local/bin/scrt4 on
    # first run. If that file is the wrapper (not a native binary), remove it.
    # The native installer puts a different file at the same path, so we
    # have to inspect contents before deleting.
    WRAPPER_CANDIDATES="${HOME}/.local/bin/scrt4 /usr/local/bin/scrt4"
    for c in $WRAPPER_CANDIDATES; do
        [ -f "$c" ] || continue
        # Wrappers contain the install URL in a header comment; the native CLI
        # is a bash build with `scrt4_module_` symbols and no install URL.
        if grep -qsE '(install\.llmsecrets\.com/v2|install\.llmsecrets\.com\b)' "$c" 2>/dev/null \
           && ! grep -qs 'scrt4_module_' "$c" 2>/dev/null; then
            rm -f "$c" && {
                printf 'scrt4-uninstall: removed Docker wrapper %s\n' "$c" >&2
                REMOVED_ANYTHING=1
            }
        fi
    done
}

# ── Native install (binaries + systemd/launchd + macOS zenity shim) ─────
uninstall_native() {
    # 0. Stop any running daemon + kill client zombies BEFORE touching files.
    # Without this, `scrt4 unlock` processes blocked on FIDO2 auth hold open
    # fd's to the daemon binary and refuse to exit. The user who ran this
    # script on WSL ended up with 7 stuck scrt4 processes — avoid that.
    kill_scrt4_processes

    # 1. Services. Stop the daemon cleanly before we yank its binary.
    if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1; then
        UNIT="${HOME}/.config/systemd/user/scrt4-daemon.service"
        if systemctl --user is-enabled scrt4-daemon.service >/dev/null 2>&1 \
           || systemctl --user is-active  scrt4-daemon.service >/dev/null 2>&1; then
            systemctl --user disable --now scrt4-daemon.service >/dev/null 2>&1 || true
            printf 'scrt4-uninstall: disabled systemd --user scrt4-daemon.service\n' >&2
            REMOVED_ANYTHING=1
        fi
        if [ -f "$UNIT" ]; then
            rm -f "$UNIT"
            systemctl --user daemon-reload >/dev/null 2>&1 || true
            printf 'scrt4-uninstall: removed %s\n' "$UNIT" >&2
            REMOVED_ANYTHING=1
        fi
    fi

    if [ "$OS" = "darwin" ]; then
        PLIST="${HOME}/Library/LaunchAgents/com.llmsecrets.scrt4-daemon.plist"
        if [ -f "$PLIST" ]; then
            launchctl unload "$PLIST" >/dev/null 2>&1 || true
            rm -f "$PLIST"
            printf 'scrt4-uninstall: removed launchd agent %s\n' "$PLIST" >&2
            REMOVED_ANYTHING=1
        fi
    fi

    # 2. Binaries. Prefer the install manifest — it lists exactly what the
    # installer wrote. Falls back to heuristics for installs that predate
    # manifests. Manifest path mirrors write_install_manifest() in
    # scrt4-native.sh (XDG_CONFIG_HOME/scrt4/install-manifest).
    MANIFEST="${XDG_CONFIG_HOME:-$HOME/.config}/scrt4/install-manifest"
    if [ -f "$MANIFEST" ]; then
        uninstall_via_manifest "$MANIFEST"
    else
        uninstall_via_heuristic
    fi

    # 3. Runtime socket — cheap cleanup, harmless if already gone.
    RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp}"
    if [ -S "$RUNTIME_DIR/scrt4.sock" ]; then
        rm -f "$RUNTIME_DIR/scrt4.sock"
    fi
}

# Manifest path: safe. We delete only the exact paths the installer logged.
uninstall_via_manifest() {
    manifest="$1"
    printf 'scrt4-uninstall: using install manifest %s\n' "$manifest" >&2
    # claude_md_* vars are populated inside the loop and applied after,
    # so we don't depend on line ordering in the manifest.
    claude_md_path=""
    claude_md_action=""
    while IFS= read -r line; do
        case "$line" in
            file=*)
                path="${line#file=}"
                if [ -f "$path" ]; then
                    rm -f "$path" && {
                        printf 'scrt4-uninstall: removed %s\n' "$path" >&2
                        REMOVED_ANYTHING=1
                    }
                fi
                ;;
            claude_md=*)        claude_md_path="${line#claude_md=}" ;;
            claude_md_action=*) claude_md_action="${line#claude_md_action=}" ;;
        esac
    done < "$manifest"

    # Reverse the CLAUDE.md import. We tracked whether we CREATED the
    # file or APPENDED to an existing one so we can cleanly undo either.
    if [ -n "$claude_md_path" ]; then
        remove_claude_import "$claude_md_path" "$claude_md_action"
    fi

    # Now delete the manifest itself. Its parent config dir may hold
    # daemon state (tags.json etc) we deliberately keep — don't rm -rf.
    rm -f "$manifest"
}

# Strip the managed @scrt4.md import block from ~/.claude/CLAUDE.md.
# Matches the marker written by install_claude_primer in scrt4-native.sh;
# keep these two strings byte-identical.
remove_claude_import() {
    path="$1"
    action="$2"
    # Fixed-string probe — parens in the marker would trip up grep -E.
    marker_literal='# scrt4 import (managed by scrt4 installer'
    # sed address uses BRE, where `(` is literal — no escaping needed.
    sed_addr='/^# scrt4 import (managed by scrt4 installer/,/^@scrt4\.md$/d'
    [ -f "$path" ] || return 0

    if ! grep -qF "$marker_literal" "$path" 2>/dev/null; then
        # Nothing of ours in the file — leave it alone.
        return 0
    fi

    # Delete from the marker line to the next @scrt4.md line (inclusive).
    # sed -i with a backup suffix works on both GNU and BSD sed.
    sed -i.scrt4bak -e "$sed_addr" "$path" 2>/dev/null || {
        printf 'scrt4-uninstall: could not strip scrt4 import from %s (sed failed)\n' "$path" >&2
        return 0
    }
    rm -f "${path}.scrt4bak"
    printf 'scrt4-uninstall: removed @scrt4.md import from %s\n' "$path" >&2
    REMOVED_ANYTHING=1

    # If we created the file (action=created) AND what's left is only
    # whitespace, delete the now-empty shell file. If the user added
    # their own content after our install, keep the file.
    if [ "$action" = "created" ]; then
        if ! grep -qE '[^[:space:]]' "$path" 2>/dev/null; then
            rm -f "$path" && printf 'scrt4-uninstall: removed empty %s\n' "$path" >&2
        fi
    fi
}

# Heuristic path: content-sniffing fallback for pre-manifest installs.
# Strictly check each binary looks like something we wrote before removing.
uninstall_via_heuristic() {
    printf 'scrt4-uninstall: no install manifest found — falling back to heuristic checks\n' >&2

    CANDIDATE_DIRS=""
    if [ -n "${SCRT4_INSTALL_DIR:-}" ]; then
        CANDIDATE_DIRS="$SCRT4_INSTALL_DIR"
    else
        # Mirror the installer's preference order: include /opt/homebrew/bin
        # so Apple Silicon installs are caught by the heuristic sweep.
        CANDIDATE_DIRS="/opt/homebrew/bin /usr/local/bin ${HOME}/.local/bin"
    fi

    for d in $CANDIDATE_DIRS; do
        [ -d "$d" ] || continue

        # scrt4-daemon: do NOT blanket-remove anymore. A dev's
        # `cargo install scrt4-daemon` would land a legitimate binary here
        # that we shouldn't touch. Only remove if the manifest path was set
        # explicitly, OR --yes was passed (user explicitly consented to
        # heuristic removal).
        if [ -f "$d/scrt4-daemon" ]; then
            if [ "$ASSUME_YES" = "1" ] || [ -n "${SCRT4_INSTALL_DIR:-}" ]; then
                rm -f "$d/scrt4-daemon" && {
                    printf 'scrt4-uninstall: removed %s/scrt4-daemon (heuristic)\n' "$d" >&2
                    REMOVED_ANYTHING=1
                }
            else
                printf 'scrt4-uninstall: found %s/scrt4-daemon — skipping (no manifest, no --yes).\n' "$d" >&2
                printf '  Re-run with --yes if you want to remove it, or delete manually.\n' >&2
            fi
        fi

        # scrt4 at this path could be the native CLI or the Docker wrapper.
        if [ -f "$d/scrt4" ] && grep -qs 'scrt4_module_' "$d/scrt4" 2>/dev/null; then
            rm -f "$d/scrt4" && {
                printf 'scrt4-uninstall: removed %s/scrt4\n' "$d" >&2
                REMOVED_ANYTHING=1
            }
        fi

        if [ "$OS" = "darwin" ] && [ -f "$d/zenity" ]; then
            if grep -qs 'scrt4\|osascript' "$d/zenity" 2>/dev/null; then
                rm -f "$d/zenity" && {
                    printf 'scrt4-uninstall: removed %s/zenity (macOS shim)\n' "$d" >&2
                    REMOVED_ANYTHING=1
                }
            fi
        fi
    done
}

# Best-effort: stop the daemon and clean up blocked `scrt4 unlock` clients.
# The FIDO2 unlock flow can leave a process parked on a prompt indefinitely.
kill_scrt4_processes() {
    if command -v pgrep >/dev/null 2>&1; then
        # Daemon first, then clients — gives the daemon a chance to close
        # its socket gracefully before clients go looking for it.
        for pattern in 'scrt4-daemon' 'scrt4 unlock' 'scrt4 view'; do
            pids=$(pgrep -f "$pattern" 2>/dev/null || true)
            if [ -n "$pids" ]; then
                # shellcheck disable=SC2086
                kill $pids 2>/dev/null || true
                sleep 1
                # shellcheck disable=SC2086
                kill -9 $pids 2>/dev/null || true
                printf 'scrt4-uninstall: killed processes matching "%s"\n' "$pattern" >&2
            fi
        done
    fi
}

detect_source_tree() {
    # Checked attributes:
    #   - daemon/Cargo.toml with package name scrt4-daemon
    #   - scripts/build-scrt4.sh
    # Either match is enough to assume we're in a checkout.
    cwd="$(pwd)"
    in_tree=0
    if [ -f "$cwd/daemon/Cargo.toml" ] && grep -qs 'scrt4-daemon' "$cwd/daemon/Cargo.toml" 2>/dev/null; then
        in_tree=1
    elif [ -f "$cwd/scripts/build-scrt4.sh" ]; then
        in_tree=1
    fi
    if [ "$in_tree" = "1" ]; then
        printf '\nscrt4-uninstall: WARNING — you appear to be running this from inside a scrt4 source checkout.\n' >&2
        printf '  cwd: %s\n' "$cwd" >&2
        printf '  If you have a local dev build at ~/.local/bin/scrt4-daemon (e.g. from `cargo install`),\n' >&2
        printf '  this script will leave it alone unless a matching install manifest exists.\n' >&2
        printf '  Pass --native-only --yes to override.\n\n' >&2
    fi
}

# ── Vault (~/.scrt4) ──────────────────────────────────────────────────
handle_vault() {
    VAULT_DIR="${HOME}/.scrt4"
    if [ ! -d "$VAULT_DIR" ]; then
        return 0
    fi

    if [ "$PURGE_VAULT" = "1" ]; then
        if [ "$ASSUME_YES" = "1" ] || confirm_destructive "DELETE the encrypted vault at $VAULT_DIR? This is IRREVERSIBLE."; then
            rm -rf "$VAULT_DIR"
            printf 'scrt4-uninstall: purged vault at %s\n' "$VAULT_DIR" >&2
            REMOVED_ANYTHING=1
        else
            printf 'scrt4-uninstall: vault kept at %s\n' "$VAULT_DIR" >&2
        fi
        return 0
    fi

    # Default: keep the vault, but tell the user it's still there.
    printf '\nscrt4-uninstall: vault kept at %s (pass --purge to delete).\n' "$VAULT_DIR" >&2
}

# ── Prompt helpers ─────────────────────────────────────────────────────
# confirm <question>  → "y" to proceed, "n" to skip. Under --yes, returns proceed.
confirm() {
    if [ "$ASSUME_YES" = "1" ]; then
        return 0
    fi
    _prompt "$1 [y/N] " ans || return 1
    case "$ans" in
        y|Y|yes|YES) return 0 ;;
        *)           return 1 ;;
    esac
}

# confirm_destructive — same, but refuses the safe default (requires typing YES).
confirm_destructive() {
    _prompt "$1
  Type DELETE to confirm: " ans || return 1
    [ "$ans" = "DELETE" ]
}

_prompt() {
    # Read from /dev/tty so curl|sh still interacts with the user.
    if [ -t 0 ]; then
        printf '%s' "$1" >&2
        # shellcheck disable=SC2162
        read "$2"
        eval "ans=\${$2}"
        return 0
    fi
    if [ -r /dev/tty ]; then
        printf '%s' "$1" >/dev/tty
        # shellcheck disable=SC2162
        read "$2" < /dev/tty
        eval "ans=\${$2}"
        return 0
    fi
    return 1
}

main "$@"
