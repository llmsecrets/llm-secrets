#!/usr/bin/env sh
#
# scrt4 native installer — no Docker required.
#
# Usage:
#   # Core-only (default — no modules beyond unlock/add/view/list/run):
#   curl -fsSL https://install.llmsecrets.com/native | sh
#
#   # Opt-in to one or more whitelisted modules (repeatable):
#   curl -fsSL https://install.llmsecrets.com/native | sh -s -- --module github
#   curl -fsSL https://install.llmsecrets.com/native | sh -s -- --module github --module stripe
#
#   # Env-var alternative (comma-separated):
#   curl -fsSL https://install.llmsecrets.com/native | SCRT4_MODULES=github,stripe sh
#
# Module installation is whitelist-gated: each requested module must appear
# in the approved list at https://install.llmsecrets.com/modules.json, and
# the downloaded module source is SHA256-verified against that manifest
# before being spliced into the core scrt4 binary. See
# install/modules-whitelist.json in the repo for the approved set.
#
# What it does:
#   - Detects OS (linux/darwin) + arch (x86_64/aarch64)
#   - Downloads the matching prebuilt scrt4-daemon + scrt4 CLI (native-default:
#     TCB core + encrypt-folder + import-env + cloud-crypt)
#     from the GitHub Releases page and verifies SHA256
#   - If --module flags were passed: verifies each against the server
#     whitelist, fetches + SHA-verifies each module source, splices module
#     bodies into the core scrt4 binary at the documented hook marker
#   - Installs both binaries to /usr/local/bin (if writable) or ~/.local/bin
#   - On Linux: installs a systemd --user unit so the daemon auto-starts
#   - On macOS: installs a launchd plist with RunAtLoad
#   - Prints the next steps (setup, unlock)
#
# Env overrides:
#   SCRT4_VERSION=v0.2.0            Pin a specific tag (default: latest)
#   SCRT4_INSTALL_DIR=/path/to/bin  Override install directory
#   SCRT4_SKIP_SERVICE=1            Install binaries only; skip systemd/launchd
#   SCRT4_SKIP_DEPS=1               Don't apt-get/brew/dnf install jq+zenity
#   SCRT4_REPO=owner/repo           Repo slug for error/issue links (default: VestedJosh/scrt4)
#   SCRT4_RELEASE_BASE_URL=https:// Override release-artifact host (default:
#                                   https://install.llmsecrets.com/releases)
#   SCRT4_MODULES=a,b,c             Equivalent to --module a --module b --module c
#   SCRT4_MANIFEST_URL=https://...  Override module whitelist URL (for forks/testing)
#   SCRT4_MODULES_BASE_URL=https://  Override per-module source URL base
#
# To uninstall:
#   systemctl --user disable --now scrt4-daemon.service   (linux)
#   launchctl unload ~/Library/LaunchAgents/com.llmsecrets.scrt4-daemon.plist  (macOS)
#   rm -f  ~/.local/bin/scrt4 ~/.local/bin/scrt4-daemon
#   rm -rf ~/.config/systemd/user/scrt4-daemon.service

main() {
    set -eu

    REPO="${SCRT4_REPO:-VestedJosh/scrt4}"
    VERSION="${SCRT4_VERSION:-latest}"
    SKIP_SERVICE="${SCRT4_SKIP_SERVICE:-0}"
    RELEASE_BASE_URL="${SCRT4_RELEASE_BASE_URL:-https://install.llmsecrets.com/releases}"
    MANIFEST_URL="${SCRT4_MANIFEST_URL:-https://install.llmsecrets.com/modules.json}"
    MODULES_BASE_URL="${SCRT4_MODULES_BASE_URL:-https://install.llmsecrets.com/modules}"

    # ── 0. Parse args ─────────────────────────────────────────────────
    # MODULES is a space-separated list of module names that were requested
    # via --module flags or SCRT4_MODULES env. Empty by default — native-default
    # (encrypt-folder + import-env + cloud-crypt) is already baked into the
    # downloaded CLI.
    MODULES=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --module)
                shift
                if [ $# -eq 0 ] || [ -z "${1:-}" ]; then
                    printf 'scrt4-native: --module requires a name (e.g. --module github)\n' >&2
                    exit 1
                fi
                MODULES="$MODULES $1"
                ;;
            --module=*)
                name="${1#--module=}"
                if [ -z "$name" ]; then
                    printf 'scrt4-native: --module= needs a name\n' >&2
                    exit 1
                fi
                MODULES="$MODULES $name"
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            --)
                shift
                break
                ;;
            *)
                printf 'scrt4-native: unknown argument: %s\n' "$1" >&2
                printf '  Run with --help to see supported flags.\n' >&2
                exit 1
                ;;
        esac
        shift
    done

    # SCRT4_MODULES env var (comma-separated) folds in alongside --module flags.
    if [ -n "${SCRT4_MODULES:-}" ]; then
        _ifs_save="$IFS"
        IFS=,
        # shellcheck disable=SC2086
        set -- $SCRT4_MODULES
        IFS="$_ifs_save"
        for m in "$@"; do
            [ -n "$m" ] && MODULES="$MODULES $m"
        done
    fi

    # ── 1. Detect OS + arch ───────────────────────────────────────────
    OS_UNAME=$(uname -s 2>/dev/null || echo unknown)
    case "$OS_UNAME" in
        Linux)  OS=linux   ;;
        Darwin) OS=darwin  ;;
        *)
            printf 'scrt4-native: unsupported OS: %s\n' "$OS_UNAME" >&2
            printf 'Supported: Linux, macOS. For Windows, use WSL2.\n' >&2
            exit 1
            ;;
    esac

    ARCH_UNAME=$(uname -m 2>/dev/null || echo unknown)
    case "$ARCH_UNAME" in
        x86_64|amd64)        ARCH=x86_64  ;;
        aarch64|arm64)       ARCH=aarch64 ;;
        *)
            printf 'scrt4-native: unsupported architecture: %s\n' "$ARCH_UNAME" >&2
            printf 'Supported: x86_64, aarch64/arm64.\n' >&2
            exit 1
            ;;
    esac

    # Intel Macs: we ship only aarch64 darwin builds. Rosetta 2 runs them
    # transparently. Remap so the artifact URL resolves; first-run will
    # prompt the user to install Rosetta if it's not already present.
    if [ "$OS" = darwin ] && [ "$ARCH" = x86_64 ]; then
        printf 'scrt4-native: Intel Mac detected — using aarch64 build via Rosetta 2.\n' >&2
        ARCH=aarch64
    fi

    printf 'scrt4-native: detected %s/%s\n' "$OS" "$ARCH" >&2

    # ── 2. Dependencies check ─────────────────────────────────────────
    for cmd in curl tar; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            printf 'scrt4-native: required command not found: %s\n' "$cmd" >&2
            printf 'Install it with your package manager and re-run.\n' >&2
            exit 1
        fi
    done
    SHA_CMD=""
    if   command -v sha256sum >/dev/null 2>&1; then SHA_CMD=sha256sum
    elif command -v shasum    >/dev/null 2>&1; then SHA_CMD="shasum -a 256"
    else
        printf 'scrt4-native: neither sha256sum nor shasum found — cannot verify downloads.\n' >&2
        printf 'Install coreutils (Linux) or leave the default macOS shasum in place.\n' >&2
        exit 1
    fi

    # ── 2b. Runtime deps (jq, qrencode, zenity) ───────────────────────
    # jq       — required: the scrt4 bash CLI parses every daemon RPC through jq
    # qrencode — required: renders the unlock/setup QR in the terminal so users
    #            can scan it with their phone camera. Without it, `scrt4 unlock`
    #            and `scrt4 setup` fall back to printing only the auth URL.
    # zenity   — required for `scrt4 view` GUI dialog (secret values never touch
    #            terminal scrollback) and the `scrt4 add` no-arg paste dialog.
    #            CLI paths (`scrt4 add KEY=value`, `scrt4 view --cli`) work
    #            without it, but view defaults to GUI on Linux desktop sessions.
    install_runtime_deps

    # ── 3. Pick install dir ───────────────────────────────────────────
    # Preference order:
    #   1. SCRT4_INSTALL_DIR override
    #   2. /opt/homebrew/bin — Apple Silicon Homebrew prefix. Writable for
    #      brew users, and it's the one bin dir that's on PATH by default
    #      in Terminal.app on arm64 Macs. /usr/local/bin exists on M1 but
    #      is root-owned and off the brew path, so putting scrt4 there
    #      leaves it invisible unless the user already extended PATH.
    #   3. /usr/local/bin — writable Intel-Homebrew / classic *nix location
    #   4. ~/.local/bin — last-resort fallback; installer still writes a
    #      PATH export into .zprofile/.bashrc below so new terminals see it.
    if [ -n "${SCRT4_INSTALL_DIR:-}" ]; then
        INSTALL_DIR="$SCRT4_INSTALL_DIR"
        mkdir -p "$INSTALL_DIR" 2>/dev/null || {
            printf 'scrt4-native: cannot create %s\n' "$INSTALL_DIR" >&2
            exit 1
        }
    elif [ "$OS" = "darwin" ] && [ -d /opt/homebrew/bin ] && [ -w /opt/homebrew/bin ]; then
        INSTALL_DIR=/opt/homebrew/bin
    elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
        INSTALL_DIR=/usr/local/bin
    else
        INSTALL_DIR="${HOME}/.local/bin"
        mkdir -p "$INSTALL_DIR"
    fi

    # ── 4. Resolve version ────────────────────────────────────────────
    if [ "$VERSION" = "latest" ]; then
        # Pointer file served by the release host — single line, the version tag.
        VERSION=$(curl -fsSL "${RELEASE_BASE_URL}/latest.txt" 2>/dev/null | tr -d '[:space:]')
        if [ -z "$VERSION" ]; then
            printf 'scrt4-native: could not resolve latest release from %s/latest.txt — set SCRT4_VERSION explicitly.\n' \
                "$RELEASE_BASE_URL" >&2
            exit 1
        fi
    fi
    printf 'scrt4-native: installing %s to %s\n' "$VERSION" "$INSTALL_DIR" >&2

    # ── 5. Download + verify ──────────────────────────────────────────
    REL_BASE="${RELEASE_BASE_URL}/${VERSION}"
    # Portable mktemp: GNU honors XXXXXX in the template, BSD (macOS) treats
    # -t's argument as a prefix and adds its own random suffix. Using a full
    # path with XXXXXX works identically on both.
    TMP=$(mktemp -d "${TMPDIR:-/tmp}/scrt4-native.XXXXXX")
    trap 'rm -rf "$TMP"' EXIT

    DAEMON_FILE="scrt4-daemon-${OS}-${ARCH}"
    CLI_FILE="scrt4"
    CHECKSUM_FILE="SHA256SUMS"

    printf 'scrt4-native: downloading %s\n' "$DAEMON_FILE"      >&2
    curl -fsSL "${REL_BASE}/${DAEMON_FILE}"  -o "${TMP}/${DAEMON_FILE}"
    printf 'scrt4-native: downloading %s\n' "$CLI_FILE"         >&2
    curl -fsSL "${REL_BASE}/${CLI_FILE}"     -o "${TMP}/${CLI_FILE}"
    printf 'scrt4-native: downloading %s\n' "$CHECKSUM_FILE"    >&2
    curl -fsSL "${REL_BASE}/${CHECKSUM_FILE}" -o "${TMP}/${CHECKSUM_FILE}"

    # Verify — filter the checksum file to only our two artifacts so we
    # don't error on missing (other-arch) lines.
    (
        cd "$TMP"
        grep -E "  (${DAEMON_FILE}|${CLI_FILE})$" "$CHECKSUM_FILE" > expected.sums
        if [ ! -s expected.sums ]; then
            printf 'scrt4-native: release is missing checksum lines for %s / %s\n' "$DAEMON_FILE" "$CLI_FILE" >&2
            exit 1
        fi
        $SHA_CMD -c expected.sums >/dev/null || {
            printf 'scrt4-native: checksum mismatch — refusing to install.\n' >&2
            exit 1
        }
    )
    printf 'scrt4-native: checksums OK\n' >&2

    # ── 5b. Opt-in modules ────────────────────────────────────────────
    # If --module flags were passed (or SCRT4_MODULES env was set), verify
    # each against the server whitelist, fetch + sha-check each source,
    # and splice them into the downloaded core CLI at the hook marker.
    # Default (no flag) keeps native-default — the downloaded CLI already
    # contains the TCB surface (unlock / add / view / list / run / backup /
    # recover) plus encrypt-folder + import-env. Extra modules (github, gcp,
    # stripe, etc.) are the opt-in path.
    if [ -n "$MODULES" ]; then
        install_modules
    else
        printf 'scrt4-native: native-default install (TCB core + encrypt-folder + import-env + cloud-crypt; no extra --module flags)\n' >&2
    fi

    # ── 6. Install binaries ───────────────────────────────────────────
    install -m 0755 "${TMP}/${DAEMON_FILE}" "${INSTALL_DIR}/scrt4-daemon"
    install -m 0755 "${TMP}/${CLI_FILE}"    "${INSTALL_DIR}/scrt4"
    printf 'scrt4-native: installed %s/scrt4-daemon\n' "$INSTALL_DIR" >&2
    printf 'scrt4-native: installed %s/scrt4\n'         "$INSTALL_DIR" >&2

    # ── 6b. macOS zenity shim ────────────────────────────────────────
    # scrt4 view + scrt4 add (no-arg) + receive prompts call `zenity …`.
    # Homebrew's zenity pulls gtk+3 and requires XQuartz — ugly UX on a
    # Mac. Instead, we drop a tiny osascript-backed shim at
    # ${INSTALL_DIR}/zenity so scrt4-core keeps calling `zenity` and gets
    # native Cocoa dialogs. Only install if no zenity is already on PATH.
    if [ "$OS" = "darwin" ]; then
        install_macos_zenity_shim
    fi

    # ── 6c. Claude Code primer ───────────────────────────────────────
    # Drop a scrt4-only primer at ~/.claude/scrt4.md and wire it into
    # ~/.claude/CLAUDE.md via a managed @scrt4.md import so every
    # Claude Code session in every project can discover the $env[NAME]
    # injection contract. Idempotent; respects any existing CLAUDE.md
    # (appends, never overwrites). The uninstaller reverses this by
    # reading the install manifest.
    install_claude_primer

    # ── 6d. Install manifest ─────────────────────────────────────────
    # Written last so it captures every path the installer touched in
    # this run (binaries + macOS zenity shim + Claude primer + CLAUDE.md
    # action). The uninstaller reads this to delete ONLY what this
    # installer put on disk — prevents clobbering a dev's local
    # `cargo install scrt4-daemon`.
    write_install_manifest

    # ── 7. PATH hint ──────────────────────────────────────────────────
    # macOS Terminal.app opens login shells, which read ~/.zprofile — NOT
    # ~/.zshrc. Writing to both catches interactive *and* login zsh without
    # the user having to source anything. For bash we pair .bashrc with
    # .bash_profile for the same reason.
    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            rcs=""
            case "${SHELL:-}" in
                */zsh)
                    rcs="${HOME}/.zshrc ${HOME}/.zprofile"
                    ;;
                */bash)
                    rcs="${HOME}/.bashrc ${HOME}/.bash_profile"
                    ;;
                *)
                    if   [ -f "${HOME}/.zshrc" ];   then rcs="${HOME}/.zshrc ${HOME}/.zprofile"
                    elif [ -f "${HOME}/.bashrc" ];  then rcs="${HOME}/.bashrc ${HOME}/.bash_profile"
                    elif [ -f "${HOME}/.profile" ]; then rcs="${HOME}/.profile"
                    fi
                    ;;
            esac
            line='export PATH="'"${INSTALL_DIR}"':$PATH"'
            wrote=0
            for rc in $rcs; do
                [ -z "$rc" ] && continue
                if grep -qsF "$line" "$rc" 2>/dev/null; then
                    wrote=1
                    continue
                fi
                {
                    printf '\n# Added by scrt4 native installer\n'
                    printf '%s\n' "$line"
                } >> "$rc" 2>/dev/null && {
                    printf 'scrt4-native: added %s to PATH in %s\n' "$INSTALL_DIR" "$rc" >&2
                    wrote=1
                }
            done
            if [ "$wrote" = "1" ]; then
                printf '  Open a new terminal window or run:  export PATH="%s:$PATH"\n' "$INSTALL_DIR" >&2
            else
                printf 'scrt4-native: add this to your shell rc:\n' >&2
                printf '  %s\n' "$line" >&2
            fi
            ;;
    esac

    # ── 8. Service (optional) ────────────────────────────────────────
    if [ "$SKIP_SERVICE" = "1" ]; then
        printf 'scrt4-native: SCRT4_SKIP_SERVICE=1 — skipping service setup.\n' >&2
    elif [ "$OS" = "linux" ]; then
        install_systemd_user
    elif [ "$OS" = "darwin" ]; then
        install_launchd
    fi

    # ── 9. Done ──────────────────────────────────────────────────────
    printf '\n' >&2
    printf '\033[0;32mscrt4-native: installed.\033[0m\n' >&2
    printf 'Next:\n' >&2
    printf '  1. scrt4 setup agent     # enroll your FIDO2 authenticator\n' >&2
    printf '  2. scrt4 unlock          # 20-hour session\n' >&2
    printf '  3. scrt4 quickstart      # readiness snapshot\n' >&2
    printf '  4. scrt4 help            # full command list\n' >&2
}

print_usage() {
    cat <<'EOF'
scrt4 native installer

Usage:
  curl -fsSL https://install.llmsecrets.com/native | sh
  curl -fsSL https://install.llmsecrets.com/native | sh -s -- --module NAME [--module NAME ...]
  curl -fsSL https://install.llmsecrets.com/native | SCRT4_MODULES=github,stripe sh

Flags:
  --module NAME     Opt in to a whitelisted module. Repeatable. Each NAME is
                    verified against https://install.llmsecrets.com/modules.json
                    (a server-side allowlist) and its source is sha256-pinned
                    before it is spliced into the scrt4 CLI.
  -h, --help        Show this message.

Common env overrides:
  SCRT4_VERSION=v0.2.0            Pin a specific release tag
  SCRT4_INSTALL_DIR=/path/to/bin  Override install directory
  SCRT4_SKIP_SERVICE=1            Skip systemd/launchd setup
  SCRT4_SKIP_DEPS=1               Skip auto-install of jq + zenity
  SCRT4_MODULES=a,b,c             Comma-separated equivalent of --module flags
  SCRT4_MANIFEST_URL=URL          Override the whitelist manifest URL
  SCRT4_MODULES_BASE_URL=URL      Override the per-module source URL base
  SCRT4_RELEASE_BASE_URL=URL      Override the release-artifact host
  SCRT4_REPO=owner/repo           Repo slug used in error/issue links

Default install is native-default: TCB core (unlock, add, view, list, run,
backup-*, recover) plus encrypt-folder, import-env, and cloud-crypt. Extra
modules (github, gcp, stripe, etc.) are opt-in only and must be on the
server allowlist.
EOF
}

install_modules() {
    # Prerequisites ------------------------------------------------------
    if ! command -v jq >/dev/null 2>&1; then
        printf 'scrt4-native: jq is required to verify the module whitelist but is not installed.\n' >&2
        printf '  Install jq (apt-get install jq / brew install jq) and re-run, or drop the --module flags.\n' >&2
        exit 1
    fi

    # Fetch whitelist ----------------------------------------------------
    printf 'scrt4-native: fetching module whitelist %s\n' "$MANIFEST_URL" >&2
    if ! curl -fsSL "$MANIFEST_URL" -o "${TMP}/modules.json"; then
        printf 'scrt4-native: could not fetch module whitelist from %s\n' "$MANIFEST_URL" >&2
        printf '  Drop --module flags to install native-default only, or set SCRT4_MANIFEST_URL to a reachable mirror.\n' >&2
        exit 1
    fi
    if ! jq -e '.modules' "${TMP}/modules.json" >/dev/null 2>&1; then
        printf 'scrt4-native: whitelist at %s is malformed (no .modules object)\n' "$MANIFEST_URL" >&2
        exit 1
    fi

    # De-dup the requested list — no point fetching github twice.
    REQUESTED="$(printf '%s\n' $MODULES | awk 'NF && !seen[$0]++')"

    # Verify each request is on the whitelist, fetch + sha-check ---------
    MODULES_STAGING="${TMP}/modules"
    mkdir -p "$MODULES_STAGING"

    for name in $REQUESTED; do
        sha_expected="$(jq -r --arg n "$name" '.modules[$n].sha256 // ""' "${TMP}/modules.json")"
        if [ -z "$sha_expected" ]; then
            approved="$(jq -r '.modules | keys | join(", ")' "${TMP}/modules.json")"
            printf 'scrt4-native: module "%s" is not on the approved whitelist.\n' "$name" >&2
            printf '  Approved modules: %s\n' "$approved" >&2
            printf '  To add a module to the whitelist, open a PR against install/modules-whitelist.json in https://github.com/%s\n' "$REPO" >&2
            exit 1
        fi

        mod_url="${MODULES_BASE_URL}/${name}.sh"
        printf 'scrt4-native: fetching module %-18s %s\n' "$name" "$mod_url" >&2
        if ! curl -fsSL "$mod_url" -o "${MODULES_STAGING}/${name}.sh"; then
            printf 'scrt4-native: could not fetch module source from %s\n' "$mod_url" >&2
            exit 1
        fi

        sha_got="$($SHA_CMD "${MODULES_STAGING}/${name}.sh" | awk '{print $1}')"
        if [ "$sha_got" != "$sha_expected" ]; then
            printf 'scrt4-native: sha256 mismatch for module %s\n' "$name" >&2
            printf '  expected: %s\n' "$sha_expected" >&2
            printf '  got:      %s\n' "$sha_got" >&2
            printf '  Refusing to install — the module source does not match the whitelist pin.\n' >&2
            exit 1
        fi
    done

    # Splice module bodies into the downloaded core CLI ------------------
    HOOK='## SCRT4_MODULE_SOURCE_HOOK ##'
    if ! grep -qF "$HOOK" "${TMP}/${CLI_FILE}"; then
        printf 'scrt4-native: core CLI at %s is missing the module hook marker.\n' "${TMP}/${CLI_FILE}" >&2
        printf '  This release may predate v0.2 modules — pin a newer SCRT4_VERSION or drop --module.\n' >&2
        exit 1
    fi

    # awk reads the core line by line; on the hook marker it prints the
    # marker, then concatenates each requested module body in order. The
    # resulting script has the same shape as `scripts/build-scrt4.sh`
    # produces at release time — just assembled client-side.
    awk -v hook="$HOOK" -v staging="$MODULES_STAGING" -v mods="$REQUESTED" '
        BEGIN {
            n = split(mods, m, "\n")
            injected = 0
        }
        $0 == hook && !injected {
            print
            for (i = 1; i <= n; i++) {
                if (m[i] == "") continue
                f = staging "/" m[i] ".sh"
                print ""
                print "# ── module: " m[i] " ──────────────────────────────────────────"
                print ""
                while ((getline line < f) > 0) print line
                close(f)
                print ""
            }
            injected = 1
            next
        }
        { print }
        END {
            if (!injected) {
                print "scrt4-native: awk did not find the hook marker as an exact-match line" > "/dev/stderr"
                exit 2
            }
        }
    ' "${TMP}/${CLI_FILE}" > "${TMP}/${CLI_FILE}.assembled"

    if [ ! -s "${TMP}/${CLI_FILE}.assembled" ]; then
        printf 'scrt4-native: splice produced empty output — aborting\n' >&2
        exit 1
    fi

    # Syntax-check the assembled script — a broken module should not reach disk.
    if command -v bash >/dev/null 2>&1; then
        if ! bash -n "${TMP}/${CLI_FILE}.assembled" 2>"${TMP}/bash-n.err"; then
            printf 'scrt4-native: assembled scrt4 has bash syntax errors — refusing to install.\n' >&2
            sed 's/^/  /' "${TMP}/bash-n.err" >&2
            exit 1
        fi
    fi

    mv "${TMP}/${CLI_FILE}.assembled" "${TMP}/${CLI_FILE}"
    chmod +x "${TMP}/${CLI_FILE}"
    printf 'scrt4-native: spliced %d module(s) into scrt4:%s\n' \
        "$(printf '%s\n' $REQUESTED | awk 'NF' | wc -l | awk '{print $1}')" \
        "$(printf ' %s' $REQUESTED)" >&2
}

install_runtime_deps() {
    # Resolve what's missing first so we only escalate to sudo when we have to.
    missing=""
    command -v jq       >/dev/null 2>&1 || missing="$missing jq"
    command -v qrencode >/dev/null 2>&1 || missing="$missing qrencode"
    # zenity only makes sense where an X/Wayland session is available. On
    # servers and CI we don't install it — the CLI fallbacks cover those.
    want_zenity=0
    if [ "$OS" = "linux" ] && { [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ] || [ -n "${WSL_DISTRO_NAME:-}" ]; }; then
        want_zenity=1
        command -v zenity >/dev/null 2>&1 || missing="$missing zenity"
    fi

    if [ -z "$missing" ]; then
        printf 'scrt4-native: runtime deps already present (jq, qrencode%s)\n' \
            "$([ "$want_zenity" = 1 ] && printf ', zenity')" >&2
        return 0
    fi

    if [ "${SCRT4_SKIP_DEPS:-0}" = "1" ]; then
        printf 'scrt4-native: SCRT4_SKIP_DEPS=1 — skipping install of:%s\n' "$missing" >&2
        printf '  Install manually:  apt-get install -y%s\n' "$missing" >&2
        return 0
    fi

    SUDO=""
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            SUDO="sudo"
        else
            printf 'scrt4-native: need to install%s but this user is not root and sudo is unavailable.\n' "$missing" >&2
            printf '  Install manually and re-run, or export SCRT4_SKIP_DEPS=1 to skip this check.\n' >&2
            exit 1
        fi
    fi

    printf 'scrt4-native: installing runtime deps:%s\n' "$missing" >&2

    if   command -v apt-get >/dev/null 2>&1; then
        # Ubuntu / Debian — primary supported path.
        $SUDO apt-get update -qq
        # shellcheck disable=SC2086
        $SUDO apt-get install -y $missing
    elif command -v dnf >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        $SUDO dnf install -y $missing
    elif command -v yum >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        $SUDO yum install -y $missing
    elif command -v pacman >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        $SUDO pacman -S --noconfirm $missing
    elif command -v apk >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        $SUDO apk add --no-cache $missing
    elif command -v brew >/dev/null 2>&1; then
        # macOS — jq + qrencode; zenity isn't used on darwin (view auto-falls back).
        # shellcheck disable=SC2086
        brew install $missing
    else
        # Tailor the "how to fix" message to the platform — a fresh macOS
        # without Homebrew is the overwhelmingly common case here.
        if [ "$OS" = "darwin" ]; then
            printf 'scrt4-native: no package manager found on this Mac.\n' >&2
            printf '  scrt4 needs:%s at runtime. Two options:\n' "$missing" >&2
            printf '    1) Install Homebrew:  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"\n' >&2
            printf '       then re-run this installer.\n' >&2
            printf '    2) Install each package manually (e.g. MacPorts: sudo port install%s),\n' "$missing" >&2
            printf '       then re-run with SCRT4_SKIP_DEPS=1\n' >&2
        else
            printf 'scrt4-native: no recognized package manager. Install manually:%s\n' "$missing" >&2
            printf '  Or export SCRT4_SKIP_DEPS=1 to skip and install yourself later.\n' >&2
        fi
        exit 1
    fi

    # Verify each actually landed — package install can silently succeed
    # with the wrong binary (e.g. a metapackage without the right executable).
    for pkg in $missing; do
        case "$pkg" in
            jq)       command -v jq       >/dev/null 2>&1 || { printf 'scrt4-native: jq still not on PATH after install.\n'       >&2; exit 1; } ;;
            qrencode) command -v qrencode >/dev/null 2>&1 || { printf 'scrt4-native: qrencode still not on PATH after install.\n' >&2; exit 1; } ;;
            zenity)   command -v zenity   >/dev/null 2>&1 || { printf 'scrt4-native: zenity still not on PATH after install.\n'   >&2; exit 1; } ;;
        esac
    done
    printf 'scrt4-native: runtime deps installed\n' >&2
}

write_install_manifest() {
    # List every path we wrote. Uninstaller will refuse to delete
    # scrt4-daemon / scrt4 / zenity unless the path appears here.
    manifest_dir="${XDG_CONFIG_HOME:-$HOME/.config}/scrt4"
    mkdir -p "$manifest_dir"
    manifest="$manifest_dir/install-manifest"

    {
        printf 'version=1\n'
        printf 'installer=scrt4-native\n'
        printf 'installed_version=%s\n' "$VERSION"
        printf 'installed_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'os=%s\n' "$OS"
        printf 'arch=%s\n' "$ARCH"
        printf 'install_dir=%s\n' "$INSTALL_DIR"
        printf 'file=%s/scrt4-daemon\n' "$INSTALL_DIR"
        printf 'file=%s/scrt4\n'         "$INSTALL_DIR"
        if [ "$OS" = "darwin" ] && [ -f "${INSTALL_DIR}/zenity" ]; then
            printf 'file=%s/zenity\n' "$INSTALL_DIR"
        fi
        # Claude Code primer. CLAUDE_MD_ACTION distinguishes "we created
        # CLAUDE.md" (safe to delete if still empty) from "we appended to
        # an existing one" (strip only our block) so uninstall reverses
        # exactly what install did.
        if [ -n "${CLAUDE_PRIMER_PATH:-}" ]; then
            printf 'file=%s\n'             "$CLAUDE_PRIMER_PATH"
            printf 'claude_md=%s\n'        "$CLAUDE_MD_PATH"
            printf 'claude_md_action=%s\n' "$CLAUDE_MD_ACTION"
        fi
    } > "$manifest"
    chmod 644 "$manifest"
    printf 'scrt4-native: wrote install manifest %s\n' "$manifest" >&2
}

install_claude_primer() {
    claude_dir="${HOME}/.claude"
    primer_path="${claude_dir}/scrt4.md"
    claude_md="${claude_dir}/CLAUDE.md"
    # Marker must stay byte-identical across install/uninstall — the
    # uninstaller greps for it to decide what to strip. Plain ASCII only.
    marker='# scrt4 import (managed by scrt4 installer; do not edit this block)'
    import_line='@scrt4.md'

    mkdir -p "$claude_dir" 2>/dev/null || {
        printf 'scrt4-native: could not create %s — skipping Claude Code primer.\n' "$claude_dir" >&2
        return 0
    }

    # (Re)write the primer. We own this file; overwriting each install
    # keeps it in sync with the current scrt4 version's contract.
    cat > "$primer_path" <<'PRIMER_EOF'
# scrt4 — Secret Injection for Claude Code

You are running with **scrt4**, a hardware-bound secret manager. The user
has stored secrets that you can use in shell commands without ever seeing
their values.

## First-run flow (do this in order)

When the user is setting up scrt4 for the first time, or says "help me get
started with scrt4", walk them through these steps — do not skip any:

1. **`scrt4 setup`** — registers a FIDO2 passkey (YubiKey, phone, Touch ID,
   Windows Hello). One-time. This is the hardware root of trust.
2. **`scrt4 unlock`** — opens a session (default 20 h). Every step below
   requires an active session.
3. **Read the live capability map**: run `scrt4 llm` and read its output.
   That reflects the current vault, loaded modules, and auth state. This
   file is static; `scrt4 llm` is live — prefer it whenever they conflict.
4. **Set up encrypted Google Drive backup** (strongly recommended, see below).
5. **Offer to import existing `.env` files** (see below).

Treat steps 4 and 5 as the *default* onboarding path. The user will almost
always want both, but ask before doing step 5 (scanning filesystem for
`.env` files feels intrusive without consent).

## Step 4 — encrypted Google Drive backup (client-side encryption)

Without a backup, a lost hardware authenticator = permanently lost vault.
The recommended recovery path is **client-side encrypted backup to the
user's own Google Drive**. The ciphertext lives in their Drive; Google
cannot read it. Only their master key (which they keep offline or saved
to a password manager) can decrypt.

Prioritize this flow over a plain `scrt4 backup-key` copy-paste — the
Drive path survives laptop loss, disk failure, and accidental deletion.

Two pieces the user needs:

**a. Drive-scoped OAuth for cloud-crypt.** Fastest setup paths:

    scrt4 cloud-crypt auth setup --from-gws
        Uses the `gws` CLI (Google Workspace). If they have
        ~/.claude/skills/google-workspace/SKILL.md, that skill handles
        the consent + refresh-token dance end-to-end. Ask the user to
        run the skill.

    scrt4 cloud-crypt auth setup --from-secret personal_google_workspace
        If they already have a `personal_google_workspace` OAuth blob
        in the vault, reuse it — nothing is copied.

    scrt4 cloud-crypt auth setup --paste
        Interactive paste of an existing OAuth blob.

    scrt4 cloud-crypt auth status
        Confirms which source is active.

**b. Save the master key (so the Drive ciphertext can be decrypted later):**

    scrt4 backup-key --save ~/Desktop
        Writes a password-protected backup file. Tell the user to move
        it to their password manager or a USB stick — do NOT leave it
        on the desktop.

**Pushing the encrypted vault to Drive:**

    scrt4 cloud-crypt encrypt-and-push ~/.scrt4/vault.enc
    scrt4 cloud-crypt list

All encryption happens locally before upload. Google sees opaque ciphertext.

## Step 5 — importing existing `.env` files

If the user already has project `.env` files on disk, their secrets
belong in scrt4, not in plaintext files. Offer to import them:

    scrt4 import path/to/.env

One file at a time. The parser handles `export KEY=value`, surrounding
quotes, and `#` comments.

**Finding `.env` files — with consent:**

Ask the user something like: *"Want me to scan your common project
directories for `.env` files so we can import them into scrt4?"* Only
proceed on a clear yes. Then search the directories they care about
(their current project, `~/`, explicit paths they name) — avoid
system-wide scans.

Useful search command (shows paths only, never content):

    find ~/your/projects -name '.env' -o -name '.env.local' \
        -o -name '.env.production' 2>/dev/null

For each file found, show the path and ask before importing. After a
successful import, suggest deleting the plaintext file (the user should
confirm first — some tooling still reads `.env` directly).

## How injection works

Write commands with `$env[NAME]` placeholders. scrt4 substitutes the real
values at runtime inside the subprocess environment. The substituted text
is never returned to you.

```bash
scrt4 run 'curl -H "Authorization: Bearer $env[API_KEY]" https://api.example.com'
scrt4 run 'git push https://$env[GITHUB_PAT]@github.com/user/repo.git'
scrt4 run 'forge script Deploy.s.sol --rpc-url $env[ALCHEMY_RPC_URL] --private-key $env[PRIVATE_KEY] --broadcast'
```

The syntax is literally `$env[NAME]` — not `$NAME`, not `${NAME}`.

## Discovering what's available — run `scrt4 llm`

`scrt4 llm` emits an llms.txt-style dump of:

- secret names currently in the vault (names only, never values)
- loaded modules (cloud-crypt, import-env, encrypt-folder, …)
- capabilities each module provides, with auth gates and setup paths
- session status and recommended next steps

**Prefer `scrt4 llm` over reading this file** when you need current state —
this file is static; `scrt4 llm` reflects the live vault.

## What you can and can't see

| You CAN see | You CANNOT see |
|---|---|
| Secret names (`GITHUB_PAT`, `STRIPE_SECRET_KEY`, …) | Secret values — ever |
| Command exit codes | Private keys, passwords, tokens |
| stdout from `scrt4 run` (with stored values redacted) | The master key |
| Status of session, vault, modules | Anything shown in the `scrt4 view` GUI |

The daemon scrubs every stored secret value from subprocess stdout before
returning it to you. `scrt4 view` opens a GUI dialog by design — values
never touch terminal scrollback.

## Common operations

| Task | Command |
|---|---|
| Check session status | `scrt4 status` |
| Unlock (default 20 h) | `scrt4 unlock` |
| List secret names | `scrt4 list` |
| Add a secret | `scrt4 add NAME=value` |
| Import a `.env` file | `scrt4 import path/to/.env` |
| Run a command with injection | `scrt4 run 'cmd $env[NAME]'` |
| Encrypted Drive backup | `scrt4 cloud-crypt encrypt-and-push PATH` |
| Save master key (recovery) | `scrt4 backup-key --save DIR` |
| Capability discovery | `scrt4 llm` |
| Full command reference | `scrt4 help` |

## Security model (always true)

1. Master key is derived via FIDO2 `hmac-secret` from a hardware authenticator
   (YubiKey / Touch ID / phone passkey). The key never leaves the authenticator.
2. Vault at `~/.scrt4/` is AES-256-GCM encrypted at rest.
3. During a session, secrets live in daemon memory — never written unencrypted.
4. You (the LLM) never see values, only names and commands.
5. `scrt4 view` is GUI-only; its output is invisible to you by design.
6. cloud-crypt encrypts locally before upload — Google Drive sees ciphertext only.

## Troubleshooting

- **"Secret not found"** — name may be different. Run `scrt4 list`.
- **"Session locked"** — ask the user to run `scrt4 unlock`.
- **Need a new secret** — tell the user to run `scrt4 add NAME=value`, or
  import from a `.env` with `scrt4 import FILE`.
- **Never `scrt4 view` in an automation context** — it pops a GUI dialog.

---

*Installed by the scrt4 native installer. This file is regenerated on each
install. Uninstall with `curl -fsSL https://install.llmsecrets.com/uninstall | sh`.*
PRIMER_EOF

    # Wire up ~/.claude/CLAUDE.md. Three cases:
    #   1. CLAUDE.md doesn't exist   → create it with the import block (action=created)
    #   2. CLAUDE.md exists, no marker → append our block (action=appended)
    #   3. CLAUDE.md exists with marker → no-op (action=already-present)
    if [ ! -f "$claude_md" ]; then
        {
            printf '%s\n' "$marker"
            printf '%s\n' "$import_line"
        } > "$claude_md"
        CLAUDE_MD_ACTION=created
    elif ! grep -qF "$marker" "$claude_md" 2>/dev/null; then
        {
            printf '\n%s\n' "$marker"
            printf '%s\n' "$import_line"
        } >> "$claude_md"
        CLAUDE_MD_ACTION=appended
    else
        CLAUDE_MD_ACTION=already-present
    fi

    # Export paths for write_install_manifest() to record.
    CLAUDE_PRIMER_PATH="$primer_path"
    CLAUDE_MD_PATH="$claude_md"

    printf 'scrt4-native: installed Claude Code primer %s (CLAUDE.md %s)\n' \
        "$primer_path" "$CLAUDE_MD_ACTION" >&2
}

install_macos_zenity_shim() {
    # Already have a zenity on PATH? Leave it alone.
    if command -v zenity >/dev/null 2>&1; then
        printf 'scrt4-native: zenity already on PATH — not overwriting\n' >&2
        return 0
    fi

    # Pull the shim from install.llmsecrets.com (same source of truth as
    # this installer). Falls back to the GitHub raw URL on the branch if
    # the CDN is unreachable.
    SHIM_URL="${SCRT4_ZENITY_SHIM_URL:-https://install.llmsecrets.com/zenity-macos}"
    SHIM_FALLBACK="https://raw.githubusercontent.com/${REPO}/architecture/v0.2.0/install/scrt4-zenity-macos.sh"

    printf 'scrt4-native: installing macOS zenity shim -> %s/zenity\n' "$INSTALL_DIR" >&2
    if ! curl -fsSL "$SHIM_URL"      -o "${TMP}/zenity" 2>/dev/null \
      && ! curl -fsSL "$SHIM_FALLBACK" -o "${TMP}/zenity" 2>/dev/null; then
        printf 'scrt4-native: could not download zenity shim — scrt4 view GUI will not work.\n' >&2
        printf '  scrt4 view --cli still works; you can install the shim manually later.\n' >&2
        return 0
    fi
    install -m 0755 "${TMP}/zenity" "${INSTALL_DIR}/zenity"
    printf 'scrt4-native: installed %s/zenity (osascript-backed)\n' "$INSTALL_DIR" >&2
}

install_systemd_user() {
    # systemd --user only works on sessions where linger or a login session is
    # active. If systemctl --user is unavailable, fall back to printing the
    # manual start command.
    if ! command -v systemctl >/dev/null 2>&1; then
        printf 'scrt4-native: systemctl not found — start the daemon manually with:\n' >&2
        printf '  %s/scrt4-daemon &\n' "$INSTALL_DIR" >&2
        return 0
    fi

    UNIT_DIR="${HOME}/.config/systemd/user"
    mkdir -p "$UNIT_DIR"
    UNIT="${UNIT_DIR}/scrt4-daemon.service"

    cat > "$UNIT" <<UNIT_EOF
[Unit]
Description=scrt4 daemon
After=default.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/scrt4-daemon
Restart=on-failure
RestartSec=3
# The daemon derives its socket path from XDG_RUNTIME_DIR and its vault
# from HOME — inherit both from the user session (default for --user units).

[Install]
WantedBy=default.target
UNIT_EOF

    systemctl --user daemon-reload 2>/dev/null || true
    if systemctl --user enable --now scrt4-daemon.service 2>/dev/null; then
        printf 'scrt4-native: installed + started systemd --user unit scrt4-daemon.service\n' >&2
    else
        printf 'scrt4-native: systemd --user not usable in this session.\n' >&2
        printf '  Start manually:  %s/scrt4-daemon &\n' "$INSTALL_DIR" >&2
        printf '  Or enable when lingering is on:  loginctl enable-linger $USER\n' >&2
    fi
}

install_launchd() {
    PLIST_DIR="${HOME}/Library/LaunchAgents"
    mkdir -p "$PLIST_DIR"
    PLIST="${PLIST_DIR}/com.llmsecrets.scrt4-daemon.plist"

    cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>             <string>com.llmsecrets.scrt4-daemon</string>
  <key>ProgramArguments</key>  <array><string>${INSTALL_DIR}/scrt4-daemon</string></array>
  <key>RunAtLoad</key>         <true/>
  <key>KeepAlive</key>         <true/>
  <key>StandardOutPath</key>   <string>${HOME}/Library/Logs/scrt4-daemon.log</string>
  <key>StandardErrorPath</key> <string>${HOME}/Library/Logs/scrt4-daemon.log</string>
</dict>
</plist>
PLIST_EOF

    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load   "$PLIST" 2>/dev/null && \
        printf 'scrt4-native: installed + loaded launchd agent com.llmsecrets.scrt4-daemon\n' >&2 || \
        printf 'scrt4-native: wrote %s — load with: launchctl load %s\n' "$PLIST" "$PLIST" >&2
}

main "$@"
