#!/bin/bash
# scrt WSL daemon installer
# Supports both pre-built tarballs and source builds

set -e

# Detect package manager
detect_pkg_manager() {
    if command -v pacman &>/dev/null; then echo "pacman"
    elif command -v apt &>/dev/null; then echo "apt"
    elif command -v dnf &>/dev/null; then echo "dnf"
    else echo "unknown"
    fi
}

pkg_install_hint() {
    local pkg="$1"
    case "$(detect_pkg_manager)" in
        pacman)
            case "$pkg" in
                openbsd-netcat) echo "sudo pacman -S openbsd-netcat" ;;
                *)              echo "sudo pacman -S $pkg" ;;
            esac ;;
        apt)
            case "$pkg" in
                openbsd-netcat) echo "sudo apt install netcat-openbsd" ;;
                *)              echo "sudo apt install $pkg" ;;
            esac ;;
        dnf)  echo "sudo dnf install $pkg" ;;
        *)    echo "Install '$pkg' using your package manager" ;;
    esac
}

# Check required dependencies
check_dependencies() {
    local missing=()

    if ! command -v jq &>/dev/null; then
        missing+=("jq")
    fi

    # Check for a working Unix socket client (socat or nc with -U)
    if ! command -v socat &>/dev/null && ! command -v nc &>/dev/null; then
        missing+=("socat")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "WARNING: Missing recommended dependencies:"
        for dep in "${missing[@]}"; do
            echo "  - $dep: $(pkg_install_hint "$dep")"
        done
        echo ""
    fi

    # Check optional but recommended
    if ! command -v zenity &>/dev/null; then
        echo "NOTE: zenity is not installed. GUI features (scrt view) will not work."
        echo "  Install: $(pkg_install_hint zenity)"
        echo ""
    fi
}

check_dependencies

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."

# Auto-detect binary locations: tarball (bin/) or source build (target/release/)
find_binary() {
    local name="$1"
    if [ -f "$PROJECT_DIR/target/release/$name" ]; then
        echo "$PROJECT_DIR/target/release/$name"
    elif [ -f "$PROJECT_DIR/bin/$name" ]; then
        echo "$PROJECT_DIR/bin/$name"
    else
        echo ""
    fi
}

DAEMON_BIN=$(find_binary "scrt-daemon")
CLIENT_BIN=$(find_binary "scrt-client")
CLI_SCRIPT="$PROJECT_DIR/bin/scrt"

# If binaries not found, try building from source
if [ -z "$DAEMON_BIN" ] || [ -z "$CLIENT_BIN" ]; then
    if command -v cargo &>/dev/null; then
        echo "Pre-built binaries not found. Building from source..."
        echo ""
        (cd "$PROJECT_DIR" && cargo build --release)
        (cd "$PROJECT_DIR/scrt-client" && cargo build --release)
        DAEMON_BIN="$PROJECT_DIR/target/release/scrt-daemon"
        CLIENT_BIN="$PROJECT_DIR/scrt-client/target/release/scrt-client"
    else
        echo "ERROR: Binaries not found and Rust is not installed."
        echo ""
        echo "Options:"
        echo "  1. Download the pre-built release tarball"
        echo "  2. Install Rust (https://rustup.rs) and run 'make build'"
        exit 1
    fi
fi

if [ ! -f "$CLI_SCRIPT" ]; then
    echo "ERROR: CLI script not found at $CLI_SCRIPT"
    exit 1
fi

# Create directories
mkdir -p ~/.local/bin
mkdir -p ~/.config/systemd/user
mkdir -p ~/.config/scrt
mkdir -p ~/.local/share/scrt

# Stop existing daemon if running (ignore errors)
systemctl --user stop scrt-daemon 2>/dev/null || true

# Copy binaries
cp "$DAEMON_BIN" ~/.local/bin/scrt-daemon
cp "$CLIENT_BIN" ~/.local/bin/scrt-client
cp "$CLI_SCRIPT" ~/.local/bin/scrt
chmod +x ~/.local/bin/scrt-daemon
chmod +x ~/.local/bin/scrt-client
chmod +x ~/.local/bin/scrt

# Ensure LF line endings on shell script (in case of Windows checkout)
sed -i 's/\r$//' ~/.local/bin/scrt

# Install man page
MAN_DIR="$HOME/.local/share/man/man1"
mkdir -p "$MAN_DIR"
cp "$SCRIPT_DIR/scrt.1" "$MAN_DIR/"
echo "Installed man page to $MAN_DIR/scrt.1"

# Install shell completions
BASH_COMP_DIR="$HOME/.local/share/bash-completion/completions"
ZSH_COMP_DIR="$HOME/.zsh/completions"

mkdir -p "$BASH_COMP_DIR"
cp "$SCRIPT_DIR/completions/scrt.bash" "$BASH_COMP_DIR/scrt"
echo "Installed bash completion to $BASH_COMP_DIR/scrt"

mkdir -p "$ZSH_COMP_DIR"
cp "$SCRIPT_DIR/completions/_scrt" "$ZSH_COMP_DIR/"
echo "Installed zsh completion to $ZSH_COMP_DIR/_scrt"

# Install systemd service
cp "$SCRIPT_DIR/scrt-daemon.service" ~/.config/systemd/user/

# Reload systemd and enable service
systemctl --user daemon-reload
systemctl --user enable scrt-daemon
systemctl --user start scrt-daemon

echo ""
echo "Installation complete!"
echo ""
echo "Installed to ~/.local/bin:"
echo "  - scrt-daemon  (background daemon)"
echo "  - scrt-client  (low-level client)"
echo "  - scrt         (CLI wrapper)"
echo ""
echo "Daemon status:"
systemctl --user status scrt-daemon --no-pager || true
echo ""
echo "Quick start:"
echo "  scrt unlock     # Authenticate with Windows Hello"
echo "  scrt list       # List available secrets"
echo "  scrt run <cmd>  # Run command with secrets injected"
echo ""
echo "Make sure ~/.local/bin is in your PATH:"
echo '  export PATH="$HOME/.local/bin:$PATH"'

# Set up Claude Code integration (global CLAUDE.md)
setup_claude_code() {
    local claude_dir="$HOME/.claude"
    local claude_md="$claude_dir/CLAUDE.md"
    local marker="## scrt2"

    mkdir -p "$claude_dir"

    # If CLAUDE.md doesn't exist, create it with scrt2 section
    if [ ! -f "$claude_md" ]; then
        cat > "$claude_md" << 'CLAUDEEOF'
# Secret Access Reference

## scrt2 — WSL2 Secure Secret Injector (TOTP Edition)

Use `$env[SECRET_NAME]` syntax for secret injection. Values are injected
at runtime and never returned to the LLM.

```bash
scrt2 unlock                # Authenticate (20h session)
scrt2 list                  # List secret names
scrt2 run 'cmd $env[KEY]'   # Run command with secret injection
scrt2 add KEY=value         # Add a secret
scrt2 setup-2fa agent       # AI agent setup (non-interactive)
scrt2 help                  # Full command list
```

Run `scrt2 learn` to regenerate this file with your current secret names.
CLAUDEEOF
        echo "Created ~/.claude/CLAUDE.md with scrt2 reference"

    # If CLAUDE.md exists but doesn't mention scrt2, append section
    elif ! grep -qF "$marker" "$claude_md" 2>/dev/null; then
        cat >> "$claude_md" << 'CLAUDEEOF'

---

## scrt2 — Dev/Beta (Unstable)

scrt2 is an unstable dev/beta version with experimental features.
Most users do not have scrt2 installed. Use `$env[SECRET_NAME]` syntax.

```bash
scrt2 unlock                # Authenticate (20h session)
scrt2 run 'cmd $env[KEY]'   # Same injection syntax as scrt
scrt2 setup-2fa agent       # AI agent setup (non-interactive)
scrt2 help                  # Full command list
```

scrt2 has its own `CLAUDE.md` and `SECURITY.md` in its repo root.
CLAUDEEOF
        echo "Added scrt2 section to existing ~/.claude/CLAUDE.md"

    else
        echo "~/.claude/CLAUDE.md already has scrt2 section"
    fi
}

# Only set up Claude Code if claude directory exists or Claude Code is installed
if command -v claude &>/dev/null || [ -d "$HOME/.claude" ]; then
    setup_claude_code
fi
