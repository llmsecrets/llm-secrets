#!/bin/bash
# wsl2-daemon/install/install.sh

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
        echo "NOTE: zenity is not installed. GUI features (view, edit, add, gui) will not work."
        echo "  Install: $(pkg_install_hint zenity)"
        echo ""
    fi
}

check_dependencies

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."
DAEMON_BIN="$PROJECT_DIR/target/release/scrt-daemon"
CLIENT_BIN="$PROJECT_DIR/scrt-client/target/release/scrt-client"
CLI_SCRIPT="$PROJECT_DIR/bin/scrt"
HELLO_BRIDGE="$PROJECT_DIR/../scrt-linux/lib/hello-bridge.ps1"

# Check if binaries exist
if [ ! -f "$DAEMON_BIN" ]; then
    echo "ERROR: Daemon binary not found. Run 'cargo build --release' first."
    exit 1
fi

if [ ! -f "$CLIENT_BIN" ]; then
    echo "ERROR: Client binary not found. Run 'cargo build --release' in scrt-client first."
    exit 1
fi

if [ ! -f "$CLI_SCRIPT" ]; then
    echo "ERROR: CLI script not found at $CLI_SCRIPT"
    exit 1
fi

# Create directories
mkdir -p ~/.local/bin
mkdir -p ~/.config/systemd/user
mkdir -p ~/.config/scrt
mkdir -p /usr/local/share/scrt 2>/dev/null || mkdir -p ~/.local/share/scrt

# Determine share directory (prefer system-wide, fallback to user)
SHARE_DIR="/usr/local/share/scrt"
if [ ! -w "$(dirname "$SHARE_DIR")" ]; then
    SHARE_DIR="$HOME/.local/share/scrt"
    mkdir -p "$SHARE_DIR"
fi

# Copy binaries
cp "$DAEMON_BIN" ~/.local/bin/scrt-daemon
cp "$CLIENT_BIN" ~/.local/bin/scrt-client
cp "$CLI_SCRIPT" ~/.local/bin/scrt
chmod +x ~/.local/bin/scrt-daemon
chmod +x ~/.local/bin/scrt-client
chmod +x ~/.local/bin/scrt

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

# Copy hello-bridge.ps1 if it exists
if [ -f "$HELLO_BRIDGE" ]; then
    cp "$HELLO_BRIDGE" "$SHARE_DIR/hello-bridge.ps1"
    echo "Installed hello-bridge.ps1 to $SHARE_DIR"
else
    echo "WARNING: hello-bridge.ps1 not found. Windows Hello integration may not work."
fi

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
