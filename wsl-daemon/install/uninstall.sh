#!/bin/bash
# wsl2-daemon/install/uninstall.sh
# Cleanly removes all scrt components

set -e

echo "Scrt Uninstaller"
echo "================"
echo ""

# Check for --force flag
FORCE=false
if [[ "$1" == "--force" ]] || [[ "$1" == "-f" ]]; then
    FORCE=true
fi

if [[ "$FORCE" != "true" ]]; then
    echo "This will remove:"
    echo "  - scrt-daemon binary"
    echo "  - scrt-client binary"
    echo "  - scrt CLI wrapper"
    echo "  - systemd service"
    echo "  - man page"
    echo "  - shell completions"
    echo ""
    echo "Your secrets and configuration in ~/.scrt/ will NOT be removed."
    echo ""
    read -p "Continue? [y/N] " confirm
    if [[ "$confirm" != "y" ]] && [[ "$confirm" != "Y" ]]; then
        echo "Cancelled."
        exit 0
    fi
fi

echo ""

# Stop and disable systemd service
echo "Stopping scrt-daemon service..."
systemctl --user stop scrt-daemon 2>/dev/null || true
systemctl --user disable scrt-daemon 2>/dev/null || true

# Remove systemd service file
echo "Removing systemd service..."
rm -f ~/.config/systemd/user/scrt-daemon.service
systemctl --user daemon-reload 2>/dev/null || true

# Remove binaries
echo "Removing binaries..."
rm -f ~/.local/bin/scrt-daemon
rm -f ~/.local/bin/scrt-client
rm -f ~/.local/bin/scrt

# Remove man page
echo "Removing man page..."
rm -f ~/.local/share/man/man1/scrt.1

# Remove shell completions
echo "Removing shell completions..."
rm -f ~/.local/share/bash-completion/completions/scrt
rm -f ~/.zsh/completions/_scrt

# Remove hello-bridge.ps1 from share directory
echo "Removing shared files..."
rm -f ~/.local/share/scrt/hello-bridge.ps1
rmdir ~/.local/share/scrt 2>/dev/null || true

# Try to remove from system-wide location if writable
if [[ -w /usr/local/share/scrt ]]; then
    rm -f /usr/local/share/scrt/hello-bridge.ps1
    rmdir /usr/local/share/scrt 2>/dev/null || true
fi

# Remove socket if it exists
SOCKET_PATH="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/scrt.sock"
if [[ -S "$SOCKET_PATH" ]]; then
    echo "Removing socket..."
    rm -f "$SOCKET_PATH"
fi

echo ""
echo "Uninstallation complete!"
echo ""
echo "Note: Your secrets and configuration in ~/.scrt/ were preserved."
echo "To remove them completely, run: rm -rf ~/.scrt"
echo ""
echo "To remove audit logs: rm -f ~/.scrt/audit.log"
