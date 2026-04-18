#!/bin/bash
# One-shot deploy setup for install.llmsecrets.com.
#
# Run on prod-repo-app-instance-v001 as root (via sudo).
# Idempotent — safe to re-run.
set -euo pipefail

REPO_SSH="git@github.com:VestedJosh/scrt4.git"
CHECKOUT_DIR="/var/lib/scrt4-install"
WEB_DIR="/var/www/install"
KEY_PATH="/root/.ssh/scrt4_deploy"
SYNC_SCRIPT="/usr/local/bin/sync-scrt4-install"

echo "=== 1/6 Generate deploy key (if absent) ==="
mkdir -p /root/.ssh
chmod 700 /root/.ssh
if [ ! -f "$KEY_PATH" ]; then
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "scrt4-install-deploy@prod-repo"
    echo "Key generated."
else
    echo "Key already present."
fi
echo ""
echo "=== PUBLIC KEY (add to GitHub as deploy key) ==="
cat "${KEY_PATH}.pub"
echo ""

echo "=== 2/6 Configure SSH to use this key for github.com ==="
cat > /root/.ssh/config <<EOF
Host github.com-scrt4-install
    HostName github.com
    User git
    IdentityFile $KEY_PATH
    IdentitiesOnly yes
    StrictHostKeyChecking accept-new
EOF
chmod 600 /root/.ssh/config
echo "OK"

echo ""
echo "=== 3/6 Clone or update repo ==="
if [ ! -d "$CHECKOUT_DIR/.git" ]; then
    # Replace github.com with the aliased host so SSH picks our key.
    git clone "git@github.com-scrt4-install:VestedJosh/scrt4.git" "$CHECKOUT_DIR"
else
    git -C "$CHECKOUT_DIR" pull --ff-only
fi

echo ""
echo "=== 4/6 Install sync script ==="
cat > "$SYNC_SCRIPT" <<'SYNC'
#!/bin/bash
# sync-scrt4-install — pulls latest main and copies install/*.sh + README to
# /var/www/install so install.llmsecrets.com serves the newest content.
set -euo pipefail
CHECKOUT_DIR="/var/lib/scrt4-install"
WEB_DIR="/var/www/install"
mkdir -p "$WEB_DIR"
git -C "$CHECKOUT_DIR" fetch --quiet origin public/llmsecrets-sanitized
git -C "$CHECKOUT_DIR" reset --quiet --hard origin/public/llmsecrets-sanitized
cp "$CHECKOUT_DIR/install/scrt4-docker.sh" "$WEB_DIR/scrt4-docker.sh"
cp "$CHECKOUT_DIR/install.sh" "$WEB_DIR/install.sh"
chown -R www-data:www-data "$WEB_DIR"
chmod 644 "$WEB_DIR"/*.sh
SYNC
chmod 755 "$SYNC_SCRIPT"
echo "Installed: $SYNC_SCRIPT"

echo ""
echo "=== 5/6 Create systemd timer (1-min interval) ==="
cat > /etc/systemd/system/scrt4-install-sync.service <<EOF
[Unit]
Description=Sync install.llmsecrets.com content from scrt4 main
After=network-online.target

[Service]
Type=oneshot
ExecStart=$SYNC_SCRIPT
EOF

cat > /etc/systemd/system/scrt4-install-sync.timer <<EOF
[Unit]
Description=Sync scrt4 install files every minute

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
Unit=scrt4-install-sync.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now scrt4-install-sync.timer
echo "Timer active:"
systemctl list-timers scrt4-install-sync.timer --no-pager | head -5

echo ""
echo "=== 6/6 Run sync once now ==="
"$SYNC_SCRIPT"
ls -la "$WEB_DIR"
echo ""
echo "=== DONE ==="
