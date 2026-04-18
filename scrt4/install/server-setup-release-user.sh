#!/bin/bash
# server-setup-release-user.sh — one-time setup for GitHub Actions → prod host.
#
# Creates the `scrt4-release` service user whose sole job is to land new
# release artifacts under /var/www/install/releases/<tag>/. Run once on
# prod-repo-app-instance-v001 as root (via sudo). Idempotent — safe to re-run.
#
# What it does:
#   1. Creates user `scrt4-release` (no login shell for humans, SSH-only)
#   2. Generates an ed25519 keypair at /home/scrt4-release/.ssh/id_ed25519
#      The public key goes in authorized_keys; the PRIVATE key must be
#      copied into the repo's GitHub Actions secrets as SCRT4_RELEASE_SSH_KEY.
#   3. Puts `scrt4-release` in the `www-data` group so files it writes are
#      group-readable by Caddy out of the box.
#   4. Creates /var/www/install/releases/ with 2775 perms + setgid so new
#      files inherit the www-data group.
#   5. Prints the SSH public key + known_hosts line so you can paste them
#      into the GitHub repo secrets.
#
# After running, add these to the scrt4 repo's Settings → Secrets → Actions:
#   SCRT4_RELEASE_SSH_KEY         — contents of /home/scrt4-release/.ssh/id_ed25519
#   SCRT4_RELEASE_SSH_HOST        — the IP or hostname used by CI to reach the server
#   SCRT4_RELEASE_SSH_USER        — scrt4-release
#   SCRT4_RELEASE_SSH_KNOWN_HOSTS — the ssh-keyscan output printed at the end

set -euo pipefail

USER_NAME="scrt4-release"
HOME_DIR="/home/${USER_NAME}"
RELEASES_DIR="/var/www/install/releases"
# Caddy also serves the auth relay's static files out of this dir; the same
# deploy user pushes auth.html updates here from the deploy-relay.yml workflow.
# Kept as a separate variable so a future split (different user) is a one-liner.
RELAY_PUBLIC_DIR="/home/jgott/scrt4-relay/public"

if [ "$(id -u)" -ne 0 ]; then
    echo "server-setup-release-user: must be run as root (sudo)" >&2
    exit 1
fi

# 1. Create user (idempotent).
if ! id "$USER_NAME" >/dev/null 2>&1; then
    useradd --system --create-home --home-dir "$HOME_DIR" \
            --shell /usr/sbin/nologin \
            --comment "scrt4 release deploy user" \
            "$USER_NAME"
    echo "created user $USER_NAME"
else
    echo "user $USER_NAME already exists"
fi

# 2. Give the deploy user a real shell — SSH needs one to exec scp/ssh commands.
# /usr/sbin/nologin blocks all SSH commands including scp. Use /bin/bash, but
# keep interactive login disabled via the `command=` restriction in authorized_keys.
usermod --shell /bin/bash "$USER_NAME"

# 3. Add to www-data group so files it writes are readable by Caddy.
if command -v getent >/dev/null 2>&1 && getent group www-data >/dev/null 2>&1; then
    usermod -aG www-data "$USER_NAME"
    echo "added $USER_NAME to www-data group"
else
    echo "server-setup-release-user: WARN — www-data group missing, Caddy may not read files" >&2
fi

# 4. Generate SSH keypair (idempotent).
SSH_DIR="${HOME_DIR}/.ssh"
KEY_PATH="${SSH_DIR}/id_ed25519"
install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "$SSH_DIR"

if [ ! -f "$KEY_PATH" ]; then
    sudo -u "$USER_NAME" ssh-keygen -t ed25519 -N "" -f "$KEY_PATH" -C "scrt4-release@$(hostname)"
    echo "generated keypair at $KEY_PATH"
else
    echo "keypair already exists at $KEY_PATH"
fi

# 5. Seed authorized_keys with this server's own pubkey + a force-command
# restriction so inbound SSH can only upload artifacts — not open a shell.
AUTH_KEYS="${SSH_DIR}/authorized_keys"
PUB_KEY_CONTENT="$(cat "${KEY_PATH}.pub")"

# The force-command wrapper allows scp/sftp and rejects interactive logins.
# We write our own wrapper rather than use `command="internal-sftp"` because
# the CI job runs `ssh $REMOTE "mkdir -p ..."` + `scp` + `ssh $REMOTE "mv ..."`,
# so plain SFTP alone isn't sufficient.
WRAPPER="/usr/local/bin/scrt4-release-ssh-wrapper"
cat > "$WRAPPER" <<'WRAPPER_EOF'
#!/bin/bash
# Restrict scrt4-release SSH to commands the release pipeline actually needs.
#
# Allowed: scp (into /var/www/install/releases), mkdir/mv within that tree.
# Denied:  anything else — including arbitrary shells.
set -euo pipefail

CMD="${SSH_ORIGINAL_COMMAND:-}"

if [ -z "$CMD" ]; then
    echo "scrt4-release: interactive shell not permitted" >&2
    exit 1
fi

case "$CMD" in
    # scp subprocess — binary releases under /var/www/install/releases/
    scp\ -t\ /var/www/install/releases/*|scp\ -t\ -d\ /var/www/install/releases/*)
        exec $CMD
        ;;
    # scp subprocess — relay static assets under /home/jgott/scrt4-relay/public/
    # (auth.html, index.html, sw.js, and any future companion files).
    scp\ -t\ /home/jgott/scrt4-relay/public/*|scp\ -t\ -d\ /home/jgott/scrt4-relay/public/*)
        exec $CMD
        ;;
    # mkdir within releases/ — only allow creating tagged subdirs.
    "mkdir -p '/var/www/install/releases/"*"'")
        exec $CMD
        ;;
    # Atomic rename for latest.txt flip on the releases side.
    "mv '/var/www/install/releases/latest.txt.new' '/var/www/install/releases/latest.txt'")
        exec $CMD
        ;;
    # Atomic file swap on the relay side — used by deploy-relay.yml to flip
    # each *.new upload into place without a torn read by Caddy.
    "mv '/home/jgott/scrt4-relay/public/"*".new' '/home/jgott/scrt4-relay/public/"*"'")
        exec $CMD
        ;;
    *)
        echo "scrt4-release: command rejected by wrapper: $CMD" >&2
        exit 1
        ;;
esac
WRAPPER_EOF
chmod 755 "$WRAPPER"
chown root:root "$WRAPPER"

# Overwrite authorized_keys (not append) to keep this file authoritative.
printf 'command="%s",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty %s\n' \
    "$WRAPPER" "$PUB_KEY_CONTENT" > "$AUTH_KEYS"
chown "$USER_NAME":"$USER_NAME" "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"

# 6. Prepare /var/www/install/releases/ with group-write + setgid so new
# files land with the www-data group automatically.
install -d -m 2775 -o "$USER_NAME" -g www-data "$RELEASES_DIR"
echo "prepared $RELEASES_DIR (2775, $USER_NAME:www-data)"

# 6b. Relay dir: keep owner as jgott (interactive edits still work) but flip
# the group to www-data with setgid + group-write so scrt4-release (a member
# of www-data) can drop new auth.html / index.html files in via scp. The dir
# must already exist — this script does not create it.
if [ -d "$RELAY_PUBLIC_DIR" ]; then
    chgrp www-data "$RELAY_PUBLIC_DIR"
    chmod 2775 "$RELAY_PUBLIC_DIR"
    echo "prepared $RELAY_PUBLIC_DIR (2775, group=www-data, setgid)"
else
    echo "server-setup-release-user: WARN — $RELAY_PUBLIC_DIR missing; relay deploys will fail until it exists" >&2
fi

# 7. Print what the operator needs to paste into GitHub Actions secrets.
echo
echo "── ACTION REQUIRED — add these to the scrt4 repo's Actions secrets ──"
echo
echo "SCRT4_RELEASE_SSH_USER:"
echo "  $USER_NAME"
echo
echo "SCRT4_RELEASE_SSH_HOST:"
echo "  <the public IP or FQDN CI should connect to — \$(curl -s ifconfig.me) = $(curl -fsS ifconfig.me 2>/dev/null || echo UNKNOWN)>"
echo
echo "SCRT4_RELEASE_SSH_KEY (private, ed25519):"
echo "------------------------------------------"
cat "$KEY_PATH"
echo "------------------------------------------"
echo
echo "SCRT4_RELEASE_SSH_KNOWN_HOSTS (host key for GHA to pin):"
echo "  ssh-keyscan -H <the host above>"
echo "--- ssh-keyscan preview (localhost) ---"
ssh-keyscan -H localhost 2>/dev/null | head -5
echo "---------------------------------------"
echo
echo "After setting the secrets, push a tag (v*.*.*) and the release.yml"
echo "workflow will build + scp the artifacts into $RELEASES_DIR/<tag>/"
echo "and flip latest.txt in a single atomic mv."
