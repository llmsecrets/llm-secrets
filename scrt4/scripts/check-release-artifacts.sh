#!/usr/bin/env bash
#
# check-release-artifacts.sh DAEMON CLI
#
# Verifies that a built daemon and CLI are fit to publish. Run against the
# artifacts themselves, on the platform they were built for.
#
# It answers one question the build alone cannot: does every command the CLI
# can issue reach a handler that exists? A command whose handler was removed
# still parses, still registers, and still looks fine in review — it only
# fails when someone runs it. That shipped once: `lock`, `clear` and `logout`
# all sent a method the protocol never defined, so locking the vault was a
# silent no-op.
#
# Unlock needs a hardware authenticator, so this deliberately does not test
# the authenticated paths. It tests routing, which is what breaks silently.
set -euo pipefail

DAEMON="${1:?usage: check-release-artifacts.sh DAEMON CLI}"
CLI="${2:?usage: check-release-artifacts.sh DAEMON CLI}"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/scrt4-check.XXXXXX")
export XDG_RUNTIME_DIR="$WORK"
SOCKET="$WORK/scrt4.sock"
FAILED=0

cleanup() {
    [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "== artifacts"
chmod +x "$DAEMON" "$CLI"
file "$DAEMON" | sed 's/^/   /'
bash -n "$CLI" && echo "   CLI syntax OK"

echo "== daemon starts"
HOME="$WORK" "$DAEMON" >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do
    [ -S "$SOCKET" ] && break
    sleep 0.2
done
if [ ! -S "$SOCKET" ]; then
    echo "   FAIL: no socket at $SOCKET after 10s"
    sed 's/^/   | /' "$WORK/daemon.log"
    exit 1
fi
kill -0 "$DAEMON_PID" 2>/dev/null || { echo "   FAIL: daemon exited"; exit 1; }
echo "   listening at $SOCKET"

# One round-trip per method, straight to the socket. Going through the CLI
# would not work here: for most commands it refuses before it sends anything,
# so the RPC that matters is never exercised.
send() {
    python3 - "$SOCKET" "$1" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(sys.argv[1])
s.sendall((sys.argv[2] + "\n").encode())
buf = b""
while b"\n" not in buf:
    chunk = s.recv(65536)
    if not chunk:
        break
    buf += chunk
print(buf.decode(errors="replace").strip())
PY
}

echo "== status responds"
resp=$(send '{"method":"status"}')
case "$resp" in
    *'"success":true'*) echo "   $resp" ;;
    *) echo "   FAIL: $resp"; FAILED=1 ;;
esac

echo "== a method that does not exist is rejected"
# Proves the assertion below can actually fail. Without this the whole check
# passes vacuously if the error text ever changes.
resp=$(send '{"method":"definitely_not_a_method"}')
case "$resp" in
    *'Invalid request'*) echo "   rejected as expected" ;;
    *) echo "   FAIL: unknown method was not rejected: $resp"; FAILED=1 ;;
esac

echo "== the command surface has not shrunk"
# v0.4.4 shipped without `upgrade`. A branch cut before that feature landed
# carried an older copy of the client and silently reverted it on merge, and
# nothing here noticed: the build succeeded, every method still routed, and
# the only symptom was a command that no longer existed. Losing a command is
# not a routing failure, so it needs its own check.
#
# This list is a floor, not an inventory. Adding a command does not require
# touching it; removing one is meant to be a deliberate edit here.
REQUIRED="add backup-key backup-vault clear extend help list lock logout
          recover run setup status unlock upgrade verify-self view"
missing=""
for want in $REQUIRED; do
    grep -qE "_register_command[ 	]+${want}\b" "$CLI" || missing="$missing $want"
done
if [ -n "$missing" ]; then
    echo "   FAIL: the CLI no longer registers:$missing"
    FAILED=1
else
    echo "   all $(echo $REQUIRED | wc -w | tr -d ' ') required commands present"
fi

echo "== every method the CLI can send is routable"
# Two spellings, and missing the second one makes this check pass vacuously:
# requests written as raw JSON use "method":"x", but those built through jq
# use bare object keys — method:"x". Roughly half the surface is the jq form.
METHODS=$(grep -oE '"?method"?[[:space:]]*:[[:space:]]*"[a-z_]+"' "$CLI" \
    | sed 's/.*"\([a-z_]*\)"$/\1/' | sort -u)
COUNT=$(printf '%s\n' "$METHODS" | grep -c . || true)
[ "$COUNT" -ge 15 ] || {
    echo "   FAIL: only $COUNT methods found in the CLI — extraction is wrong,"
    echo "         not the CLI. A real client sends more than that."
    exit 1
}
for m in $METHODS; do
    resp=$(send "{\"method\":\"$m\"}")
    case "$resp" in
        *'Invalid request'*)
            # Distinguish "no such method" from "wrong params for a real
            # method" — only the first is a broken command.
            case "$resp" in
                *'unknown variant'*)
                    printf '   %-26s UNROUTABLE -- no handler\n' "$m"; FAILED=1 ;;
                *)
                    printf '   %-26s ok (needs params)\n' "$m" ;;
            esac ;;
        *) printf '   %-26s ok\n' "$m" ;;
    esac
done

echo
if [ "$FAILED" -ne 0 ]; then
    echo "RESULT: FAILED"
    exit 1
fi
echo "RESULT: PASS -- $COUNT methods, all routable"
