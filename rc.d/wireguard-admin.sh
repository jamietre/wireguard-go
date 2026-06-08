#!/bin/sh
#
# WireGuard peer admin UI — runs on port 8080 (LAN only).
#
# Required flags:
#   -endpoint <WAN-IP-or-hostname>:51822   (public endpoint for client configs)
#
# Optional:
#   -srm-sessions <path>    SRM active session file. When set, users already
#                           logged in to SRM are admitted automatically.
#                           Falls back to local login form (/etc/shadow) otherwise.
#
# Session file confirmed on RT6600AX: /usr/syno/etc/private/session/current.users
# Each line is a JSON object with "id" (cookie) and "name" (username).
# Reading directly avoids the IP-binding issue with SRM's API-based auth.

INSTALL_DIR=/volume1/wireguard
BINARY=$INSTALL_DIR/bin/wg-admin
LOG=/var/log/wireguard-admin.log
PIDFILE=/var/run/wireguard-admin.pid

# ── Edit these to match your deployment ──────────────────────────────────────
ENDPOINT="71.181.45.226:51822"
SRM_SESSIONS="/usr/syno/etc/private/session/current.users"
ADDR="0.0.0.0:8080"
DNS="172.16.2.1"
# ─────────────────────────────────────────────────────────────────────────────

start() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "wireguard-admin is already running"
        exit 0
    fi
    if [ ! -x "$BINARY" ]; then
        echo "wg-admin binary not found: $BINARY"
        exit 1
    fi
    if [ -z "$ENDPOINT" ]; then
        echo "ENDPOINT not set in $0"
        exit 1
    fi

    ARGS="-endpoint $ENDPOINT -addr $ADDR -dns $DNS"
    [ -n "$SRM_SESSIONS" ] && ARGS="$ARGS -srm-sessions $SRM_SESSIONS"

    $BINARY $ARGS >> $LOG 2>&1 &
    echo $! > "$PIDFILE"
    echo "wireguard-admin started (pid $(cat $PIDFILE)) → http://$ADDR"
}

stop() {
    if [ ! -f "$PIDFILE" ]; then
        echo "wireguard-admin is not running"
        exit 0
    fi
    pid=$(cat "$PIDFILE")
    kill "$pid" 2>/dev/null && rm -f "$PIDFILE"
    echo "wireguard-admin stopped"
}

status() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "wireguard-admin is running (pid $(cat $PIDFILE))"
    else
        echo "wireguard-admin is not running"
    fi
}

case "$1" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; sleep 1; start ;;
    status)  status ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
