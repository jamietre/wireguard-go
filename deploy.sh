#!/bin/sh
# Deploy WireGuard to Synology RT6600AX
# Usage: ./deploy.sh [router-host] [router-user]

HOST=${1:-172.16.2.1}
USER=${2:-admin}
REMOTE_DIR=/volume1/wireguard

set -e

echo "Deploying to $USER@$HOST:$REMOTE_DIR"

ssh "$USER@$HOST" "mkdir -p $REMOTE_DIR/bin"

scp bin/wireguard-go "$USER@$HOST:$REMOTE_DIR/bin/wireguard-go"
scp bin/wg           "$USER@$HOST:$REMOTE_DIR/bin/wg"
scp rc.d/wireguard.sh "$USER@$HOST:/usr/local/etc/rc.d/wireguard.sh"

ssh "$USER@$HOST" "
  chmod +x $REMOTE_DIR/bin/wireguard-go
  chmod +x $REMOTE_DIR/bin/wg
  chmod +x /usr/local/etc/rc.d/wireguard.sh
"

# Copy config only if it doesn't already exist on the router
ssh "$USER@$HOST" "test -f $REMOTE_DIR/wg0.conf" 2>/dev/null || {
    echo "No config found on router."
    echo "Copy config/wg0.conf.example to $REMOTE_DIR/wg0.conf and fill in keys before starting."
}

echo "Done. To start: ssh $USER@$HOST /usr/local/etc/rc.d/wireguard.sh start"
