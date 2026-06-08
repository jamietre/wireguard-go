#!/bin/sh
# Deploy WireGuard to Synology RT6600AX
# Usage: ./deploy.sh [router-host] [router-user]

HOST=${1:-172.16.2.1}
USER=${2:-jamiet}
REMOTE_DIR=/volume1/wireguard

set -e

echo "Deploying to $USER@$HOST:$REMOTE_DIR"

ssh "$USER@$HOST" "sudo mkdir -p $REMOTE_DIR/bin $REMOTE_DIR/rc.d"

ssh "$USER@$HOST" "cat > /tmp/wireguard-go"   < bin/wireguard-go
ssh "$USER@$HOST" "cat > /tmp/wg"            < bin/wg
ssh "$USER@$HOST" "cat > /tmp/wireguard-rc.sh" < rc.d/wireguard.sh
ssh "$USER@$HOST" "cat > /tmp/restore.sh"    < restore.sh

ssh "$USER@$HOST" "
  sudo mv /tmp/wireguard-go  $REMOTE_DIR/bin/wireguard-go
  sudo mv /tmp/wg            $REMOTE_DIR/bin/wg
  sudo mv /tmp/wireguard-rc.sh $REMOTE_DIR/rc.d/wireguard.sh
  sudo mv /tmp/restore.sh    $REMOTE_DIR/restore.sh
  sudo chmod +x $REMOTE_DIR/bin/wireguard-go $REMOTE_DIR/bin/wg
  sudo chmod +x $REMOTE_DIR/rc.d/wireguard.sh $REMOTE_DIR/restore.sh

  # install rc.d script into live location
  sudo cp $REMOTE_DIR/rc.d/wireguard.sh /usr/local/etc/rc.d/wireguard.sh
  sudo chmod +x /usr/local/etc/rc.d/wireguard.sh
"

# Copy config only if it doesn't already exist on the router
ssh "$USER@$HOST" "test -f $REMOTE_DIR/wg0.conf" 2>/dev/null || {
    echo "No config found on router."
    echo "Copy config/wg0.conf.example to $REMOTE_DIR/wg0.conf and fill in keys before starting."
}

echo "Done. To start: ssh $USER@$HOST sudo /usr/local/etc/rc.d/wireguard.sh start"
