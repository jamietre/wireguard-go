#!/bin/sh
# Restore post-firmware-update configuration on Synology RT6600AX.
# Must be run as admin (root), not via sudo — jamiet's sudo access is
# one of the things being restored.
# Usage: ssh admin@router 'sh /volume1/wireguard/restore.sh'

INSTALL_DIR=/volume1/wireguard
PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqnaxlGHNK5FBGrJaboQFSWuX3X+sx8VwVRXrpSsVVl jamie@LENOVO-X1-7"

set -e

echo "==> Restoring sudoers for jamiet"
grep -q '^jamiet ' /etc/sudoers 2>/dev/null || \
    echo 'jamiet ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

echo "==> Restoring SSH keys"
for USER in jamiet claude; do
    mkdir -p /etc/ssh/keys/$USER
    echo "$PUBKEY" > /etc/ssh/keys/$USER/authorized_keys
    chmod 700 /etc/ssh/keys/$USER
    chmod 600 /etc/ssh/keys/$USER/authorized_keys
    chown -R $USER /etc/ssh/keys/$USER
done

echo "==> Restoring rc.d init script"
cp $INSTALL_DIR/rc.d/wireguard.sh /usr/local/etc/rc.d/wireguard.sh
chmod +x /usr/local/etc/rc.d/wireguard.sh

echo "Done. WireGuard will start automatically on next boot."
echo "To start now: /usr/local/etc/rc.d/wireguard.sh start"
