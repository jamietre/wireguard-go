#!/bin/sh

INSTALL_DIR=/volume1/wireguard
WG_BIN=$INSTALL_DIR/bin/wireguard-go
WG_TOOL=$INSTALL_DIR/bin/wg
CONFIG=$INSTALL_DIR/wg0.conf
INTERFACE=wg0
LOG=/var/log/wireguard.log
# VPN subnet for MASQUERADE and WAN interface (eth0 on RT6600AX)
WG_SUBNET=10.10.0.0/24
WAN_IF=eth0

start() {
    if ip link show $INTERFACE > /dev/null 2>&1; then
        echo "WireGuard $INTERFACE is already running"
        exit 0
    fi

    if [ ! -f "$CONFIG" ]; then
        echo "WireGuard config not found: $CONFIG" | tee -a $LOG
        exit 1
    fi

    # tun is normally pre-loaded on RT6600AX; load it if missing
    lsmod | grep -q '^tun ' || insmod /lib/modules/tun.ko

    # Start wireguard-go (userspace).
    # WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 is required because
    # this kernel (4.4.60) reports native WireGuard support but the kernel
    # module is not loaded.  Without it, wireguard-go refuses to start.
    WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 \
        $WG_BIN $INTERFACE >> $LOG 2>&1

    # wait for wireguard-go to create the TUN interface
    for i in $(seq 1 10); do
        sleep 1
        ip link show $INTERFACE > /dev/null 2>&1 && break
        if [ $i -eq 10 ]; then
            echo "Timed out waiting for $INTERFACE" | tee -a $LOG
            exit 1
        fi
    done

    $WG_TOOL setconf $INTERFACE $CONFIG

    # read Address from the #Address comment in wg0.conf
    ADDR=$(grep '^#\?Address\s*=' $CONFIG | head -1 | sed 's/.*=\s*//' | tr -d ' ')
    if [ -n "$ADDR" ]; then
        ip addr add $ADDR dev $INTERFACE
    fi

    ip link set up dev $INTERFACE

    # Allow WireGuard UDP packets through SRM's INPUT_FIREWALL chain.
    # Skip if the rule already exists (e.g. added via SRM Security GUI).
    PORT=$(grep 'ListenPort' $CONFIG | awk '{print $3}')
    iptables -C INPUT_FIREWALL -p udp --dport $PORT -j ACCEPT 2>/dev/null || \
        iptables -I INPUT_FIREWALL -p udp --dport $PORT -j ACCEPT

    # NAT VPN subnet out the WAN interface so clients reach the internet.
    # SRM does not manage NAT for custom subnets; this must be done here.
    iptables -t nat -C POSTROUTING -s $WG_SUBNET -o $WAN_IF -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s $WG_SUBNET -o $WAN_IF -j MASQUERADE

    echo "WireGuard $INTERFACE started" | tee -a $LOG
}

stop() {
    if ! ip link show $INTERFACE > /dev/null 2>&1; then
        echo "WireGuard $INTERFACE is not running"
        exit 0
    fi
    PORT=$(grep 'ListenPort' $CONFIG | awk '{print $3}')
    iptables -D INPUT_FIREWALL -p udp --dport $PORT -j ACCEPT 2>/dev/null
    iptables -t nat -D POSTROUTING -s $WG_SUBNET -o $WAN_IF -j MASQUERADE 2>/dev/null
    ip link delete $INTERFACE
    pkill -f "wireguard-go.*$INTERFACE" 2>/dev/null || true
    echo "WireGuard $INTERFACE stopped" | tee -a $LOG
}

status() {
    if ip link show $INTERFACE > /dev/null 2>&1; then
        $WG_TOOL show $INTERFACE
    else
        echo "WireGuard $INTERFACE is not running"
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
