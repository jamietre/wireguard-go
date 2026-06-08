#!/bin/sh

INSTALL_DIR=/volume1/wireguard
WG_BIN=$INSTALL_DIR/bin/wireguard-go
WG_TOOL=$INSTALL_DIR/bin/wg
CONFIG=$INSTALL_DIR/wg0.conf
INTERFACE=wg0
LOG=/var/log/wireguard.log

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

    WG_PROCESS_FOREGROUND=1 $WG_BIN $INTERFACE >> $LOG 2>&1 &

    # wait for wireguard-go to create the interface socket
    for i in $(seq 1 10); do
        sleep 1
        ip link show $INTERFACE > /dev/null 2>&1 && break
        if [ $i -eq 10 ]; then
            echo "Timed out waiting for $INTERFACE" | tee -a $LOG
            exit 1
        fi
    done

    $WG_TOOL setconf $INTERFACE $CONFIG

    # read Address from config comment/header if present, else fall back
    ADDR=$(grep '^#\?Address\s*=' $CONFIG | head -1 | sed 's/.*=\s*//' | tr -d ' ')
    if [ -n "$ADDR" ]; then
        ip addr add $ADDR dev $INTERFACE
    fi

    ip link set up dev $INTERFACE

    echo "WireGuard $INTERFACE started" | tee -a $LOG
}

stop() {
    if ! ip link show $INTERFACE > /dev/null 2>&1; then
        echo "WireGuard $INTERFACE is not running"
        exit 0
    fi
    ip link delete $INTERFACE
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
