/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

// On Linux < 5.x (e.g. Synology SRM 4.4.x) Go's epoll-based UDP receive is
// unreliable: EPOLLIN events are missed, leaving the receive goroutine stuck
// in epoll_wait forever. Python tests confirmed that poll() + recvmsg()
// (level-triggered, no epoll) works correctly on the same kernel.
//
// makeReceiveIPv4Legacy / makeReceiveIPv6Legacy work around a kernel 4.4.x bug
// (Synology SRM) where epoll never fires EPOLLIN for UDP sockets. poll(2) and
// ppoll(2) are equally broken. However, Go's timer-based deadline mechanism is
// independent of epoll: SetReadDeadline arms a runtime timer that wakes the
// goroutine unconditionally. On wakeup, a non-blocking ReadMsgUDP call reads
// any packet that has been sitting in the socket buffer since epoll last
// (failed to) fire. This gives at most pollInterval of extra latency per
// packet in exchange for working receive on this kernel.

import (
	"net"
	"time"
)

const legacyPollInterval = 10 * time.Millisecond

func (s *StdNetBind) makeReceiveIPv4Legacy(conn *net.UDPConn) ReceiveFunc {
	oobBuf := make([]byte, stickyControlSize)

	return func(bufs [][]byte, sizes []int, eps []Endpoint) (int, error) {
		for {
			conn.SetReadDeadline(time.Now().Add(legacyPollInterval))
			n, oobn, _, from, err := conn.ReadMsgUDP(bufs[0], oobBuf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return 0, err
			}
			sizes[0] = n
			addrPort := from.AddrPort()
			ep := &StdNetEndpoint{AddrPort: addrPort}
			getSrcFromControl(oobBuf[:oobn], ep)
			eps[0] = ep
			return 1, nil
		}
	}
}

func (s *StdNetBind) makeReceiveIPv6Legacy(conn *net.UDPConn) ReceiveFunc {
	oobBuf := make([]byte, stickyControlSize)

	return func(bufs [][]byte, sizes []int, eps []Endpoint) (int, error) {
		for {
			conn.SetReadDeadline(time.Now().Add(legacyPollInterval))
			n, oobn, _, from, err := conn.ReadMsgUDPAddrPort(bufs[0], oobBuf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return 0, err
			}
			sizes[0] = n
			ep := &StdNetEndpoint{AddrPort: from}
			getSrcFromControl(oobBuf[:oobn], ep)
			eps[0] = ep
			return 1, nil
		}
	}
}
