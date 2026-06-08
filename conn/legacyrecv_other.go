//go:build !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "net"

func (s *StdNetBind) makeReceiveIPv4Legacy(conn *net.UDPConn) ReceiveFunc {
	return s.makeReceiveIPv4(nil, conn, false)
}

func (s *StdNetBind) makeReceiveIPv6Legacy(conn *net.UDPConn) ReceiveFunc {
	return s.makeReceiveIPv6(nil, conn, false)
}
