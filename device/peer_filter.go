//go:build wg_peer_filter

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import "net"

// peerFilterExt holds the list of destination subnets this peer is permitted
// to reach. An empty slice means no restriction (permit all).
type peerFilterExt struct {
	permittedSubnets []net.IPNet
}

const (
	ipv4OffsetDst = 16 // IPv4 header: dst starts at byte 16
	ipv6OffsetDst = 24 // IPv6 header: dst starts at byte 24
)

// allowedByFilter checks the packet's destination IP against permittedSubnets.
// Returns true (allow) when the peer has no restrictions, or when the
// destination falls within at least one permitted subnet.
func (peer *Peer) allowedByFilter(packet []byte) bool {
	if len(peer.permittedSubnets) == 0 {
		return true
	}
	if len(packet) == 0 {
		return false
	}
	var dst net.IP
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < ipv4OffsetDst+net.IPv4len {
			return false
		}
		dst = net.IP(packet[ipv4OffsetDst : ipv4OffsetDst+net.IPv4len])
	case 6:
		if len(packet) < ipv6OffsetDst+net.IPv6len {
			return false
		}
		dst = net.IP(packet[ipv6OffsetDst : ipv6OffsetDst+net.IPv6len])
	default:
		return false
	}
	for i := range peer.permittedSubnets {
		if peer.permittedSubnets[i].Contains(dst) {
			return true
		}
	}
	return false
}
