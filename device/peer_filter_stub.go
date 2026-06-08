//go:build !wg_peer_filter

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

// peerFilterExt is a zero-size stub when the wg_peer_filter build tag is absent.
type peerFilterExt struct{}

// allowedByFilter always permits traffic when filtering is not compiled in.
func (peer *Peer) allowedByFilter(_ []byte) bool { return true }
