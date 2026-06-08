/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

// batchReadWorks reports whether recvmmsg via rawConn.RawRead is reliable on
// this kernel. On Linux < 5.x (e.g. Synology SRM 4.4.x), recvmmsg returns
// EAGAIN even when data is present, causing wireguard-go's receive goroutine
// to stall indefinitely. Fall back to ReadMsgUDP (recvmsg) on old kernels.
var batchReadWorks = func() bool {
	major, _ := kernelVersion()
	return major >= 5
}()
