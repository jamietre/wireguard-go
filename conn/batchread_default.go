//go:build !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

// batchReadWorks is only relevant on Linux; other platforms use ReadMsgUDP
// via the else branch in receiveIP anyway.
var batchReadWorks = false
