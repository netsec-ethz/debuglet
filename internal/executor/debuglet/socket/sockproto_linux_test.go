// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package socket

import "syscall"

// socketProtocol reports the socket's protocol, so a test can tell a plain
// TCP listener from a Multipath TCP one.
func socketProtocol(fd int) (proto int, known bool, err error) {
	proto, err = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_PROTOCOL)
	return proto, true, err
}
