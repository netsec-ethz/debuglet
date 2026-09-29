// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build unix

package netpolicy

import "syscall"

// probePingSocket opens and closes one unprivileged ICMPv4 datagram ("ping")
// socket. It is not bound or connected and sends nothing. Linux permits it to
// the groups in net.ipv4.ping_group_range.
func probePingSocket() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		return err
	}
	return syscall.Close(fd)
}
