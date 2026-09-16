// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package hostconn

import (
	"context"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func (h *HostConn) Drain(ctx context.Context) {
	tcpConn, ok := h.conn.(*net.TCPConn)
	if !ok {
		return
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return
	}
	for {
		var (
			info *unix.TCPInfo
			err  error
		)
		rawConn.Control(func(fd uintptr) {
			info, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		})

		if err != nil || info == nil || info.Notsent_bytes == 0 {
			return
		}

		estDuration := 200 * time.Millisecond
		if h.limit > 0 {
			estDuration = time.Duration(float64(info.Notsent_bytes) / float64(h.limit) * float64(time.Second))
		}
		waitFor := max(min(time.Second, estDuration/2), 10*time.Millisecond)

		select {
		case <-time.After(waitFor):
		case <-ctx.Done():
			return
		}
	}
}
