// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package hostconn

import (
	"context"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Drain keeps the legacy guest ABI; recoverable socket close reports failures.
func (h *HostConn) Drain(ctx context.Context) { _ = h.DrainTCP(ctx) }

// DrainTCP lets the kernel finish queued TCP writes before accounting is
// detached. Kernel acknowledgements do not require the peer's application to
// read, so peers can both send before receiving without a protocol deadlock.
// Forced close and destination revocation bypass this bounded guest operation.
func (h *HostConn) DrainTCP(ctx context.Context) error {
	if h.tcp == nil {
		return nil
	}
	deadline := time.Now().Add(2 * time.Second)
	h.deadlineMu.Lock()
	if !h.writeDeadline.IsZero() && h.writeDeadline.Before(deadline) {
		deadline = h.writeDeadline
	}
	h.deadlineMu.Unlock()
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	raw, err := h.tcp.SyscallConn()
	if err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var info *unix.TCPInfo
		var infoErr error
		var socketErr int
		if err := raw.Control(func(fd uintptr) {
			info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
			if infoErr == nil && info.State == unix.BPF_TCP_CLOSE {
				socketErr, infoErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR)
			}
		}); err != nil {
			return err
		}
		if infoErr != nil {
			return infoErr
		}
		// A reset also empties the send queue; it is not a delivery ACK.
		if info.State == unix.BPF_TCP_CLOSE {
			if socketErr != 0 {
				return syscall.Errno(socketErr)
			}
			return net.ErrClosed
		}
		if info.Notsent_bytes == 0 && info.Unacked == 0 {
			return nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}
