// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
)

// datagramDeadline bounds one listener operation and joins its cancellation
// callback before resetting the deadline for the next operation.
func datagramDeadline(ctx context.Context, timeout int64, set func(time.Time) error) (context.Context, func(), error) {
	opCtx := ctx
	cancel := func() {}
	if timeout != 0 {
		opCtx, cancel = context.WithTimeout(ctx, time.Duration(timeout))
	}
	deadline, _ := opCtx.Deadline()
	if err := set(deadline); err != nil {
		cancel()
		return nil, nil, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(opCtx, func() { _ = set(time.Now()); close(done) })
	return opCtx, func() {
		if !stop() {
			<-done
		}
		cancel()
		_ = set(time.Time{})
	}, nil
}

// HostIOReceiveUDP receives an entire datagram before applying admission and
// accounting. metadata stores source length, original payload length, and a
// truncation flag as three uint32 values; the result counts copied bytes.
func HostIOReceiveUDP(env *WasmEnv) func(context.Context, Memory, uint32, uint32, uint32, uint32, uint32, int64) uint64 {
	return func(ctx context.Context, mem Memory, ptr, length, sender, senderLength, metadata uint32, timeout int64) uint64 {
		if _, err := extractMem[byte](mem, ptr, length); err != nil {
			panic(err)
		}
		if _, err := extractMem[byte](mem, sender, senderLength); err != nil {
			panic(err)
		}
		if _, err := extractMem[byte](mem, metadata, 12); err != nil {
			panic(err)
		}
		if err := env.Net.AvailableListener(netpolicy.UDP); err != nil {
			return ioResult(0, err)
		}
		listener := env.UdpServer
		if listener == nil {
			return ioResult(0, net.ErrClosed)
		}
		opCtx, finish, err := datagramDeadline(ctx, timeout, listener.SetReadDeadline)
		if err != nil {
			return ioResult(0, err)
		}
		defer finish()
		// The complete legal UDP payload fits here, even when the guest asks
		// for only a prefix. Charge the full admitted payload, never the prefix.
		buf := make([]byte, 65535)
		for {
			if err := opCtx.Err(); err != nil {
				return ioResult(0, context.Cause(opCtx))
			}
			n, from, err := listener.ReadFromUDPAddrPort(buf)
			if err != nil {
				if opCtx.Err() != nil {
					err = context.Cause(opCtx)
				}
				return ioResult(0, err)
			}
			match, err := env.Net.AdmitAddr(opCtx, netpolicy.Inbound, from)
			if err != nil {
				continue
			}
			if err = env.Accountant.Account(opCtx, app.TransferIn, match.Key, n); err != nil {
				return ioResult(0, err)
			}
			if opCtx.Err() != nil {
				return ioResult(0, context.Cause(opCtx))
			}
			if _, err = env.Net.AdmitAddr(opCtx, netpolicy.Inbound, from); err != nil {
				continue
			}
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			addr := from.String()
			if uint32(len(addr)) > senderLength {
				return ioResult(0, io.ErrShortBuffer)
			}
			copied := min(n, int(length), MAX_SLICE_LENGTH)
			var truncated uint32
			if copied < n {
				truncated = 1
			}
			if !mem.Write(ptr, buf[:copied]) || !mem.Write(sender, []byte(addr)) ||
				!mem.WriteUint32Le(metadata, uint32(len(addr))) || !mem.WriteUint32Le(metadata+4, uint32(n)) || !mem.WriteUint32Le(metadata+8, truncated) {
				panic("failed to write UDP receive result")
			}
			env.mu.Lock()
			env.udpReplyPeer = from
			env.mu.Unlock()
			return ioResult(copied, nil)
		}
	}
}

// HostIOReplyUDP sends one bounded datagram from the allocated listener. The
// destination is admitted again for outbound UDP, including its port. Listener
// traffic uses the shared Accountant, rather than attaching the shared listener
// to one peer's packet-counter entry. The temporary raw tagging socket is
// quota-reserved and closed before returning; the listener stays open.
func HostIOReplyUDP(env *WasmEnv) func(context.Context, Memory, uint32, uint32, uint32, uint32, int64) uint64 {
	return func(ctx context.Context, mem Memory, addrPtr, addrLen, ptr, length uint32, timeout int64) uint64 {
		address, err := extractStr(mem, addrPtr, addrLen)
		if err != nil {
			panic(err)
		}
		if length > MAX_SLICE_LENGTH {
			panic("UDP reply exceeds host transfer bound")
		}
		payload, err := extractMem[byte](mem, ptr, length)
		if err != nil {
			panic(err)
		}
		if err := env.Net.AvailableListener(netpolicy.UDP); err != nil {
			return ioResult(0, err)
		}
		listener := env.UdpServer
		if listener == nil {
			return ioResult(0, net.ErrClosed)
		}
		peer, err := netip.ParseAddrPort(address)
		if err != nil || peer.Port() == 0 {
			return ioResult(0, netpolicy.ErrDenied)
		}
		peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
		env.mu.Lock()
		received := env.udpReplyPeer
		env.mu.Unlock()
		if peer != received {
			return ioResult(0, netpolicy.ErrDenied)
		}
		opCtx := ctx
		if timeout != 0 {
			var cancel context.CancelFunc
			opCtx, cancel = context.WithTimeout(ctx, time.Duration(timeout))
			defer cancel()
		}
		if err := opCtx.Err(); err != nil {
			return ioResult(0, context.Cause(opCtx))
		}
		match, err := env.Net.AdmitAddr(opCtx, netpolicy.UDP, peer)
		if err != nil {
			return ioResult(0, err)
		}
		// The existing listener is already reserved. Two temporary slots cover
		// a route-selection socket and the userspace tagger's raw sending socket.
		reservation, err := env.Registry.Reserve(2)
		if err != nil {
			return ioResult(0, err)
		}
		defer reservation.Release()
		remote := net.UDPAddrFromAddrPort(peer)
		conn := tagger.UDPReplyConn(listener, remote)
		if tagging, ok := env.Tagger.(interface {
			WrapUDPReply(*net.UDPConn, *net.UDPAddr) (net.Conn, error)
		}); ok {
			conn, err = tagging.WrapUDPReply(listener, remote)
			if err != nil {
				return ioResult(0, fmt.Errorf("%w: %w", netpolicy.ErrUntagged, err))
			}
		}
		defer func() { env.RecordCleanupError(conn.Close()) }()
		opCtx, finish, err := datagramDeadline(opCtx, 0, conn.SetWriteDeadline)
		if err != nil {
			return ioResult(0, err)
		}
		defer finish()
		if err = env.Accountant.Account(opCtx, app.TransferOut, match.Key, len(payload)); err != nil {
			return ioResult(0, err)
		}
		// Admission may have changed while waiting for bandwidth.
		if _, err = env.Net.AdmitAddr(opCtx, netpolicy.UDP, peer); err != nil {
			return ioResult(0, err)
		}
		if err = env.Net.Egress().Charge(len(payload)); err != nil {
			return ioResult(0, err)
		}
		if opCtx.Err() != nil {
			return ioResult(0, context.Cause(opCtx))
		}
		n, err := conn.Write(payload)
		if err != nil && opCtx.Err() != nil {
			err = context.Cause(opCtx)
		}
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		return ioResult(n, err)
	}
}
