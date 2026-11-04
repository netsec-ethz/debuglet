// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

func (e *WasmEnv) scionQUICOwnsListener() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.scionQUICUsed
}

func (e *WasmEnv) stopSCIONQUICEcho() error {
	e.scionQUICMu.Lock()
	defer e.scionQUICMu.Unlock()
	if e.scionQUICEcho == nil {
		return nil
	}
	err := e.scionQUICEcho.Close()
	e.scionQUICEcho = nil
	return err
}

func scionQUICHooks(e *WasmEnv) socket.SCIONQUICHooks {
	return socket.SCIONQUICHooks{
		Admit: func(ctx context.Context, peer pan.UDPAddr) error { _, err := scionPeer(ctx, e, peer); return err },
		Account: func(ctx context.Context, peer pan.UDPAddr, out bool, n int) error {
			match, err := scionPeer(ctx, e, peer)
			if err != nil {
				return err
			}
			direction := app.TransferIn
			if out {
				direction = app.TransferOut
			}
			return e.Accountant.Account(ctx, direction, match.Key, n)
		},
	}
}

func runSCIONQUIC(runCtx, opCtx context.Context, e *WasmEnv, operation string, req guestio.SCIONRequest) (result guestio.SCIONResponse, err error) {
	switch operation {
	case guestio.SCIONQUICEchoStop:
		return result, e.stopSCIONQUICEcho()
	case guestio.SCIONQUICEchoStart:
		if err := e.Net.AvailableListener(netpolicy.SCION); err != nil {
			return result, err
		}
		e.scionQUICMu.Lock()
		defer e.scionQUICMu.Unlock()
		if err := e.scionListenerMu.Lock(opCtx); err != nil {
			return result, err
		}
		defer e.scionListenerMu.Unlock()
		e.mu.Lock()
		if e.closed || e.ScionServer == nil {
			e.mu.Unlock()
			return result, net.ErrClosed
		}
		if e.scionQUICUsed {
			e.mu.Unlock()
			return result, fmt.Errorf("SCION QUIC echo may start once per run")
		}
		e.scionQUICUsed = true
		listener := e.ScionServer
		e.mu.Unlock()
		service, err := socket.NewSCIONQUICEcho(runCtx, listener, scionQUICHooks(e))
		if err != nil {
			return result, err
		}
		e.scionQUICEcho = service
		if err := opCtx.Err(); err != nil {
			_ = service.Close()
			e.scionQUICEcho = nil
			return result, context.Cause(opCtx)
		}
		result.QUICListener = &guestio.SCIONQUICListener{Address: service.Address(), CertificateSHA256: service.CertificateSHA256()}
		return result, nil
	case guestio.SCIONQUICExchangeFunction:
		if req.TimeoutNS > int64(10*time.Second) {
			return result, fmt.Errorf("SCION QUIC exchange timeout exceeds 10 seconds")
		}
		pin, err := hex.DecodeString(req.CertificateSHA256)
		if err != nil || len(pin) != 32 || req.PathID == "" {
			return result, fmt.Errorf("exact SCION path and SHA256 certificate pin required")
		}
		sc, _, err := scionConn(opCtx, e, req.Address)
		if err != nil {
			return result, err
		}
		var local netip.AddrPort
		var target pan.UDPAddr
		var path *pan.Path
		err = sc.WithLock(opCtx, func(conn pan.Conn, selector *socket.PathSelector) error {
			var err error
			path, _, err = selectSCIONPath(conn, selector, req.PathID)
			if err != nil {
				return err
			}
			addr, ok := conn.LocalAddr().(pan.UDPAddr)
			if !ok {
				return fmt.Errorf("invalid local SCION address")
			}
			local = netip.AddrPortFrom(addr.IP, 0)
			target, ok = conn.RemoteAddr().(pan.UDPAddr)
			if !ok {
				return fmt.Errorf("invalid remote SCION address")
			}
			return nil
		})
		if err != nil {
			return result, err
		}
		reservation, err := e.Budget.ReserveSocket(1)
		if err != nil {
			return result, err
		}
		defer reservation.Release()
		reply, err := socket.SCIONQUICExchange(opCtx, local, target, path, req.CertificateSHA256, req.Payload, scionQUICHooks(e))
		result.QUICExchange = &guestio.SCIONQUICExchange{Data: reply.Data, Sender: target.String(), HandshakeMS: reply.HandshakeMS, DurationMS: reply.DurationMS, Verified: reply.Verified}
		if reply.OutboundSent {
			result.QUICExchange.PathID = req.PathID
		}
		return result, err
	default:
		return result, fmt.Errorf("unknown SCION QUIC operation")
	}
}
