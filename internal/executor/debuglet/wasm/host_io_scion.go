// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

// A listener operation owns its deadline and last-received peer together.
// Cancellation while another operation is pending must not block a host call.
type scionOperationLock struct {
	once sync.Once
	gate chan struct{}
}

func (l *scionOperationLock) Lock(ctx context.Context) error {
	l.once.Do(func() { l.gate = make(chan struct{}, 1) })
	select {
	case l.gate <- struct{}{}:
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	if ctx.Err() != nil {
		l.Unlock()
		return context.Cause(ctx)
	}
	return nil
}
func (l *scionOperationLock) Unlock() { <-l.gate }

// SCION operations use the same bounded JSON convention as mesh services. Each
// request completes before returning, and no guest memory is retained.
func hostSCION(env *WasmEnv, operation string) func(context.Context, Memory, uint32, uint32, uint32, uint32) uint64 {
	return func(ctx context.Context, mem Memory, ptr, size, out, capacity uint32) uint64 {
		if size > MAX_SLICE_LENGTH || capacity < guestio.SCIONBufferSize {
			return ioResult(0, fmt.Errorf("SCION buffer bounds"))
		}
		if uint64(out)+guestio.SCIONBufferSize > 1<<32 {
			panic("invalid SCION output buffer")
		}
		if _, ok := mem.Read(out, 1); !ok {
			panic("invalid SCION output buffer")
		}
		if _, ok := mem.Read(out+guestio.SCIONBufferSize-1, 1); !ok {
			panic("invalid SCION output buffer")
		}
		raw, err := extractMem[byte](mem, ptr, size)
		if err != nil {
			panic(err)
		}
		var req guestio.SCIONRequest
		if err := meshDecode(raw, &req); err != nil {
			return ioResult(0, err)
		}
		if req.TimeoutNS < 0 || len(req.Payload) > guestio.SCIONMaxPayload || len(req.Address) > 256 || len(req.PathID) > 256 {
			return ioResult(0, fmt.Errorf("SCION request bounds"))
		}
		if (operation == guestio.SCIONReceive || operation == guestio.SCIONExchangeFunction) && (req.MaxBytes < 1 || req.MaxBytes > guestio.SCIONMaxPayload) {
			return ioResult(0, fmt.Errorf("SCION receive size bounds"))
		}
		opCtx, cancel := probeDeadline(ctx, req.TimeoutNS)
		defer cancel()
		if _, ok := opCtx.Deadline(); !ok {
			return ioResult(0, fmt.Errorf("SCION operation requires a deadline"))
		}
		var result guestio.SCIONResponse
		var operationErr error
		if operation == guestio.SCIONQUICEchoStart || operation == guestio.SCIONQUICEchoStop || operation == guestio.SCIONQUICExchangeFunction {
			result, operationErr = runSCIONQUIC(ctx, opCtx, env, operation, req)
		} else {
			result, operationErr = runSCION(opCtx, env, operation, req)
		}
		if errors.Is(operationErr, socket.ErrSCIONQUICCertificate) {
			result.Error = "SCION QUIC certificate did not match the required pin"
		}
		if errors.Is(operationErr, socket.ErrSCIONPathUnavailable) {
			result.Error = "SCION path is unavailable or expired; discover paths again"
		}
		if errors.Is(operationErr, socket.ErrSCIONPathInvalid) {
			result.Error = "Invalid SCION path identifier"
		}
		data, err := json.Marshal(result)
		if err != nil {
			return ioResult(0, err)
		}
		if len(data) > guestio.SCIONBufferSize {
			return ioResult(0, io.ErrShortBuffer)
		}
		for offset := 0; offset < len(data); {
			end := min(offset+MAX_SLICE_LENGTH, len(data))
			if !mem.Write(out+uint32(offset), data[offset:end]) {
				panic("invalid SCION output buffer")
			}
			offset = end
		}
		return ioResult(len(data), operationErr)
	}
}

func runSCION(ctx context.Context, env *WasmEnv, operation string, req guestio.SCIONRequest) (result guestio.SCIONResponse, err error) {
	if err := ctx.Err(); err != nil {
		return result, context.Cause(ctx)
	}
	switch operation {
	case guestio.SCIONPaths, guestio.SCIONSelectPath, guestio.SCIONExchangeFunction:
		if operation != guestio.SCIONPaths && req.PathID == "" {
			return result, fmt.Errorf("SCION path ID required")
		}
		sc, match, err := scionConn(ctx, env, req.Address)
		if err != nil {
			return result, err
		}
		err = sc.WithLock(ctx, func(conn pan.Conn, selector *socket.PathSelector) error {
			if operation == guestio.SCIONPaths {
				local, ok := scionLocalPath(conn)
				if ok {
					result.Paths = []guestio.SCIONPath{local}
					return nil
				}
				result.Paths = []guestio.SCIONPath{}
				paths := selector.Paths()
				if len(paths) > 32 {
					return fmt.Errorf("SCION path list exceeds 32 paths")
				}
				for _, path := range paths {
					result.Paths = append(result.Paths, socket.DescribeSCIONPath(path))
				}
				return nil
			}
			path, description, err := selectSCIONPath(conn, selector, req.PathID)
			if err != nil {
				return err
			}
			if operation == guestio.SCIONSelectPath {
				result.Path = &description
				return nil
			}
			exchange, err := exchangeSCION(ctx, env, conn, path, description.ID, match, req)
			result.Exchange = &exchange
			return err
		})
		return result, err
	case guestio.SCIONListenerAddressFunction, guestio.SCIONReceive, guestio.SCIONReply:
		if err := env.Net.AvailableListener(netpolicy.SCION); err != nil {
			return result, err
		}
		if err := env.scionListenerMu.Lock(ctx); err != nil {
			return result, err
		}
		defer env.scionListenerMu.Unlock()
		if err := ctx.Err(); err != nil {
			return result, context.Cause(ctx)
		}
		if env.scionQUICOwnsListener() {
			return result, netpolicy.ErrDenied
		}
		listener := env.ScionServer
		if listener == nil {
			return result, net.ErrClosed
		}
		if operation == guestio.SCIONListenerAddressFunction {
			result.Address = listener.LocalAddr().String()
			return result, nil
		}
		if operation == guestio.SCIONReceive {
			packet, err := receiveSCION(ctx, env, listener, req.MaxBytes)
			result.Datagram = &packet
			return result, err
		}
		if req.Address == "" || req.Address != env.scionReplyPeer {
			return result, netpolicy.ErrDenied
		}
		peer, err := pan.ParseUDPAddr(req.Address)
		if err != nil {
			return result, err
		}
		match, err := scionPeer(ctx, env, peer)
		if err != nil {
			return result, err
		}
		_, finish, err := datagramDeadline(ctx, 0, listener.SetWriteDeadline)
		if err != nil {
			return result, err
		}
		defer finish()
		if err := env.Accountant.Account(ctx, app.TransferOut, match.Key, len(req.Payload)); err != nil {
			return result, err
		}
		if err := ctx.Err(); err != nil {
			return result, context.Cause(ctx)
		}
		result.Bytes, err = listener.WriteTo(req.Payload, peer)
		if err == nil && result.Bytes != len(req.Payload) {
			err = io.ErrShortWrite
		}
		return result, err
	default:
		return result, fmt.Errorf("unknown SCION operation")
	}
}

func scionLocalPath(conn pan.Conn) (guestio.SCIONPath, bool) {
	local, localOK := conn.LocalAddr().(pan.UDPAddr)
	remote, remoteOK := conn.RemoteAddr().(pan.UDPAddr)
	if !localOK || !remoteOK || local.IA != remote.IA {
		return guestio.SCIONPath{}, false
	}
	return guestio.SCIONPath{ID: guestio.SCIONLocalPath, Source: local.IA.String(), Destination: remote.IA.String(), Interfaces: []guestio.SCIONInterface{}}, true
}

func selectSCIONPath(conn pan.Conn, selector *socket.PathSelector, id string) (*pan.Path, guestio.SCIONPath, error) {
	if local, ok := scionLocalPath(conn); ok {
		if id != guestio.SCIONLocalPath {
			return nil, guestio.SCIONPath{}, socket.ErrSCIONPathUnavailable
		}
		return nil, local, nil
	}
	path, err := selector.SelectPathID(id)
	if err != nil {
		return nil, guestio.SCIONPath{}, err
	}
	return path, socket.DescribeSCIONPath(path), nil
}

func exchangeSCION(ctx context.Context, env *WasmEnv, conn pan.Conn, path *pan.Path, id string, match netpolicy.Match, req guestio.SCIONRequest) (result guestio.SCIONExchange, err error) {
	_, finish, err := datagramDeadline(ctx, 0, conn.SetDeadline)
	if err != nil {
		return result, err
	}
	defer finish()
	if err := env.Accountant.Account(ctx, app.TransferOut, match.Key, len(req.Payload)); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, context.Cause(ctx)
	}
	// Selection is a snapshot. WriteVia ensures a concurrent path refresh cannot
	// substitute a different outbound path between selection and transmission.
	if path != nil && !path.Expiry.After(time.Now()) {
		return result, socket.ErrSCIONPathUnavailable
	}
	started := time.Now()
	n, err := conn.WriteVia(path, req.Payload)
	if err == nil && n != len(req.Payload) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return result, err
	}
	result.PathID, result.Sender = id, conn.RemoteAddr().String()
	buffer := make([]byte, 65535)
	n, err = conn.Read(buffer)
	result.DurationMS = float64(time.Since(started)) / float64(time.Millisecond)
	if err != nil {
		return result, err
	}
	if n < 0 || n > len(buffer) {
		return result, fmt.Errorf("invalid SCION receive length")
	}
	if _, err := scionDestination(ctx, env, req.Address); err != nil {
		return result, err
	}
	if err := env.Accountant.Account(ctx, app.TransferIn, match.Key, n); err != nil {
		return result, err
	}
	return guestio.SCIONExchange{Data: buffer[:min(n, req.MaxBytes)], PathID: id, Sender: conn.RemoteAddr().String(), DurationMS: result.DurationMS, Size: n, Truncated: n > req.MaxBytes}, nil
}

func receiveSCION(ctx context.Context, env *WasmEnv, listener pan.ListenConn, limit int) (guestio.SCIONDatagram, error) {
	_, finish, err := datagramDeadline(ctx, 0, listener.SetReadDeadline)
	if err != nil {
		return guestio.SCIONDatagram{}, err
	}
	defer finish()
	buffer := make([]byte, 65535)
	for {
		if err := ctx.Err(); err != nil {
			return guestio.SCIONDatagram{}, context.Cause(ctx)
		}
		n, from, err := listener.ReadFrom(buffer)
		if err != nil {
			return guestio.SCIONDatagram{}, err
		}
		if n < 0 || n > len(buffer) {
			return guestio.SCIONDatagram{}, fmt.Errorf("invalid SCION receive length")
		}
		match, err := scionPeer(ctx, env, from)
		if err != nil {
			continue
		}
		if err := env.Accountant.Account(ctx, app.TransferIn, match.Key, n); err != nil {
			return guestio.SCIONDatagram{}, err
		}
		env.scionReplyPeer = from.String()
		return guestio.SCIONDatagram{Data: buffer[:min(n, limit)], Sender: from.String(), ReceivedAtMS: time.Now().UnixMilli(), Size: n, Truncated: n > limit}, nil
	}
}
