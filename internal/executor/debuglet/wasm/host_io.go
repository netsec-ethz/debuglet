// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// RegisterIO adds recoverable sockets without changing the legacy env module.
func RegisterIO(builder wazero.HostModuleBuilder, env *WasmEnv) wazero.HostModuleBuilder {
	return builder.NewFunctionBuilder().WithFunc(HostIODial(env)).Export("dial").
		NewFunctionBuilder().WithFunc(HostIORead(env)).Export("read").
		NewFunctionBuilder().WithFunc(HostIOWrite(env)).Export("write").
		NewFunctionBuilder().WithFunc(HostIOClose(env)).Export("close").
		NewFunctionBuilder().WithFunc(HostIODeadline(env)).Export("deadline")
}

func ioResult(n int, err error) uint64 {
	status := guestio.OK
	var timeout net.Error
	switch {
	case err == nil:
	case errors.Is(err, io.EOF):
		status = guestio.EOF
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &timeout) && timeout.Timeout():
		status = guestio.Timeout
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		status = guestio.Reset
	case errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrClosedPipe):
		status = guestio.Closed
	case errors.Is(err, syscall.ECONNREFUSED):
		status = guestio.Refused
	case errors.Is(err, socket.ErrQuota), errors.Is(err, netpolicy.ErrDenied), errors.Is(err, netpolicy.ErrNotInPolicy), errors.Is(err, netpolicy.ErrTransportUnavailable), errors.Is(err, netpolicy.ErrUntagged):
		status = guestio.Denied
	case errors.Is(err, io.ErrNoProgress):
		status = guestio.NoProgress
	case errors.Is(err, io.ErrShortWrite):
		status = guestio.ShortWrite
	case errors.Is(err, context.Canceled):
		status = guestio.Canceled
	default:
		status = guestio.Failure
	}
	return uint64(status)<<32 | uint64(uint32(n))
}

func ioSocket(env *WasmEnv, handle int32) (socket.Socket, error) {
	sock, err := env.Registry.Get(handle)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		panic(err)
	}
	return sock, err
}

func HostIODial(env *WasmEnv) func(context.Context, api.Module, uint32, uint32, uint32, int64) uint64 {
	return func(ctx context.Context, mod api.Module, transport, ptr, length uint32, timeout int64) uint64 {
		addr, err := ExtractStr(mod, ptr, length)
		if err != nil {
			panic(err)
		}
		dialCtx := ctx
		if timeout != 0 {
			var cancel context.CancelFunc
			dialCtx, cancel = context.WithTimeout(ctx, time.Duration(timeout))
			defer cancel()
		}
		handle, err := connectSocket(ctx, dialCtx, env, socket.SocketType(transport), addr)
		return ioResult(int(handle), err)
	}
}

func HostIORead(env *WasmEnv) func(context.Context, api.Module, int32, uint32, uint32) uint64 {
	return func(_ context.Context, mod api.Module, handle int32, ptr, length uint32) uint64 {
		buf, err := ExtractMem[byte](mod, ptr, length)
		if err != nil {
			panic(err)
		}
		sock, err := ioSocket(env, handle)
		if err != nil {
			return ioResult(0, err)
		}
		n, err := sock.Read(buf)
		if n < 0 || n > len(buf) {
			panic(fmt.Errorf("read returned invalid byte count %d", n))
		}
		if !isStreamSocket(sock.Type()) && errors.Is(err, io.EOF) {
			err = errors.New("unexpected datagram EOF")
		}
		if isStreamSocket(sock.Type()) && n == 0 && err == nil && len(buf) != 0 {
			err = io.ErrNoProgress
		}
		return ioResult(n, err)
	}
}

func HostIOWrite(env *WasmEnv) func(context.Context, api.Module, int32, uint32, uint32) uint64 {
	return func(_ context.Context, mod api.Module, handle int32, ptr, length uint32) uint64 {
		buf, err := ExtractMem[byte](mod, ptr, length)
		if err != nil {
			panic(err)
		}
		sock, err := ioSocket(env, handle)
		if err != nil {
			return ioResult(0, err)
		}
		if !isStreamSocket(sock.Type()) && length > MAX_SLICE_LENGTH {
			panic("datagram exceeds host transfer bound")
		}
		n, err := sock.Write(buf)
		if n < 0 || n > len(buf) {
			panic(fmt.Errorf("write returned invalid byte count %d", n))
		}
		if n < len(buf) && err == nil {
			err = io.ErrShortWrite
		}
		return ioResult(n, err)
	}
}

func HostIOClose(env *WasmEnv) func(context.Context, int32) uint64 {
	return func(_ context.Context, handle int32) uint64 {
		if _, err := ioSocket(env, handle); err != nil {
			return ioResult(0, err)
		}
		return ioResult(0, env.Registry.Close(handle))
	}
}

func HostIODeadline(env *WasmEnv) func(context.Context, int32, uint32, int64) uint64 {
	return func(_ context.Context, handle int32, write uint32, unixNano int64) uint64 {
		if write > 1 {
			panic("invalid deadline mode")
		}
		sock, err := ioSocket(env, handle)
		if err != nil {
			return ioResult(0, err)
		}
		deadlines, ok := sock.(interface {
			SetReadDeadline(time.Time) error
			SetWriteDeadline(time.Time) error
		})
		if !ok {
			return uint64(guestio.Unsupported) << 32
		}
		var deadline time.Time
		if unixNano != 0 {
			deadline = time.Unix(0, unixNano)
		}
		switch write {
		case 0:
			err = deadlines.SetReadDeadline(deadline)
		case 1:
			err = deadlines.SetWriteDeadline(deadline)
		}
		return ioResult(0, err)
	}
}
