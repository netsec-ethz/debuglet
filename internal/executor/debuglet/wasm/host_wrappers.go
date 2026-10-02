// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/tetratelabs/wazero/api"
)

func HostIODial(env *WasmEnv) func(context.Context, api.Module, uint32, uint32, uint32, int64) uint64 {
	fn := hostIODial(env)
	return func(ctx context.Context, mod api.Module, transport, ptr, length uint32, timeout int64) uint64 {
		return fn(ctx, mod.Memory(), transport, ptr, length, timeout)
	}
}
func HostIORead(env *WasmEnv) func(context.Context, api.Module, int32, uint32, uint32) uint64 {
	fn := hostIORead(env)
	return func(ctx context.Context, mod api.Module, handle int32, ptr, length uint32) uint64 {
		return fn(ctx, mod.Memory(), handle, ptr, length)
	}
}
func HostIOWrite(env *WasmEnv) func(context.Context, api.Module, int32, uint32, uint32) uint64 {
	fn := hostIOWrite(env)
	return func(ctx context.Context, mod api.Module, handle int32, ptr, length uint32) uint64 {
		return fn(ctx, mod.Memory(), handle, ptr, length)
	}
}
func HostConnect(env *WasmEnv, socketType socket.SocketType) func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
	fn := hostConnect(env, socketType)
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
		return fn(ctx, mod.Memory(), addrp, addrLen)
	}
}
func HostReceiveData(env *WasmEnv) func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) int32 {
	fn := hostReceiveData(env)
	return func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) int32 {
		return fn(ctx, mod.Memory(), sockID, bufp, bufLen)
	}
}
func HostSendData(env *WasmEnv) func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) {
	fn := hostSendData(env)
	return func(ctx context.Context, mod api.Module, sockID int32, bufp, bufLen uint32) {
		fn(ctx, mod.Memory(), sockID, bufp, bufLen)
	}
}
func HostGetRemoteAddr(env *WasmEnv) func(ctx context.Context, mod api.Module, sockID int32, bufPtr, bufLen uint32) int32 {
	fn := hostGetRemoteAddr(env)
	return func(ctx context.Context, mod api.Module, sockID int32, bufPtr, bufLen uint32) int32 {
		return fn(ctx, mod.Memory(), sockID, bufPtr, bufLen)
	}
}
func HostGetTCPAddr(env *WasmEnv) func(ctx context.Context, mod api.Module, bufPtr, bufLen uint32) int32 {
	fn := hostGetTCPAddr(env)
	return func(ctx context.Context, mod api.Module, bufPtr, bufLen uint32) int32 {
		return fn(ctx, mod.Memory(), bufPtr, bufLen)
	}
}
func HostGetUDPAddr(env *WasmEnv) func(ctx context.Context, mod api.Module, bufPtr, bufLen uint32) int32 {
	fn := hostGetUDPAddr(env)
	return func(ctx context.Context, mod api.Module, bufPtr, bufLen uint32) int32 {
		return fn(ctx, mod.Memory(), bufPtr, bufLen)
	}
}
func HostReceiveUDPFrom(env *WasmEnv) func(ctx context.Context, mod api.Module, recvp, recvLen, senderp, senderLen, addrLenp uint32) int32 {
	fn := hostReceiveUDPFrom(env)
	return func(ctx context.Context, mod api.Module, recvp, recvLen, senderp, senderLen, addrLenp uint32) int32 {
		return fn(ctx, mod.Memory(), recvp, recvLen, senderp, senderLen, addrLenp)
	}
}
func HostSendSCIONUDPPacket(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
	fn := hostSendSCIONUDPPacket(env)
	return func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
		return fn(ctx, mod.Memory(), addrp, addrLen, sendp, sendLen)
	}
}
func HostReceiveSCIONServerUDPPacket(env *WasmEnv) func(ctx context.Context, mod api.Module, recvp, recvLen uint32, timeout int32) (int32, int64) {
	fn := hostReceiveSCIONServerUDPPacket(env)
	return func(ctx context.Context, mod api.Module, recvp, recvLen uint32, timeout int32) (int32, int64) {
		return fn(ctx, mod.Memory(), recvp, recvLen, timeout)
	}
}
func HostAnswerSCIONUDPPacket(env *WasmEnv, addresses []string) func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
	fn := hostAnswerSCIONUDPPacket(env, addresses)
	return func(ctx context.Context, mod api.Module, addrp, addrLen, sendp, sendLen uint32) int64 {
		return fn(ctx, mod.Memory(), addrp, addrLen, sendp, sendLen)
	}
}
func HostSCIONAvailablePaths(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
	fn := hostSCIONAvailablePaths(env)
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32) int32 {
		return fn(ctx, mod.Memory(), addrp, addrLen)
	}
}
func HostSCIONPathLength(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) int32 {
	fn := hostSCIONPathLength(env)
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) int32 {
		return fn(ctx, mod.Memory(), addrp, addrLen, pathIdx)
	}
}
func HostSCIONGetInterfaceDetails(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32, ifIdx int32) (int64, int64) {
	fn := hostSCIONGetInterfaceDetails(env)
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32, ifIdx int32) (int64, int64) {
		return fn(ctx, mod.Memory(), addrp, addrLen, pathIdx, ifIdx)
	}
}
func HostSCIONSelectPath(env *WasmEnv) func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) {
	fn := hostSCIONSelectPath(env)
	return func(ctx context.Context, mod api.Module, addrp, addrLen uint32, pathIdx int32) {
		fn(ctx, mod.Memory(), addrp, addrLen, pathIdx)
	}
}
