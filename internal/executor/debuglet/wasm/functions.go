// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"reflect"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Function describes one fixed guest import. The supervisor and the local
// runtime use the same table and implementation; only memory access differs.
type Function struct {
	Module, Name    string
	Params, Results []api.ValueType
	invoke          func(context.Context, Memory, []uint64)
}

func (f Function) Call(ctx context.Context, mem Memory, stack []uint64) {
	if len(stack) < max(len(f.Params), len(f.Results)) {
		panic("invalid host argument count")
	}
	f.invoke(ctx, mem, stack)
}

// Register installs the fixed imports. A nil proxy calls the local host;
// otherwise the worker calls its parent through the supplied bounded bridge.
func Register(builder wazero.HostModuleBuilder, module string, functions []Function, proxy func(context.Context, api.Module, int, []uint64)) wazero.HostModuleBuilder {
	for id, f := range functions {
		if f.Module != module {
			continue
		}
		builder = builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			if proxy != nil {
				proxy(ctx, m, id, stack)
			} else {
				f.Call(ctx, m.Memory(), stack)
			}
		}), f.Params, f.Results).Export(f.Name)
	}
	return builder
}

// function adapts only the scalar signatures in this file, once at creation.
// The guest cannot supply Go types, function names, or a different table.
func function(module, name string, fn any) Function {
	v := reflect.ValueOf(fn)
	t := v.Type()
	memory := t.NumIn() > 1 && t.In(1) == reflect.TypeFor[Memory]()
	first := 1
	if memory {
		first++
	}
	valueType := func(t reflect.Type) api.ValueType {
		switch t.Kind() {
		case reflect.Int32, reflect.Uint32:
			return api.ValueTypeI32
		case reflect.Int64, reflect.Uint64:
			return api.ValueTypeI64
		default:
			panic("unsupported fixed host signature")
		}
	}
	f := Function{Module: module, Name: name}
	for i := first; i < t.NumIn(); i++ {
		f.Params = append(f.Params, valueType(t.In(i)))
	}
	for i := 0; i < t.NumOut(); i++ {
		f.Results = append(f.Results, valueType(t.Out(i)))
	}
	f.invoke = func(ctx context.Context, mem Memory, stack []uint64) {
		args := make([]reflect.Value, t.NumIn())
		args[0] = reflect.ValueOf(ctx)
		if memory {
			args[1] = reflect.ValueOf(mem)
		}
		for i := first; i < t.NumIn(); i++ {
			args[i] = reflect.ValueOf(stack[i-first]).Convert(t.In(i))
		}
		values := v.Call(args)
		for i, r := range values {
			stack[i] = r.Convert(reflect.TypeFor[uint64]()).Uint()
		}
	}
	return f
}

func Functions(env *WasmEnv) []Function {
	return []Function{
		function("env", "connect_tls", hostConnect(env, socket.SocketTypeTLS)),
		function("env", "connect_tcp", hostConnect(env, socket.SocketTypeTCP)),
		function("env", "receive_tcp_data", hostReceiveData(env)),
		function("env", "send_tcp_data", hostSendData(env)),
		function("env", "close_tcp", HostClose(env)),
		function("env", "accept_tcp", HostAcceptTCP(env)),
		function("env", "get_tcp_addr", hostGetTCPAddr(env)),
		function("env", "connect_udp", hostConnect(env, socket.SocketTypeUDP)),
		function("env", "receive_udp_data", hostReceiveData(env)),
		function("env", "send_udp_data", hostSendData(env)),
		function("env", "receive_udp_from", hostReceiveUDPFrom(env)),
		function("env", "get_udp_addr", hostGetUDPAddr(env)),
		function("env", "connect_icmp4", hostConnect(env, socket.SocketTypeICMP4)),
		function("env", "receive_icmp4_data", hostReceiveData(env)),
		function("env", "send_icmp4_data", hostSendData(env)),
		function("env", "close_icmp4", HostClose(env)),
		function("env", "drain_connection", HostDrain(env)),
		function("env", "get_remote_addr", hostGetRemoteAddr(env)),
		function("env", "send_scion_udp_packet", hostSendSCIONUDPPacket(env)),
		function("env", "receive_scion_server_udp_packet", hostReceiveSCIONServerUDPPacket(env)),
		function("env", "answer_scion_udp_packet", hostAnswerSCIONUDPPacket(env, nil)),
		function("env", "scion_available_paths", hostSCIONAvailablePaths(env)),
		function("env", "scion_path_length", hostSCIONPathLength(env)),
		function("env", "scion_get_interface_details", hostSCIONGetInterfaceDetails(env)),
		function("env", "scion_select_path", hostSCIONSelectPath(env)),
		function(guestio.Module, "dial", hostIODial(env)),
		function(guestio.Module, "read", hostIORead(env)),
		function(guestio.Module, "write", hostIOWrite(env)),
		function(guestio.Module, "close", HostIOClose(env)),
		function(guestio.Module, "deadline", HostIODeadline(env)),
		function(ExperimentModule, "ready", hostExperimentReady(env)),
	}
}
