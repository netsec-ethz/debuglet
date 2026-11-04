// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build wasip1

package debuglet

import (
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/guestio"
)

//go:wasmimport debuglet_io_v1 scion_paths
func hostSCIONPaths(ptr, size, out, capacity uint32) uint64

//go:wasmimport debuglet_io_v1 scion_select_path
func hostSCIONSelectPath(ptr, size, out, capacity uint32) uint64

//go:wasmimport debuglet_io_v1 scion_exchange
func hostSCIONExchange(ptr, size, out, capacity uint32) uint64

//go:wasmimport debuglet_io_v1 scion_listener_address
func hostSCIONListenerAddress(ptr, size, out, capacity uint32) uint64

//go:wasmimport debuglet_io_v1 scion_receive
func hostSCIONReceive(ptr, size, out, capacity uint32) uint64

//go:wasmimport debuglet_io_v1 scion_reply
func hostSCIONReply(ptr, size, out, capacity uint32) uint64

func invokeSCIONPaths(data []byte) ([]byte, error) { return scionResponse(data, hostSCIONPaths) }
func invokeSCIONSelectPath(data []byte) ([]byte, error) {
	return scionResponse(data, hostSCIONSelectPath)
}
func invokeSCIONExchange(data []byte) ([]byte, error) { return scionResponse(data, hostSCIONExchange) }
func invokeSCIONListenerAddress(data []byte) ([]byte, error) {
	return scionResponse(data, hostSCIONListenerAddress)
}
func invokeSCIONReceive(data []byte) ([]byte, error) { return scionResponse(data, hostSCIONReceive) }
func invokeSCIONReply(data []byte) ([]byte, error)   { return scionResponse(data, hostSCIONReply) }

//go:wasmimport debuglet_io_v1 scion_quic_echo_start
func hostSCIONQUICEchoStart(ptr, size, out, capacity uint32) uint64

//go:wasmimport debuglet_io_v1 scion_quic_echo_stop
func hostSCIONQUICEchoStop(ptr, size, out, capacity uint32) uint64

//go:wasmimport debuglet_io_v1 scion_quic_exchange
func hostSCIONQUICExchange(ptr, size, out, capacity uint32) uint64
func invokeSCIONQUICEchoStart(data []byte) ([]byte, error) {
	return scionResponse(data, hostSCIONQUICEchoStart)
}
func invokeSCIONQUICEchoStop(data []byte) ([]byte, error) {
	return scionResponse(data, hostSCIONQUICEchoStop)
}
func invokeSCIONQUICExchange(data []byte) ([]byte, error) {
	return scionResponse(data, hostSCIONQUICExchange)
}

func scionResponse(data []byte, invoke func(uint32, uint32, uint32, uint32) uint64) ([]byte, error) {
	out := make([]byte, guestio.SCIONBufferSize)
	count, err := ioOutcome(invoke(bytePtr(data), uint32(len(data)), bytePtr(out), uint32(len(out))))
	if count == 0 && err != nil {
		return nil, err
	}
	if count < 1 || count > len(out) {
		return nil, fmt.Errorf("debuglet: invalid SCION result length")
	}
	return out[:count], err
}
