// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

// TCPListenerEndpoint returns only an installed listener's advertised endpoint.
// It becomes unavailable as soon as terminal resource closure begins.
func (e *WasmEnv) TCPListenerEndpoint() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.TcpServer == nil {
		return ""
	}
	return e.TcpServerAddr
}
