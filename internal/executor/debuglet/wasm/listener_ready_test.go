// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"net"
	"testing"
)

func TestTCPReadinessFollowsListenerLifetime(t *testing.T) {
	env := &WasmEnv{}
	if env.TCPListenerEndpoint() != "" {
		t.Fatal("uninstalled listener ready")
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().String()
	if err := env.InstallTCP(listener, 0, address, nil); err != nil {
		t.Fatal(err)
	}
	if env.TCPListenerEndpoint() != address {
		t.Fatal("installed endpoint missing")
	}
	if err := env.Close(); err != nil {
		t.Fatal(err)
	}
	if env.TCPListenerEndpoint() != "" {
		t.Fatal("closed listener remains ready")
	}
}
