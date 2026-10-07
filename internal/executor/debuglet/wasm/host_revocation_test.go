// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
)

// A connection whose destination is denied after admission but before it is
// registered is closed instead of being handed to the guest.
func TestAttachSocketClosesAConnectionRevokedInFlight(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	run := netpolicy.Run{Addresses: []string{"127.0.0.1"}}
	env := policyEnv(t, localSpec(), run)
	revoked := netpolicy.NewRevocations()
	operator, err := netpolicy.Parse(localSpec())
	if err != nil {
		t.Fatal(err)
	}
	env.Net = netpolicy.New(operator.WithRevocations(revoked), run)
	ctx := context.Background()
	if _, err := env.Net.AdmitDestination(ctx, netpolicy.TCP, listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	revoked.Update([]string{"127.0.0.1"}, true) // no run registered yet: nothing to close
	reservation, err := env.Registry.Reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Release()
	handle, err := attachSocket(ctx, env, conn, "127.0.0.1", socket.SocketTypeTCP, reservation)
	if handle != -1 || !errors.Is(err, socket.ErrRevoked) {
		t.Fatalf("attachSocket = %d, %v; want the revoked connection refused", handle, err)
	}
	if _, err := env.Registry.Get(0); !errors.Is(err, socket.ErrRevoked) {
		t.Fatalf("registered entry: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := server.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("the revoked connection is still open: n=%d err=%v", n, err)
	}
}
