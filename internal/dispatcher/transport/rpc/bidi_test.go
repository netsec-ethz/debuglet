// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
)

// An executor that establishes the yamux session but never serves gRPC over it
// must not park the dispatcher's session goroutine forever.
//
// This is the shape of a fleet-wide outage: every executor connected, the
// dispatcher logged "Yamux session established" and then nothing at all,
// because the reverse Hello never returned. The executors stayed connected and
// heartbeating into a registry they were not in, and could not detect it or
// recover. registerExecutor has to give up so the caller closes the session and
// the executor reconnects.
func TestRegisterExecutorGivesUpWhenPeerNeverServes(t *testing.T) {
	prev := registerTimeout
	registerTimeout = 200 * time.Millisecond
	t.Cleanup(func() { registerTimeout = prev })

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })

	// The peer keeps its side of the session alive — it answers yamux frames,
	// so the transport looks healthy — but never serves a gRPC server on it.
	peer, err := yamux.Client(clientConn, nil)
	if err != nil {
		t.Fatalf("yamux client: %v", err)
	}
	t.Cleanup(func() { peer.Close() })

	session, err := yamux.Server(serverConn, nil)
	if err != nil {
		t.Fatalf("yamux server: %v", err)
	}

	b := &BidiServer{logger: zap.NewNop(), clients: make(map[string]ExecutorConn)}
	gconn, err := b.createExecutorClient(session)
	if err != nil {
		t.Fatalf("createExecutorClient: %v", err)
	}
	t.Cleanup(func() { gconn.Close() })

	done := make(chan error, 1)
	go func() {
		_, err := b.registerExecutor(context.Background(), gconn, session)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected registration to fail against a peer that never serves, got nil")
		}
	case <-time.After(10 * registerTimeout):
		t.Fatal("registerExecutor never returned: the Hello handshake is unbounded")
	}
}
