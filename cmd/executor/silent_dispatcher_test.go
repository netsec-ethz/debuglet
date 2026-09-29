// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
)

// transportSession is the part of a session that the supervisor sees, taken
// directly from a real control client: loss and its cause are the client's own,
// as they are for executor sessions, and readiness is its negotiation.
type transportSession struct{ client *rpc.BidiClient }

func (s transportSession) Run(ctx context.Context) error { return s.client.ConnectAndServe(ctx) }
func (s transportSession) Stop(cause error)              { s.client.Stop(cause) }
func (s transportSession) Wait(context.Context) error    { s.client.Close(); return nil }
func (s transportSession) WaitResourcesReady(ctx context.Context) error {
	return s.client.WaitReadyContext(ctx)
}
func (s transportSession) Lost() <-chan struct{} { return s.client.Lost() }
func (s transportSession) Cause() error          { return s.client.Cause() }

// TestExecutorReconnectsAfterSilentDispatcher: a dispatcher that accepts the
// yamux session and answers pings but never sends Hello must not leave the
// executor connected without a registration. The session ends at the
// pre-offer deadline and the supervisor dials a new one.
func TestExecutorReconnectsAfterSilentDispatcher(t *testing.T) {
	listen := func() net.Listener {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return lis
	}
	direct, reverse := listen(), listen()
	var directConns atomic.Int32
	accepted := make(chan time.Time, 4)
	var sessions []*yamux.Session
	var mu sync.Mutex
	var peers sync.WaitGroup
	peers.Add(2)
	go func() {
		defer peers.Done()
		for {
			conn, err := direct.Accept()
			if err != nil {
				return
			}
			directConns.Add(1)
			conn.Close()
		}
	}()
	go func() {
		defer peers.Done()
		cfg := yamux.DefaultConfig()
		cfg.LogOutput = io.Discard
		for {
			conn, err := reverse.Accept()
			if err != nil {
				return
			}
			accepted <- time.Now()
			session, err := yamux.Server(conn, cfg)
			if err != nil {
				conn.Close()
				continue
			}
			mu.Lock()
			sessions = append(sessions, session)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		direct.Close()
		reverse.Close()
		peers.Wait()
		mu.Lock()
		defer mu.Unlock()
		for _, session := range sessions {
			session.Close()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var dials []time.Time
	redialed := make(chan struct{})
	go func() {
		defer close(redialed)
		for len(dials) < 2 {
			select {
			case at := <-accepted:
				dials = append(dials, at)
			case <-ctx.Done():
				return
			}
		}
		cancel() // Stop at the new session; its own deadline is not needed.
	}()
	core, logs := observer.New(zap.InfoLevel)
	created, waits := 0, 0
	err := serveNode(ctx, "", "silent-test", nodeServices{
		newSession: func() (executorSession, error) {
			created++
			client, err := rpc.NewBidiClient(rpc.BidiOptions{Address: direct.Addr().String(), YamuxAddress: reverse.Addr().String(), Logger: zap.NewNop()}, nil)
			if err != nil {
				return nil, err
			}
			return transportSession{client}, nil
		},
		wait:      func(context.Context, time.Duration) error { waits++; return nil },
		closeNode: func() error { return nil }, closeStorage: func() error { return nil },
		logger: zap.New(core),
	})
	cancel()
	<-redialed
	if err != nil || created != 2 || waits != 1 || len(dials) != 2 {
		t.Fatalf("result=%v sessions=%d waits=%d dials=%d", err, created, waits, len(dials))
	}
	// The gap is the 5 s pre-offer deadline, the first session's teardown, the
	// supervisor's wait (zero here) and the redial. The upper second covers the
	// teardown and goroutine scheduling under -race.
	gap := dials[1].Sub(dials[0])
	t.Logf("first dial -> reconnect dial: %v", gap)
	if gap < 4500*time.Millisecond || gap > 6*time.Second {
		t.Fatalf("reconnect %v after the first dial, want the 5s pre-offer deadline", gap)
	}
	entries := logs.FilterMessage("Control session lost; reconnecting").All()
	if len(entries) != 1 {
		t.Fatalf("reconnect lines: %d of %d entries", len(entries), logs.Len())
	}
	cause, _ := entries[0].ContextMap()["error"].(string)
	t.Logf("logged %q error=%q", entries[0].Message, cause)
	if !strings.Contains(cause, controlsession.TransportUnavailable.String()) || !strings.Contains(cause, context.DeadlineExceeded.Error()) {
		t.Fatalf("reconnect cause: %q", cause)
	}
	if n := directConns.Load(); n != 0 {
		t.Fatalf("executor used the direct channel %d times without an offer", n)
	}
}
