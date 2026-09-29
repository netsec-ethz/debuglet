// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// silentDispatcher accepts the executor's yamux session and answers its pings,
// but never opens the reverse stream, so no Hello offer ever arrives. Its direct
// channel records every call that reaches it.
type silentDispatcher struct {
	direct, reverse net.Listener
	mu              sync.Mutex
	calls           []string
	accepted        chan time.Time
	sessions        chan *yamux.Session
}

func newSilentDispatcher(t *testing.T) *silentDispatcher {
	t.Helper()
	listen := func() net.Listener {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return lis
	}
	d := &silentDispatcher{direct: listen(), reverse: listen(), accepted: make(chan time.Time, 1), sessions: make(chan *yamux.Session, 1)}
	record := func(method string) {
		d.mu.Lock()
		d.calls = append(d.calls, method)
		d.mu.Unlock()
	}
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			record(info.FullMethod)
			return handler(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			record(info.FullMethod)
			return handler(srv, ss)
		}),
	)
	pb.RegisterDispatcherServiceServer(srv, pb.UnimplementedDispatcherServiceServer{})
	directDone, reverseDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(directDone); _ = srv.Serve(d.direct) }()
	go func() {
		defer close(reverseDone)
		conn, err := d.reverse.Accept()
		if err != nil {
			return
		}
		d.accepted <- time.Now()
		cfg := yamux.DefaultConfig()
		cfg.LogOutput = io.Discard
		session, err := yamux.Server(conn, cfg)
		if err != nil {
			conn.Close()
			return
		}
		d.sessions <- session
	}()
	t.Cleanup(func() {
		srv.Stop()
		d.reverse.Close()
		awaitNegotiation(t, directDone)
		awaitNegotiation(t, reverseDone)
		select {
		case session := <-d.sessions:
			session.Close()
		default:
		}
	})
	return d
}

func (d *silentDispatcher) recorded() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

// TestBidiSilentDispatcherEndsBeforeOffer runs the real client against a
// dispatcher whose yamux session is up and answers pings but which never sends
// Hello. The client must end at its pre-offer deadline as a transport loss,
// report that cause to readiness waiters, send nothing on the direct channel,
// close the session and join.
func TestBidiSilentDispatcherEndsBeforeOffer(t *testing.T) {
	d := newSilentDispatcher(t)
	b, err := NewBidiClient(BidiOptions{Address: d.direct.Addr().String(), YamuxAddress: d.reverse.Addr().String(), Logger: zap.NewNop()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	var serveErr error
	var ended time.Time
	go func() { defer close(served); serveErr = b.ConnectAndServe(ctx); ended = time.Now() }()
	readyErr := make(chan error, 1)
	go func() { readyErr <- b.WaitReadyContext(ctx) }()
	closed := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		go func() { defer close(closed); b.Close() }()
		awaitNegotiation(t, closed)
		awaitNegotiation(t, served)
	})

	var dialed time.Time
	select {
	case dialed = <-d.accepted:
	case <-time.After(negotiationTestWait):
		t.Fatal("client did not dial the yamux listener")
	}
	awaitNegotiation(t, b.serving) // The client's ping succeeded.
	var session *yamux.Session
	select {
	case session = <-d.sessions:
	case <-time.After(negotiationTestWait):
		t.Fatal("dispatcher session was not established")
	}
	// The startup deadline is set when ConnectAndServe is entered, before the
	// dial, and the watchdog checks it every 50 ms, so Lost fires 5.00-5.05 s
	// after entry and slightly under 5 s after the accepted dial. The second
	// over it covers goroutine scheduling under -race.
	select {
	case <-b.Lost():
	case <-time.After(preOfferTimeout + time.Second):
		t.Fatalf("client without an offer still connected %v after dial", time.Since(dialed))
	}
	lost := time.Since(dialed)
	awaitNegotiation(t, served)
	t.Logf("dial -> client lost: %v; dial -> ConnectAndServe returned: %v", lost, ended.Sub(dialed))
	if lost < preOfferTimeout-500*time.Millisecond {
		t.Fatalf("client ended after %v, before the %v pre-offer deadline", lost, preOfferTimeout)
	}

	var end *controlsession.EndError
	if !errors.As(b.Cause(), &end) || end.Kind != controlsession.TransportUnavailable || !errors.Is(end, context.DeadlineExceeded) {
		t.Fatalf("pre-offer end cause=%v", b.Cause())
	}
	if serveErr != b.Cause() {
		t.Fatalf("ConnectAndServe=%v, cause=%v", serveErr, b.Cause())
	}
	select {
	case err := <-readyErr:
		if err != b.Cause() {
			t.Fatalf("WaitReadyContext=%v, cause=%v", err, b.Cause())
		}
	case <-time.After(negotiationTestWait):
		t.Fatal("readiness waiter was not released by the transport loss")
	}
	select {
	case <-session.CloseChan():
	case <-time.After(negotiationTestWait):
		t.Fatal("client left the yamux session open after ending")
	}
	if calls := d.recorded(); len(calls) != 0 {
		t.Fatalf("client reached the dispatcher before any offer: %v", calls)
	}
	t.Logf("end cause: %v", b.Cause())
}
