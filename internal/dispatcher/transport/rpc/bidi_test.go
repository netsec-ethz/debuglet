package rpc

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestBidiCancellation(t *testing.T) {
	t.Run("owned grpc listener", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer lis.Close()
		b := newTestBidiServer(t, zap.NewNop(), nil, "00000000-0000-4000-8000-000000000001")
		done := make(chan error, 1)
		joined := make(chan struct{})
		t.Cleanup(func() { cancel(); b.Close(); awaitSessionSignal(t, joined) })
		go func() { defer close(joined); done <- b.ServeGRPCListener(ctx, lis) }()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("ServeGRPCListener did not join")
		}
		awaitSessionSignal(t, joined)
		lis.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
		if _, err := lis.Accept(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("listener remains open: %v", err)
		}
	})
	t.Run("yamux handshake ownership", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer lis.Close()
		b := newTestBidiServer(t, zap.NewNop(), nil, "00000000-0000-4000-8000-000000000001")
		accepted := make(chan struct{})
		tracked := &acceptedListener{Listener: lis, accepted: accepted}
		done := make(chan error, 1)
		joined := make(chan struct{})
		t.Cleanup(func() { cancel(); b.Close(); awaitSessionSignal(t, joined) })
		go func() { defer close(joined); done <- b.ServeYamux(ctx, tracked) }()
		conn, err := net.DialTimeout("tcp", lis.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		select {
		case <-accepted:
		case <-time.After(5 * time.Second):
			t.Fatal("connection not accepted")
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("yamux callback did not join")
		}
		awaitSessionSignal(t, joined)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.Copy(io.Discard, conn); err != nil {
			t.Fatalf("owned handshake connection still open: %v", err)
		}
	})
}

type acceptedListener struct {
	net.Listener
	accepted chan struct{}
}

func (l *acceptedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		close(l.accepted)
	}
	return conn, err
}

func newTestBidiServer(t *testing.T, logger *zap.Logger, state DispatcherState, incarnation string) *BidiServer {
	t.Helper()
	b, err := NewBidiServer(logger, state, incarnation, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestServingRequiresBothControlListeners proves that readiness is not
// satisfied by half a control channel: when the listener executors dial goes
// away, the transport says so even though the direct one still accepts.
func TestServingRequiresBothControlListeners(t *testing.T) {
	b := newTestBidiServer(t, zap.NewNop(), nil, "00000000-0000-4000-8000-000000000002")
	t.Cleanup(b.Close)
	if b.Serving() {
		t.Fatal("a transport that has started no listener reports itself serving")
	}
	direct, reverse := mustListenLocal(t), mustListenLocal(t)
	directCtx, stopDirect := context.WithCancel(context.Background())
	reverseCtx, stopReverse := context.WithCancel(context.Background())
	directDone, reverseDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(directDone); _ = b.ServeGRPCListener(directCtx, direct) }()
	go func() { defer close(reverseDone); _ = b.ServeYamux(reverseCtx, reverse) }()
	t.Cleanup(func() {
		stopDirect()
		stopReverse()
		awaitSessionSignal(t, directDone)
		awaitSessionSignal(t, reverseDone)
	})
	awaitServing(t, b, true)

	stopReverse()
	awaitSessionSignal(t, reverseDone)
	awaitServing(t, b, false)
}

func mustListenLocal(t *testing.T) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return lis
}

// awaitServing waits for the transport's own observation, which a serve
// goroutine publishes once it is accepting.
func awaitServing(t *testing.T, b *BidiServer, want bool) {
	t.Helper()
	for deadline := time.Now().Add(sessionTestWait); b.Serving() != want; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("Serving() = %v, want %v", !want, want)
		}
	}
}
