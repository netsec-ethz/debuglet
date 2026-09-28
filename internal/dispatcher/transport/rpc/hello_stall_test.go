// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/netsec-ethz/debuglet/protocol"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
)

// helloDeadline is the bound registerExecutor puts on the reverse Hello.
const helloDeadline = 5 * time.Second

// stalledHelloServer is a yamux listener whose only observer is the failed
// registration line, delivered by a log hook rather than by polling.
type stalledHelloServer struct {
	b       *BidiServer
	state   *lifecycleState
	addr    string
	logs    *observer.ObservedLogs
	failed  chan time.Time
	served  chan struct{}
	serving error
}

func newStalledHelloServer(t *testing.T) *stalledHelloServer {
	t.Helper()
	core, logs := observer.New(zap.DebugLevel)
	failed := make(chan time.Time, 8)
	core = zapcore.RegisterHooks(core, func(entry zapcore.Entry) error {
		if entry.Message == "failed to register executor" {
			failed <- entry.Time
		}
		return nil
	})
	state := newLifecycleState()
	s := &stalledHelloServer{
		b:      newTestBidiServer(t, zap.New(core), state, "00000000-0000-4000-8000-000000000001"),
		state:  state,
		logs:   logs,
		failed: failed,
		served: make(chan struct{}),
	}
	lis := mustListenLocal(t)
	s.addr = lis.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { defer close(s.served); s.serving = s.b.ServeYamux(ctx, lis) }()
	t.Cleanup(func() {
		cancel()
		s.b.Close()
		awaitSessionSignal(t, s.served)
		if s.serving != nil {
			t.Errorf("ServeYamux: %v", s.serving)
		}
	})
	return s
}

// dialStalledPeer opens a real yamux client session to the server and returns
// once a ping has completed, which is the moment the session is established.
func dialStalledPeer(t *testing.T, addr string) (*yamux.Session, time.Time) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	session, err := yamux.Client(conn, cfg)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	if _, err := session.Ping(); err != nil {
		t.Fatalf("yamux ping: %v", err)
	}
	return session, time.Now()
}

// blockedHello answers every reverse Hello by waiting for the caller to give up.
type blockedHello struct {
	pb.UnimplementedExecutorServiceServer
	once    sync.Once
	entered chan struct{}
	ended   chan error
}

func (h *blockedHello) Hello(ctx context.Context, _ *pb.HelloRequest) (*pb.HelloResponse, error) {
	h.once.Do(func() { close(h.entered) })
	<-ctx.Done()
	h.ended <- ctx.Err()
	return nil, ctx.Err()
}

func serveBlockedHello(t *testing.T, session *yamux.Session) *blockedHello {
	t.Helper()
	h := &blockedHello{entered: make(chan struct{}), ended: make(chan error, 1)}
	srv := grpc.NewServer()
	pb.RegisterExecutorServiceServer(srv, h)
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(session) }()
	t.Cleanup(func() { srv.Stop(); awaitSessionSignal(t, done) })
	return h
}

func awaitRegistrationFailure(t *testing.T, s *stalledHelloServer, bound time.Duration) time.Time {
	t.Helper()
	select {
	case at := <-s.failed:
		return at
	case <-time.After(bound):
		t.Fatalf("registration did not end within %v; log: %v", bound, s.logs.All())
	}
	return time.Time{}
}

func awaitPeerClosed(t *testing.T, session *yamux.Session) time.Time {
	t.Helper()
	select {
	case <-session.CloseChan():
		return time.Now()
	case <-time.After(2 * time.Second):
		t.Fatal("dispatcher did not close the yamux session of a failed registration")
	}
	return time.Time{}
}

func assertNoRegistration(t *testing.T, s *stalledHelloServer) {
	t.Helper()
	s.b.mu.RLock()
	clients, offers, lanes := len(s.b.clients), len(s.b.offers), len(s.b.lanes)
	s.b.mu.RUnlock()
	if clients != 0 || offers != 0 || lanes != 0 || s.state.connectedCount() != 0 {
		t.Fatalf("failed Hello left clients/offers/lanes/connected=%d/%d/%d/%d", clients, offers, lanes, s.state.connectedCount())
	}
	select {
	case <-s.served:
		t.Fatal("a failed registration stopped the yamux listener")
	default:
	}
}

// TestBidiSilentReverseHelloEndsRegistration runs the real yamux listener and
// the real reverse gRPC client against peers whose yamux session is up and
// answers pings while the reverse Hello never completes. Each registration must
// end at the Hello deadline, log the failure, publish nothing, close the
// session and leave no handler behind, while the listener keeps serving.
func TestBidiSilentReverseHelloEndsRegistration(t *testing.T) {
	cases := []struct {
		name string
		peer func(t *testing.T, session *yamux.Session)
	}{
		{"stream never accepted", func(*testing.T, *yamux.Session) {}},
		{"stream accepted and never read", func(t *testing.T, session *yamux.Session) {
			accepted := make(chan struct{})
			go func() {
				stream, err := session.AcceptStream()
				if err == nil {
					t.Cleanup(func() { stream.Close() })
				}
				close(accepted)
			}()
			awaitSessionSignal(t, accepted)
		}},
		{"Hello never answered", func(t *testing.T, session *yamux.Session) {
			h := serveBlockedHello(t, session)
			awaitSessionSignal(t, h.entered)
			select {
			case err := <-h.ended:
				// The propagated deadline or the caller's cancellation at its
				// deadline, whichever reaches the peer first.
				if err != context.DeadlineExceeded && err != context.Canceled {
					t.Errorf("peer Hello ended by %v", err)
				}
			case <-time.After(helloDeadline + time.Second):
				t.Error("peer Hello context did not end")
			}
		}},
	}
	servers := make([]*stalledHelloServer, len(cases))
	for i := range cases {
		servers[i] = newStalledHelloServer(t)
	}
	t.Run("peers", func(t *testing.T) {
		for i, tc := range cases {
			s := servers[i]
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				session, established := dialStalledPeer(t, s.addr)
				tc.peer(t, session)
				failed := awaitRegistrationFailure(t, s, helloDeadline+time.Second)
				closed := awaitPeerClosed(t, session)
				elapsed := failed.Sub(established)
				t.Logf("session established -> failed to register executor: %v; -> session closed by dispatcher: %v", elapsed, closed.Sub(established))
				// The deadline starts when the session is accepted, just before
				// the peer's ping returns, so it ends slightly under the bound.
				// The second over it, here and in the wait above, covers only the
				// log emission, the session teardown and goroutine scheduling
				// under -race with packages tested in parallel.
				if elapsed < helloDeadline-500*time.Millisecond || elapsed > helloDeadline+time.Second {
					t.Fatalf("registration ended after %v, want the %v Hello deadline", elapsed, helloDeadline)
				}
				assertNoRegistration(t, s)
			})
		}
	})
	for _, s := range servers {
		for _, entry := range s.logs.FilterMessage("failed to register executor").All() {
			t.Logf("logged %s %q error=%v", entry.Level, entry.Message, entry.ContextMap()["error"])
		}
		assertNoRegistration(t, s)
	}
	awaitNoSessionHandlers(t)
}

// TestBidiPeerClosedDuringHelloEndsRegistration covers the variant where the
// peer's session goes away while the reverse Hello is pending: the
// registration must fail at once, not at the deadline.
func TestBidiPeerClosedDuringHelloEndsRegistration(t *testing.T) {
	cases := []struct {
		name  string
		close func(t *testing.T, session *yamux.Session)
	}{
		{"closed after ping", func(*testing.T, *yamux.Session) {}},
		{"closed inside Hello", func(t *testing.T, session *yamux.Session) {
			awaitSessionSignal(t, serveBlockedHello(t, session).entered)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStalledHelloServer(t)
			session, _ := dialStalledPeer(t, s.addr)
			tc.close(t, session)
			closed := time.Now()
			session.Close()
			failed := awaitRegistrationFailure(t, s, time.Second)
			t.Logf("peer closed session -> failed to register executor: %v", failed.Sub(closed))
			assertNoRegistration(t, s)
		})
	}
	awaitNoSessionHandlers(t)
}

// awaitNoSessionHandlers checks, while the listeners still serve, that no
// session handler, reverse gRPC client transport or yamux session of a failed
// registration is left running.
func awaitNoSessionHandlers(t *testing.T) {
	t.Helper()
	leaked := []string{
		").handleSession",
		").registerExecutor",
		"grpc/internal/transport.(*http2Client)",
		"hashicorp/yamux.(*Session)",
	}
	buf := make([]byte, 1<<20)
	var found string
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		stacks := string(buf[:runtime.Stack(buf, true)])
		found = ""
		for _, frame := range leaked {
			if strings.Contains(stacks, frame) {
				found = frame
				break
			}
		}
		if found == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine %s still running after failed registrations:\n%s", found, stacks)
		}
	}
}
