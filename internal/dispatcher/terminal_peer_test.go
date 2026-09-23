package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/testpeer"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"go.uber.org/zap"

	_ "modernc.org/sqlite"
)

// terminalPeerAdapter is the test-only DispatcherState handed to the
// replacement Bidi. It forwards everything to the real Dispatcher except
// OnExecutorConnected, which delegates real registration and reports its
// stage result. Capacity is acknowledged over the bound direct channel. The
// fixture observes transport-marked availability only after the callback returns.
type terminalPeerAdapter struct {
	rpc.DispatcherState
	d     *Dispatcher
	ready chan terminalPeerRegistration
	once  sync.Once
}

type terminalPeerRegistration struct {
	owner *rpc.SessionOwner
	err   error
}

func (a *terminalPeerAdapter) OnExecutorConnected(ctx context.Context, owner *rpc.SessionOwner, h *pb.HelloResponse, sourceIP string) error {
	err := a.d.OnExecutorConnected(ctx, owner, h, sourceIP)
	// Transport marks Registered only after this callback returns. Report the
	// stage to the fixture; never wait for Registered here.
	a.once.Do(func() { a.ready <- terminalPeerRegistration{owner: owner, err: err} })
	return err
}

// startTerminalPeer replaces d's empty Bidi with one serving yamux on a
// loopback listener, connects the scripted executor peer over yamux and gRPC,
// and returns once Hello, real registration and a positive-capacity
// acknowledgement have completed. On failure it cancels and joins everything
// it started. The returned stop is idempotent, bounded by its cleanup
// context, and joins the complete Dispatcher before declaring teardown done.
// Constructors also register idempotent Dispatcher.Close for setup failures.
func startTerminalPeer(ctx context.Context, d *Dispatcher, capacity resource.Bitrate,
	peer pb.ExecutorServiceServer) (stop func(context.Context) error, err error) {
	if capacity <= 0 {
		return nil, errors.New("terminal peer: capacity must be positive")
	}
	if peer == nil {
		return nil, errors.New("terminal peer: nil executor service")
	}
	registrationCtx, cancelRegistration := context.WithTimeout(ctx, 10*time.Second)
	defer cancelRegistration()
	d.Bidi.Close()
	adapter := &terminalPeerAdapter{DispatcherState: d, d: d, ready: make(chan terminalPeerRegistration, 1)}
	replacement, err := rpc.NewBidiServer(zap.NewNop(), adapter, d.ControlIncarnation(), d.ControlLeaseDuration())
	if err != nil {
		return nil, err
	}
	d.Bidi = replacement
	transport, err := testpeer.Start(ctx, d.Bidi, peer)
	if err != nil {
		d.Close()
		return nil, err
	}
	var once sync.Once
	joined := make(chan struct{})
	teardown := func(cleanup context.Context) error {
		once.Do(func() {
			go func() {
				defer close(joined)
				// The actual handler join remains owned after any caller timeout.
				_ = transport.Stop(context.Background())
				d.Close()
			}()
		})
		select {
		case <-joined:
			return nil
		case <-cleanup.Done():
			return cleanup.Err()
		}
	}
	fail := func(cause error) (func(context.Context) error, error) {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := teardown(cleanup); err != nil {
			return teardown, errors.Join(cause, err)
		}
		return nil, cause
	}
	if err := transport.Client.WaitReadyContext(registrationCtx); err != nil {
		if registrationCtx.Err() != nil {
			err = registrationCtx.Err()
		}
		return fail(fmt.Errorf("terminal peer: registration: %w", err))
	}
	var registered terminalPeerRegistration
	select {
	case registered = <-adapter.ready:
	case <-registrationCtx.Done():
		return fail(registrationCtx.Err())
	}
	if registered.err != nil {
		return fail(registered.err)
	}
	if registered.owner == nil || !registered.owner.Available() {
		return fail(errors.New("terminal peer: registration has no available owner"))
	}
	binding, ok := transport.Client.Binding()
	if !ok || binding != registered.owner.Binding() {
		return fail(errors.New("terminal peer: negotiated identity mismatch"))
	}
	client, err := transport.Client.ClientFor(binding)
	if err != nil {
		return fail(err)
	}
	if _, err := client.Resources(registrationCtx, &pb.ResourcesRequest{ExecutorId: registered.owner.ExecutorID(), BandwidthCapacity: int64(capacity)}); err != nil {
		return fail(err)
	}
	if _, ok := d.GetExecutor(registered.owner.ExecutorID()); !ok {
		return fail(errors.New("terminal peer: registered executor is not discoverable"))
	}
	if _, ok := d.Bidi.GetClientFor(registered.owner); !ok {
		return fail(errors.New("terminal peer: exact reverse client is unavailable"))
	}

	return teardown, nil
}

// terminalLifecyclePeer is the minimal scripted executor used to check the
// shared transport, registration and teardown on their own.
type terminalLifecyclePeer struct {
	pb.UnimplementedExecutorServiceServer
	id     string
	aborts chan *pb.AbortRequest
}

func (p *terminalLifecyclePeer) Hello(context.Context, *pb.HelloRequest) (*pb.HelloResponse, error) {
	return &pb.HelloResponse{ExecutorId: p.id, Version: "peer", Currency: "TEST", PricePerBwS: 1}, nil
}

func (p *terminalLifecyclePeer) Abort(_ context.Context, req *pb.AbortRequest) (*pb.AbortResponse, error) {
	p.aborts <- req
	return &pb.AbortResponse{}, nil
}

// newTerminalPeerDispatcher uses SQLite because registration creates earnings.
func newTerminalPeerDispatcher(t *testing.T) *Dispatcher {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "peer.sqlite"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	testutil.ApplyMigrations(t, db, "database/migrations")
	logger := zap.NewNop()
	ph := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)
	d, err := New(logger, db, "peer-test", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

// TestTerminalPeerLifecycle proves the scripted-peer boundary alone: Hello,
// real registration with positive capacity, a dispatcher-initiated RPC over
// the yamux session, idempotent bounded teardown, and rejection of a peer
// that cannot register.
func TestTerminalPeerLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	d := newTerminalPeerDispatcher(t)
	peer := &terminalLifecyclePeer{id: "peer-exec", aborts: make(chan *pb.AbortRequest, 1)}
	stop, err := startTerminalPeer(ctx, d, resource.Megabit, peer)
	if err != nil {
		t.Fatalf("startTerminalPeer: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelCleanup()
		if err := stop(cleanupCtx); err != nil {
			t.Errorf("cleanup terminal peer: %v", err)
		}
	})

	exec, ok := d.GetExecutor("peer-exec")
	if !ok {
		t.Fatal("executor not registered after startTerminalPeer returned")
	}
	if exec.capacity != resource.Megabit || exec.Currency != "TEST" || exec.PricePerBwS != 1 {
		t.Fatalf("registration incomplete: capacity=%s currency=%q price=%d", exec.capacity, exec.Currency, exec.PricePerBwS)
	}
	d.mu.RLock()
	owner := d.executors["peer-exec"].owner
	d.mu.RUnlock()
	client, ok := d.Bidi.GetClientFor(owner)
	if !ok {
		t.Fatal("no gRPC client for the registered peer")
	}
	rpcCtx, cancelRPC := context.WithTimeout(ctx, 5*time.Second)
	defer cancelRPC()
	if _, err := client.Abort(rpcCtx, &pb.AbortRequest{DebugletId: "00000000-0000-4000-8000-000000000001", Reason: "lifecycle"}); err != nil {
		t.Fatalf("Abort over the peer session: %v", err)
	}
	select {
	case req := <-peer.aborts:
		if req.GetReason() != "lifecycle" {
			t.Fatalf("peer received %+v", req)
		}
	case <-ctx.Done():
		t.Fatal("peer did not receive the Abort")
	}

	stopCtx, cancelStop := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStop()
	if err := stop(stopCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if err := stop(stopCtx); err != nil {
		t.Fatalf("second stop: %v", err)
	}
	if _, ok := d.GetExecutor("peer-exec"); ok {
		t.Fatal("executor still registered after teardown")
	}
	if _, ok := d.Bidi.GetClientFor(owner); ok {
		t.Fatal("client still present after teardown")
	}

	// A peer whose Hello carries no executor id cannot register; the
	// constructor must fail and leave nothing running.
	bad := &terminalLifecyclePeer{id: "", aborts: make(chan *pb.AbortRequest, 1)}
	// The fixture is built before the deadline is armed. Opening the database
	// and applying its migrations is not part of the startup being measured,
	// and on a busy machine it alone can outlast the whole budget below.
	badDispatcher := newTerminalPeerDispatcher(t)
	badCtx, cancelBad := context.WithTimeout(ctx, 5*time.Second)
	defer cancelBad()
	badStop, badErr := startTerminalPeer(badCtx, badDispatcher, resource.Megabit, bad)
	if badStop != nil {
		t.Cleanup(func() {
			cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelCleanup()
			if err := badStop(cleanupCtx); err != nil {
				t.Errorf("cleanup unexpectedly registered empty-id peer: %v", err)
			}
		})
	}
	if badErr == nil {
		t.Fatal("startTerminalPeer accepted a peer with an empty executor id")
	}
	// Transport now rejects this Hello before invoking Connected. Observing
	// peer Serve termination must resolve startup without waiting for its deadline.
	if badCtx.Err() != nil || errors.Is(badErr, context.DeadlineExceeded) {
		t.Fatalf("empty-id peer rejection waited for the registration deadline: %v", badErr)
	}
	if _, err := startTerminalPeer(ctx, newTerminalPeerDispatcher(t), 0, peer); err == nil {
		t.Fatal("startTerminalPeer accepted zero capacity")
	}
}

// terminalDrainingPeer models a callback finishing database work after its RPC
// is canceled. The test controls when that final work may finish.
type terminalDrainingPeer struct {
	terminalLifecyclePeer
	entered, release, finished chan struct{}
}

func (p *terminalDrainingPeer) Abort(ctx context.Context, _ *pb.AbortRequest) (*pb.AbortResponse, error) {
	close(p.entered)
	<-ctx.Done()
	<-p.release
	close(p.finished)
	return nil, ctx.Err()
}

func TestTerminalPeerStopWaitsForHandlers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := newTerminalPeerDispatcher(t)
	peer := &terminalDrainingPeer{
		terminalLifecyclePeer: terminalLifecyclePeer{id: "draining-peer"},
		entered:               make(chan struct{}),
		release:               make(chan struct{}), finished: make(chan struct{}),
	}
	stop, err := startTerminalPeer(ctx, d, resource.Megabit, peer)
	if err != nil {
		t.Fatalf("startTerminalPeer: %v", err)
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(peer.release) }) }
	var calls sync.WaitGroup
	t.Cleanup(func() {
		release()
		cancel()
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelCleanup()
		if err := stop(cleanupCtx); err != nil {
			t.Errorf("cleanup terminal peer: %v", err)
		}
		joined := make(chan struct{})
		go func() { calls.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-cleanupCtx.Done():
			t.Error("fixture calls did not finish during cleanup")
		}
		// Drain the held callback even when this test exposes an early-return
		// bug in stop itself (the RPC client may finish before its handler).
		select {
		case <-peer.entered:
			select {
			case <-peer.finished:
			case <-cleanupCtx.Done():
				t.Error("RPC handler did not finish during cleanup")
			}
		default:
		}
	})
	d.mu.RLock()
	owner := d.executors["draining-peer"].owner
	d.mu.RUnlock()
	client, ok := d.Bidi.GetClientFor(owner)
	if !ok {
		t.Fatal("registered peer has no client")
	}
	calls.Add(1)
	go func() {
		defer calls.Done()
		_, _ = client.Abort(ctx, &pb.AbortRequest{DebugletId: "00000000-0000-4000-8000-000000000002"})
	}()
	select {
	case <-peer.entered:
	case <-ctx.Done():
		t.Fatal("RPC handler did not start")
	}
	// A handler still doing cleanup must prevent successful teardown. The
	// deadline bounds this negative assertion and tests that a fresh cleanup
	// context can subsequently join the same shutdown after work is released.
	stopCtx, cancelStop := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancelStop()
	if err := stop(stopCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stop with blocked handler = %v; want deadline exceeded", err)
	}
	release()
	if err := stop(ctx); err != nil {
		t.Fatalf("join teardown after releasing handler: %v", err)
	}
	select {
	case <-peer.finished:
	default:
		t.Fatal("successful stop did not join the handler")
	}
}
