package dispatcher

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/testpeer"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"go.uber.org/zap"

	_ "modernc.org/sqlite"
)

// startTerminalPeer waits for real registration and acknowledged capacity.
func startTerminalPeer(ctx context.Context, d *Dispatcher, capacity bitrate.Bitrate,
	peer pb.ExecutorServiceServer) (func(context.Context) error, error) {
	p, err := testpeer.StartRegistered(ctx, d, &d.Bidi, capacity, peer, 10*time.Second)
	if p == nil {
		return nil, err
	}
	if err == nil {
		if _, ok := d.GetExecutor(p.Owner.ExecutorID()); !ok {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err = errors.Join(errors.New("terminal peer: registered executor is not discoverable"), p.Stop(cleanup))
		}
	}
	return p.Stop, err
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
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "peer.sqlite"), sqlitedb.Create())
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := sqlitedb.Migrate(t.Context(), db, dispatcherdb.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	logger := zap.NewNop()
	ph, _ := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)
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
	stop, err := startTerminalPeer(ctx, d, bitrate.Megabit, peer)
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
	if exec.capacity != bitrate.Megabit || exec.Currency != "TEST" || exec.PricePerBwS != 1 {
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
	badStop, badErr := startTerminalPeer(badCtx, badDispatcher, bitrate.Megabit, bad)
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
	stop, err := startTerminalPeer(ctx, d, bitrate.Megabit, peer)
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
