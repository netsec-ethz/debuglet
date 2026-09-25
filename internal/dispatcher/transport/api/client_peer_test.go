package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/testpeer"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The dispatcher package's private test helper cannot be imported here, so
// these API fixtures construct the scripted executor from exported components.
// They introduce no production hook.

// cpAdapter is the test-only DispatcherState handed to the replacement Bidi.
// It forwards everything to the real Dispatcher except OnExecutorConnected,
// which delegates real registration and reports the stage result. Capacity
// is acknowledged over the bound direct channel. The outer fixture waits for transport-marked availability.
type cpAdapter struct {
	rpc.DispatcherState
	d     *dispatcher.Dispatcher
	ready chan cpRegistration
	once  sync.Once
}

type cpRegistration struct {
	owner *rpc.SessionOwner
	err   error
}

func (a *cpAdapter) OnExecutorConnected(ctx context.Context, owner *rpc.SessionOwner, h *pb.HelloResponse, sourceIP string) error {
	err := a.d.OnExecutorConnected(ctx, owner, h, sourceIP)
	// Transport marks Registered only after this callback returns. Report the
	// stage to the fixture; never wait for Registered here.
	a.once.Do(func() { a.ready <- cpRegistration{owner: owner, err: err} })
	return err
}

// cpPeer is the scripted ExecutorService. Upload records every payload and
// runs the current upload hook before replying, so a case can drive the real
// state and exit callbacks while the dispatcher still waits for the upload
// acknowledgement. Abort runs the abort hook; a returned error becomes an
// explicit RPC failure. Bandwidth records the received limits.
type cpPeer struct {
	pb.UnimplementedExecutorServiceServer
	direct   pb.DispatcherServiceClient
	owner    *rpc.SessionOwner
	id       string
	price    int64
	currency string

	mu         sync.Mutex
	uploads    []*pb.UploadRequest
	aborts     []*pb.AbortRequest
	bandwidths []*pb.BandwidthRequest
	onUpload   func(ctx context.Context, req *pb.UploadRequest) error
	onAbort    func(ctx context.Context, req *pb.AbortRequest) error
}

func (p *cpPeer) Hello(context.Context, *pb.HelloRequest) (*pb.HelloResponse, error) {
	return &pb.HelloResponse{
		ExecutorId:  p.id,
		Version:     "client-peer",
		Currency:    p.currency,
		PricePerBwS: p.price,
	}, nil
}

func (p *cpPeer) Upload(ctx context.Context, req *pb.UploadRequest) (*pb.UploadResponse, error) {
	p.mu.Lock()
	p.uploads = append(p.uploads, req)
	hook := p.onUpload
	p.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, req); err != nil {
			return nil, status.Error(codes.Aborted, err.Error())
		}
	}
	return &pb.UploadResponse{}, nil
}

func (p *cpPeer) Abort(ctx context.Context, req *pb.AbortRequest) (*pb.AbortResponse, error) {
	p.mu.Lock()
	p.aborts = append(p.aborts, req)
	hook := p.onAbort
	p.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, req); err != nil {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
	}
	return &pb.AbortResponse{}, nil
}

func (p *cpPeer) Bandwidth(_ context.Context, req *pb.BandwidthRequest) (*pb.BandwidthResponse, error) {
	p.mu.Lock()
	p.bandwidths = append(p.bandwidths, req)
	p.mu.Unlock()
	return &pb.BandwidthResponse{}, nil
}

func (p *cpPeer) setUploadHook(hook func(ctx context.Context, req *pb.UploadRequest) error) {
	p.mu.Lock()
	p.onUpload = hook
	p.mu.Unlock()
}

func (p *cpPeer) setAbortHook(hook func(ctx context.Context, req *pb.AbortRequest) error) {
	p.mu.Lock()
	p.onAbort = hook
	p.mu.Unlock()
}

func (p *cpPeer) uploadCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.uploads)
}

func (p *cpPeer) lastUpload() *pb.UploadRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.uploads) == 0 {
		return nil
	}
	return p.uploads[len(p.uploads)-1]
}

func (p *cpPeer) abortCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.aborts)
}

// cpRegistrationBound bounds the dial, Hello, registration and capacity
// acknowledgement of startClientPeer. It is separate from the caller's
// context, which remains the lifetime of a successfully started peer.
var cpRegistrationBound = 10 * time.Second

// startClientPeer replaces d's constructor Bidi with one serving yamux on a
// loopback listener, connects peer over yamux and gRPC, and returns once
// Hello, real registration and a positive-capacity acknowledgement have
// completed within cpRegistrationBound. On failure, including that deadline,
// it cancels and joins everything it started through the same teardown path.
// The returned stop is idempotent and bounded by its cleanup context; it
// cancels, closes the listener and session, stops the peer gRPC server
// waiting for active handlers, joins both serve goroutines and closes the
// complete Dispatcher before reporting completion. Constructors also register
// idempotent Dispatcher.Close immediately to cover setup failures.
func startClientPeer(ctx context.Context, d *dispatcher.Dispatcher, capacity resource.Bitrate,
	peer pb.ExecutorServiceServer) (stop func(context.Context) error, err error) {
	if capacity <= 0 {
		return nil, errors.New("client peer: capacity must be positive")
	}
	if peer == nil {
		return nil, errors.New("client peer: nil executor service")
	}
	registrationCtx, cancelRegistration := context.WithTimeout(ctx, cpRegistrationBound)
	defer cancelRegistration()
	d.Bidi.Close()
	adapter := &cpAdapter{DispatcherState: d, d: d, ready: make(chan cpRegistration, 1)}
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
		return fail(fmt.Errorf("client peer: registration: %w", err))
	}
	var registered cpRegistration
	select {
	case registered = <-adapter.ready:
	case <-registrationCtx.Done():
		return fail(registrationCtx.Err())
	}
	if registered.err != nil {
		return fail(registered.err)
	}
	if registered.owner == nil || !registered.owner.Available() {
		return fail(errors.New("client peer: registration has no available owner"))
	}
	binding, ok := transport.Client.Binding()
	if !ok || binding != registered.owner.Binding() {
		return fail(errors.New("client peer: negotiated identity mismatch"))
	}
	client, err := transport.Client.ClientFor(binding)
	if err != nil {
		return fail(err)
	}
	if _, err := client.Resources(registrationCtx, &pb.ResourcesRequest{ExecutorId: registered.owner.ExecutorID(), BandwidthCapacity: int64(capacity)}); err != nil {
		return fail(err)
	}
	if _, ok := d.GetExecutor(registered.owner.ExecutorID()); !ok {
		return fail(errors.New("client peer: registered executor is not discoverable"))
	}
	if _, ok := d.Bidi.GetClientFor(registered.owner); !ok {
		return fail(errors.New("client peer: exact reverse client is unavailable"))
	}
	if p, ok := peer.(*cpPeer); ok {
		p.direct = client
		p.owner = registered.owner
	}
	return teardown, nil
}

// cpBlockingHelloPeer never answers Hello, so registration cannot complete.
type cpBlockingHelloPeer struct {
	pb.UnimplementedExecutorServiceServer
	entered chan struct{}
}

func (p *cpBlockingHelloPeer) Hello(ctx context.Context, _ *pb.HelloRequest) (*pb.HelloResponse, error) {
	select {
	case <-p.entered:
	default:
		close(p.entered)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestClientPeerRegistrationDeadline proves that a peer which never completes
// registration fails startClientPeer within the registration bound while the
// caller's context is still live, that the failure ran the teardown path, and
// that the bound does not shorten a successfully started peer's lifetime.
func TestClientPeerRegistrationDeadline(t *testing.T) {
	// The short bound applies to the unresponsive peer only. One second is
	// long enough for the loopback dial and Hello to be entered under load and
	// short enough to keep that case quick. Every stage that expects a real
	// registration to complete keeps the package bound instead: a loaded host
	// can need far more than a second to dial, say Hello, register and
	// acknowledge capacity, and a registration that is merely slow is not the
	// failure those stages are looking for.
	const blockedBound = time.Second
	previous := cpRegistrationBound
	cpRegistrationBound = blockedBound
	restored := false
	restore := func() {
		if !restored {
			restored = true
			cpRegistrationBound = previous
		}
	}
	t.Cleanup(restore)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "peer.sqlite"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close sqlite: %v", err)
		}
	})
	db.SetMaxOpenConns(1)
	testutil.ApplyMigrations(t, db, ccMigrationsDir)
	logger := zap.NewNop()
	ph := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)

	blocked := &cpBlockingHelloPeer{entered: make(chan struct{})}
	d, err := dispatcher.New(logger, db, "peer-deadline", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	start := time.Now()
	stop, err := startClientPeer(ctx, d, ccCapacity, blocked)
	if err == nil {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), ccCleanupBound)
		cleanupErr := stop(cleanupCtx)
		cancelCleanup()
		if cleanupErr != nil {
			t.Errorf("stop unexpectedly registered peer: %v", cleanupErr)
		}
		t.Fatal("startClientPeer succeeded although Hello never answered")
	}
	if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		t.Fatalf("startClientPeer error %v (caller ctx %v); want the registration deadline with a live caller context", err, ctx.Err())
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("registration failure took %s", elapsed)
	}
	select {
	case <-blocked.entered:
	default:
		t.Fatal("Hello was never reached, so the deadline did not bound registration")
	}
	if len(d.ListExecutors()) != 0 {
		t.Fatalf("executors registered after failed startup: %+v", d.ListExecutors())
	}

	// An invalid Hello is rejected before Connected, so no adapter stage can
	// arrive: startup ends with the transport's own rejection rather than by
	// running out of time. The generous bound is restored first so that a
	// slow rejection is still reported as the rejection it is.
	restore()
	invalid, err := dispatcher.New(logger, db, "peer-invalid-id", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(invalid.Close)
	invalidStop, invalidErr := startClientPeer(ctx, invalid, ccCapacity, &cpPeer{id: ""})
	if invalidStop != nil {
		t.Cleanup(func() {
			cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), ccCleanupBound)
			defer cancelCleanup()
			if err := invalidStop(cleanupCtx); err != nil {
				t.Errorf("stop unexpectedly registered empty-id peer: %v", err)
			}
		})
	}
	if invalidErr == nil || errors.Is(invalidErr, context.DeadlineExceeded) || ctx.Err() != nil {
		t.Fatalf("empty-id peer = %v (caller context %v); want transport rejection before the registration deadline", invalidErr, ctx.Err())
	}

	// A peer that registers normally outlives the deadline that ended the
	// unresponsive one. startClientPeer cancels its registration context
	// before returning, so the bound that admitted this peer is already gone
	// by then; what remains to be shown is that neither bound became its
	// lifetime, which is the caller's context. Its own registration waits for
	// readiness under the package bound rather than the short deadline.
	good := &cpPeer{id: "deadline-peer", price: 1, currency: "TEST"}
	d2, err := dispatcher.New(logger, db, "peer-deadline", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d2.Close)
	stop, err = startClientPeer(ctx, d2, ccCapacity, good)
	if err != nil {
		t.Fatalf("startClientPeer with a responsive peer: %v", err)
	}
	// Register before any assertion can fail. LIFO cleanup joins the peer's
	// callbacks before the database cleanup registered above runs.
	t.Cleanup(func() {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), ccCleanupBound)
		defer cancelCleanup()
		if err := stop(cleanupCtx); err != nil {
			t.Errorf("stop responsive peer during cleanup: %v", err)
		}
	})
	// Wait past the deadline that ended the unresponsive peer, then use this
	// one. Waiting past the generous bound it was admitted under would only
	// make the test slower: that context is cancelled either way.
	waitPast := time.NewTimer(2 * blockedBound)
	defer waitPast.Stop()
	select {
	case <-waitPast.C:
	case <-ctx.Done():
		t.Fatal("test context ended")
	}
	client, ok := d2.Bidi.GetClientFor(good.owner)
	if !ok {
		t.Fatal("peer client missing after the registration bound elapsed")
	}
	rpcCtx, cancelRPC := context.WithTimeout(ctx, 5*time.Second)
	defer cancelRPC()
	if _, err := client.Bandwidth(rpcCtx, &pb.BandwidthRequest{}); err != nil {
		t.Fatalf("Bandwidth after the registration bound: %v", err)
	}
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), ccCleanupBound)
	defer cancelCleanup()
	if err := stop(cleanupCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}
}
