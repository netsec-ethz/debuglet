package api

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/testpeer"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
	// tesla, when set, is the TESLA schedule the peer announces.
	tesla           *pb.HelloResponse
	legacyBandwidth bool

	mu         sync.Mutex
	uploads    []*pb.UploadRequest
	aborts     []*pb.AbortRequest
	bandwidths []*pb.BandwidthRequest
	onUpload   func(ctx context.Context, req *pb.UploadRequest) error
	onAbort    func(ctx context.Context, req *pb.AbortRequest) error
	onInspect  func(context.Context, *pb.InspectRetainedRunRequest) (*pb.InspectRetainedRunResponse, error)
}

func (p *cpPeer) Hello(context.Context, *pb.HelloRequest) (*pb.HelloResponse, error) {
	hello := &pb.HelloResponse{
		ExecutorId:       p.id,
		Version:          "client-peer",
		BandwidthVersion: 2,
		Currency:         p.currency,
		PricePerBwS:      p.price,
	}
	if p.legacyBandwidth {
		hello.BandwidthVersion = 0
	}
	if p.tesla != nil {
		hello.TeslaAnchorKey, hello.TeslaAnchorTimestampNs = p.tesla.TeslaAnchorKey, p.tesla.TeslaAnchorTimestampNs
		hello.TeslaDelaySec, hello.TeslaDisclosureDelayEpochs = p.tesla.TeslaDelaySec, p.tesla.TeslaDisclosureDelayEpochs
		hello.TeslaChainLength = p.tesla.TeslaChainLength
		hello.Capabilities = p.tesla.Capabilities
	}
	return hello, nil
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
			// A hook that answers with a status keeps its code; any other
			// error is a refusal.
			if _, ok := status.FromError(err); ok {
				return nil, err
			}
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
	}
	return &pb.AbortResponse{}, nil
}

func (p *cpPeer) InspectRetainedRun(ctx context.Context, req *pb.InspectRetainedRunRequest) (*pb.InspectRetainedRunResponse, error) {
	p.mu.Lock()
	hook := p.onInspect
	p.mu.Unlock()
	if hook == nil {
		return nil, status.Error(codes.Unimplemented, "fixture does not inspect retained work")
	}
	return hook(ctx, req)
}

func (p *cpPeer) Bandwidth(_ context.Context, req *pb.BandwidthRequest) (*pb.BandwidthResponse, error) {
	p.mu.Lock()
	p.bandwidths = append(p.bandwidths, req)
	p.mu.Unlock()
	return &pb.BandwidthResponse{Revision: req.GetRevision()}, nil
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

// startClientPeer retains the direct client for scripted callbacks after
// real registration and a positive-capacity acknowledgement have completed.
func startClientPeer(ctx context.Context, d *dispatcher.Dispatcher, capacity bitrate.Bitrate,
	peer pb.ExecutorServiceServer) (func(context.Context) error, error) {
	p, err := testpeer.StartRegistered(ctx, d, &d.Bidi, capacity, peer, cpRegistrationBound)
	if p == nil {
		return nil, err
	}
	if err == nil {
		if _, ok := d.GetExecutor(p.Owner.ExecutorID()); !ok {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err = errors.Join(errors.New("client peer: registered executor is not discoverable"), p.Stop(cleanup))
		} else if scripted, ok := peer.(*cpPeer); ok {
			scripted.direct, scripted.owner = p.Client, p.Owner
		}
	}
	return p.Stop, err
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
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "peer.sqlite"), sqlitedb.Create())
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close sqlite: %v", err)
		}
	})
	if _, err := sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	logger := zap.NewNop()
	ph, _ := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)

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
