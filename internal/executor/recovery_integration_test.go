package executor

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"
	drpc "github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/sqlite"
	erpc "github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// This adapter scripts application replies while retaining the real v3 direct
// and reverse transports, binding credentials, lease admission and handler joins.
// It is not evidence of dispatcher bookkeeping or durable outcome delivery.
type recoveryPeer struct {
	*operationPeer
	connected chan *drpc.SessionOwner
}

func (p *recoveryPeer) OnExecutorConnected(_ context.Context, owner *drpc.SessionOwner, _ *pb.HelloResponse, _ string) error {
	p.connected <- owner
	return nil
}
func (*recoveryPeer) OnExecutorDisconnected(*drpc.SessionOwner) {}
func (*recoveryPeer) OnHeartbeat(context.Context, *drpc.Mutation, *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	return &pb.HeartbeatResponse{}, nil
}
func (*recoveryPeer) OnResources(context.Context, *drpc.Mutation, *pb.ResourcesRequest) (*pb.ResourcesResponse, error) {
	return &pb.ResourcesResponse{}, nil
}
func (p *recoveryPeer) OnDebugletAllocate(ctx context.Context, _ *drpc.Mutation, req *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error) {
	return p.DebugletAllocate(ctx, req)
}
func (p *recoveryPeer) OnDebugletState(ctx context.Context, _ *drpc.Mutation, req *pb.DebugletStateRequest) (*pb.DebugletStateResponse, error) {
	return p.DebugletState(ctx, req)
}
func (p *recoveryPeer) OnDebugletExit(ctx context.Context, _ *drpc.Mutation, req *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
	return p.DebugletExit(ctx, req)
}
func (p *recoveryPeer) OnDebugletStream(_ *drpc.SessionOwner, stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
	return p.DebugletStream(stream)
}

type recoveryHarness struct {
	t        *testing.T
	db       *sql.DB
	node     *Node
	server   *drpc.BidiServer
	peer     *recoveryPeer
	ctx      context.Context
	cancel   context.CancelFunc
	clock    atomic.Int64
	serves   sync.WaitGroup
	sessions []*Session
	runs     []<-chan error
}

func newRecoveryHarness(t *testing.T, peer *operationPeer) *recoveryHarness {
	t.Helper()
	// Register directory disposal before the harness join, so a failed
	// assertion cannot unlink SQLite while an owned finalizer is still running.
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	f := &recoveryHarness{t: t, ctx: ctx, cancel: cancel, peer: &recoveryPeer{operationPeer: peer, connected: make(chan *drpc.SessionOwner, 8)}}
	f.clock.Store(time.Now().UnixNano())
	// Even assertion failures retain joins before closing the database/node.
	t.Cleanup(f.close)
	var err error
	f.db, err = sql.Open("sqlite", filepath.Join(dir, "recovery.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	f.db.SetMaxOpenConns(1)
	testutil.ApplyMigrations(t, f.db, "database/migrations")
	f.server, err = drpc.NewBidiServer(zap.NewNop(), f.peer, uuid.NewString(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	listen := func(serve func(context.Context, net.Listener) error) string {
		t.Helper()
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		f.serves.Add(1)
		go func() {
			defer f.serves.Done()
			defer lis.Close()
			if err := serve(ctx, lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
				t.Errorf("recovery peer serving: %v", err)
			}
		}()
		return lis.Addr().String()
	}
	cfg := config.ExecutorConfig{
		Identity:   config.IdentityConfig{ExecutorID: uuid.NewString(), Version: "recovery-integration"},
		Dispatcher: config.DispatcherConfig{Addr: listen(f.server.ServeGRPCListener), YamuxAddr: listen(f.server.ServeYamux)},
		TLS:        config.TLSConfig{Disable: true},
		Resources:  config.ResourcesConfig{Capacity: 1000000000, MaxDebuglets: 8},
		Tesla:      config.TeslaConfig{Seed: "owned-recovery-fixture", Delay: 60, ChainLength: 64},
		Network:    config.NetworkConfig{PacketCounter: "fallback", DisableSCIONEnvironment: true},
		Pricing:    config.PricingConfig{Currency: "TEST", PricePerBwS: 1},
	}
	f.node, err = NewNode(&cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	f.node.newBidi = func(opts erpc.BidiOptions, state erpc.ExecutorState) (*erpc.BidiClient, error) {
		opts.LeaseNow = func() time.Time { return time.Unix(0, f.clock.Load()) }
		// Hold only the watchdog. No test cancels the session at expiry: the
		// actual admission/execution guard must notice its elapsed lease.
		opts.NewLeaseTicker = func(time.Duration) (<-chan time.Time, func()) { return make(chan time.Time), func() {} }
		return erpc.NewBidiClient(opts, state)
	}
	return f
}

func (f *recoveryHarness) start(configure func(*Executor)) (*Session, *drpc.SessionOwner, drpc.BoundExecutorClient) {
	f.t.Helper()
	s, err := NewSession(f.node, f.db)
	if err != nil {
		f.t.Fatal(err)
	}
	f.sessions = append(f.sessions, s)
	if configure != nil {
		configure(s.executor)
	}
	done := make(chan error, 1)
	f.runs = append(f.runs, done)
	go func() { done <- s.Run(f.ctx) }()
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	if err := s.WaitResourcesReady(ctx); err != nil {
		f.t.Fatalf("real session resource acknowledgement: %v", err)
	}
	var owner *drpc.SessionOwner
	select {
	case owner = <-f.peer.connected:
	case <-ctx.Done():
		f.t.Fatal("missing actual registered owner")
	}
	client, ok := f.server.GetClientFor(owner)
	if !ok {
		f.t.Fatal("registered reverse client unavailable")
	}
	return s, owner, client
}

func (f *recoveryHarness) close() {
	f.cancel()
	for _, s := range f.sessions {
		s.Stop(nil)
	}
	for _, s := range f.sessions {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := s.Wait(ctx)
		cancel()
		if err != nil {
			f.t.Errorf("owned recovery session cleanup: %v", err)
			// Retain ownership beyond a failed bounded observation.
			if err := s.Wait(context.Background()); err != nil {
				f.t.Errorf("eventual session cleanup: %v", err)
				return
			}
		}
	}
	for _, done := range f.runs {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			f.t.Error("Session.Run did not join after successful Wait")
			<-done
		}
	}
	if f.server != nil {
		f.server.Close()
	}
	f.serves.Wait()
	if f.node != nil {
		if err := f.node.Close(); err != nil {
			f.t.Error(err)
		}
	}
	if f.db != nil {
		if err := f.db.Close(); err != nil {
			f.t.Error(err)
		}
	}
}

func recoveryUpload(binding controlsession.Binding, id uuid.UUID, future bool) *pb.UploadRequest {
	req := &pb.UploadRequest{Id: id.String(), TransactionId: "local-recovery", Wasm: []byte("\x00asm\x01\x00\x00\x00"),
		ControlBinding: &pb.ControlBinding{DispatcherIncarnation: binding.Incarnation, SessionId: binding.SessionID},
		Policy:         &pb.DebugletPolicy{FloorBw: 64000, CeilBw: 1000000, TimeoutMs: 30000, Addresses: []string{"127.0.0.1"}}}
	if future {
		req.StartTime = timestamppb.New(time.Now().Add(time.Hour))
	}
	return req
}

// The positive control proves the scripted runtime can enter Run. The expiry
// cases hold actual RPC replies (or runtime compilation) with the watchdog
// deliberately idle. Neither parent cancellation nor a renew timeout can supply
// the missing guard: the deadline advances only after the held step is observed.
func TestRecoveryLeaseBlocksGuestEntryAfterDelayedStep(t *testing.T) {
	for _, step := range []string{"allocate", "compile", "started", "healthy_started"} {
		t.Run(step, func(t *testing.T) {
			peer := newOperationPeer()
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			wait := func(ctx context.Context) error {
				close(entered)
				select {
				case <-release:
					return ctx.Err()
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			if step == "allocate" {
				peer.allocate = func(ctx context.Context, _ *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error) {
					return &pb.DebugletAllocateResponse{}, wait(ctx)
				}
			} else if step != "compile" {
				peer.state = func(ctx context.Context, req *pb.DebugletStateRequest) (*pb.DebugletStateResponse, error) {
					if req.State == pb.RunState_RUN_STATE_STARTED {
						return &pb.DebugletStateResponse{}, wait(ctx)
					}
					return &pb.DebugletStateResponse{}, nil
				}
			}
			f := newRecoveryHarness(t, peer)
			t.Cleanup(unblock) // Release fixture holds before harness joining.
			runtime := &operationRuntime{}
			if step == "compile" {
				runtime.init = wait
			}
			var created atomic.Int32
			callbackDone := make(chan scheduler.Completion, 1)
			s, _, client := f.start(func(e *Executor) {
				e.newRuntime = func(spec scheduler.Spec) runtimeDebuglet {
					created.Add(1)
					runtime.close = func(context.Context) error { e.limiter.RemoveDebuglet(spec.DebugletID); return nil }
					return runtime
				}
				e.scheduler.RegisterOnStart(func(ctx context.Context, spec scheduler.Spec) scheduler.Completion {
					result := e.OnDebugletStart(ctx, spec)
					callbackDone <- result
					return result
				})
			})
			binding, ok := s.executor.Bidi.Binding()
			if !ok {
				t.Fatal("ready session lost binding")
			}
			ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
			defer cancel()
			id, sibling := uuid.New(), uuid.New()
			if _, err := client.Upload(ctx, recoveryUpload(binding, sibling, true)); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Upload(ctx, recoveryUpload(binding, id, false)); err != nil {
				t.Fatal(err)
			}
			if !operationAwait(t, entered, "held "+step) {
				return
			}
			if step != "healthy_started" {
				f.clock.Add(int64(time.Minute)) // Exact deadline; ACK arrival adds no authority.
			}
			select {
			case <-s.Lost():
				t.Fatal("session stopped before the held step returned; guard sensitivity is masked")
			default:
			}
			unblock()
			select {
			case result := <-callbackDone:
				if result.CleanupErr != nil {
					t.Fatal(result.CleanupErr)
				}
			case <-ctx.Done():
				t.Fatal("guest callback did not join within pre-renew bound")
			}
			if step == "healthy_started" {
				if created.Load() != 1 || runtime.starts.Load() != 1 || runtime.closes.Load() != 1 {
					t.Fatal("healthy control did not run and clean its runtime once")
				}
				if report := operationReport(t, peer, id); report.ExitCode != 0 {
					t.Fatal("healthy control did not report success")
				}
				s.Stop(nil)
			} else {
				if runtime.starts.Load() != 0 || (step == "allocate" && created.Load() != 0) {
					t.Fatalf("expired lease crossed runtime boundary: created=%d run=%d", created.Load(), runtime.starts.Load())
				}
				if step != "allocate" && (created.Load() != 1 || runtime.closes.Load() != 1) {
					t.Fatal("expired compilation/STARTED did not close its owned runtime exactly once")
				}
				var end *controlsession.EndError
				if !errors.As(s.Cause(), &end) || end.Kind != controlsession.LeaseExpired {
					t.Fatalf("execution guard did not select lease expiry: %v", s.Cause())
				}
				if peer.reportCalls.Load() != 0 {
					t.Fatal("expired binding sent a fresh terminal report")
				}
			}
			if err := s.Wait(ctx); err != nil {
				t.Fatalf("actual session join before harness cleanup: %v", err)
			}
			var rows int
			if err := f.db.QueryRowContext(ctx, "SELECT count(*) FROM debuglets WHERE uuid = ? AND started_at IS NULL", sibling).Scan(&rows); err != nil || rows != 1 {
				t.Fatalf("queued sibling was not preserved: rows=%d error=%v", rows, err)
			}
			if err := f.db.QueryRowContext(ctx, "SELECT count(*) FROM debuglets WHERE uuid = ?", id).Scan(&rows); err != nil || rows != 0 {
				t.Fatalf("joined active finalizer did not retire its row: rows=%d error=%v", rows, err)
			}
		})
	}
}

// A real control disconnect signals running work immediately. Reconnection is
// allowed only after that session's actual resource and SQL finalizers join.
// The same node keeps its TESLA/counter identity while the successor quarantines
// the old accepted queue instead of replaying it under its fresh binding.
func TestRecoveryReconnectWaitsForCleanupAndQuarantinesQueue(t *testing.T) {
	peer := newOperationPeer()
	f := newRecoveryHarness(t, peer)
	running, cancelled, closing := make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	runtime := &operationRuntime{run: func(ctx context.Context, _ chan<- []byte) error {
		close(running)
		<-ctx.Done()
		close(cancelled)
		return context.Cause(ctx)
	}}
	s1, owner1, client1 := f.start(func(e *Executor) {
		e.newRuntime = func(spec scheduler.Spec) runtimeDebuglet {
			runtime.close = func(context.Context) error {
				close(closing)
				<-release
				e.limiter.RemoveDebuglet(spec.DebugletID)
				return nil
			}
			return runtime
		}
	})
	ctx, cancel := context.WithTimeout(f.ctx, 8*time.Second)
	defer cancel()
	oldBinding, _ := s1.executor.Bidi.Binding()
	active, queued := uuid.New(), uuid.New()
	for _, req := range []*pb.UploadRequest{recoveryUpload(oldBinding, queued, true), recoveryUpload(oldBinding, active, false)} {
		if _, err := client1.Upload(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	if !operationAwait(t, running, "running guest before disconnect") {
		return
	}
	if !f.server.RemoveClient(owner1) {
		t.Fatal("failed to retire the actual current transport")
	}
	if !operationAwait(t, s1.Lost(), "immediate transport loss") || !operationAwait(t, cancelled, "guest cancellation from loss") || !operationAwait(t, closing, "held local resource cleanup") {
		return
	}
	short, end := context.WithTimeout(context.Background(), 25*time.Millisecond)
	err := s1.Wait(short)
	end()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("held resource cleanup incorrectly joined: %v", err)
	}
	if successor, err := NewSession(f.node, f.db); !errors.Is(err, ErrNodeBusy) {
		if successor != nil {
			f.sessions = append(f.sessions, successor)
		}
		t.Fatalf("unjoined session allowed successor: %v", err)
	}
	var rows int
	if err := f.db.QueryRowContext(ctx, "SELECT count(*) FROM debuglets WHERE uuid = ?", active).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("held active finalizer lost its canonical row: rows=%d error=%v", rows, err)
	}
	unblock()
	if err := s1.Wait(ctx); err != nil {
		t.Fatalf("released old session did not actually join: %v", err)
	}
	if runtime.starts.Load() != 1 || runtime.closes.Load() != 1 {
		t.Fatal("old runtime did not stop exactly once")
	}
	if peer.reportCalls.Load() != 0 {
		t.Fatal("old session sent a fresh report after loss")
	}
	var starts atomic.Int32
	s2, _, client2 := f.start(func(e *Executor) {
		e.newRuntime = func(spec scheduler.Spec) runtimeDebuglet {
			return &operationRuntime{
				run:   func(context.Context, chan<- []byte) error { starts.Add(1); return nil },
				close: func(context.Context) error { e.limiter.RemoveDebuglet(spec.DebugletID); return nil },
			}
		}
	})
	newBinding, ok := s2.executor.Bidi.Binding()
	if !ok || newBinding == oldBinding || newBinding.Incarnation != oldBinding.Incarnation {
		t.Fatal("same dispatcher reconnect did not negotiate a distinct session")
	}
	if s1.executor.Bidi == s2.executor.Bidi || s1.storage == s2.storage || s1.executor.limiter == s2.executor.limiter || s1.executor.portManager == s2.executor.portManager {
		t.Fatal("successor reused session-owned state")
	}
	if s1.executor.teslaSchedule != s2.executor.teslaSchedule || s1.executor.packetCount != s2.executor.packetCount {
		t.Fatal("reconnect replaced daemon-owned TESLA/counter identity")
	}
	if got := s2.storage.(*sqlite.SqliteStorage).QuarantinedCount(); got != 1 {
		t.Fatalf("successor did not quarantine exactly the old queued row: %d", got)
	}
	if _, err := client2.Abort(ctx, &pb.AbortRequest{DebugletId: queued.String(), Reason: "new binding cannot own old queue"}); err == nil {
		t.Fatal("successor cancelled a quarantined old binding")
	}
	var incarnation, sessionID string
	if err := f.db.QueryRowContext(ctx, "SELECT dispatcher_incarnation, session_id FROM debuglets WHERE uuid = ? AND started_at IS NULL", queued).Scan(&incarnation, &sessionID); err != nil || incarnation != oldBinding.Incarnation || sessionID != oldBinding.SessionID {
		t.Fatalf("quarantined ownership changed: incarnation=%q session=%q error=%v", incarnation, sessionID, err)
	}
	fresh := uuid.New()
	if _, err := client2.Upload(ctx, recoveryUpload(newBinding, fresh, false)); err != nil {
		t.Fatal(err)
	}
	if report := operationReport(t, peer, fresh); report.ExitCode != 0 || starts.Load() != 1 {
		t.Fatal("successor did not execute precisely its new work")
	}
	s2.Stop(nil)
	if err := s2.Wait(ctx); err != nil {
		t.Fatalf("successor did not join before harness cleanup: %v", err)
	}
	if err := f.db.QueryRowContext(ctx, "SELECT count(*) FROM debuglets").Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("joined reconnect left unexpected rows: rows=%d error=%v", rows, err)
	}
}
