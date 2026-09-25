package executor

import (
	"context"
	"database/sql"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/memory"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/sqlite"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const operationTestBound = 2 * time.Second

// fixtureAdmission commits every guarded transition, which is how a core behaves
// while its session binding stays eligible. The recovery sessions build the real
// guards from their Bidi lease instead.
func fixtureAdmission() scheduler.Admission {
	pass := func(_ controlsession.Binding, commit func()) error { commit(); return nil }
	return scheduler.Admission{Insert: pass, Start: pass}
}

func newFixtureStorage(t *testing.T, db *sql.DB, eligibility scheduler.RestoreEligibility) *sqlite.SqliteStorage {
	t.Helper()
	storage, err := sqlite.NewStorage(db, eligibility, fixtureAdmission())
	if err != nil {
		t.Fatal(err)
	}
	return storage
}

func newFixtureMemoryStorage(t *testing.T) *memory.MemoryStorage {
	t.Helper()
	storage, err := memory.NewStorage(fixtureAdmission())
	if err != nil {
		t.Fatal(err)
	}
	return storage
}

// fixtureConfig is a valid local configuration: no TLS material to load, the
// fallback packet counter and the default listener range.
func fixtureConfig() *config.ExecutorConfig {
	return &config.ExecutorConfig{
		Identity:  config.IdentityConfig{ExecutorID: uuid.NewString()},
		TLS:       config.TLSConfig{Disable: true},
		Resources: config.ResourcesConfig{MaxDebuglets: 8},
		Tesla:     config.TeslaConfig{Seed: "local executor fixture", Delay: 2, ChainLength: 64},
		Network:   config.NetworkConfig{PacketCounter: "fallback", DisableSCIONEnvironment: true},
	}
}

// newFixtureExecutor constructs one the way a session does, through node and
// executor construction, so a fixture holds exactly the state production holds.
// counter replaces the daemon packet counter; nil takes the configured one. The
// result owns no control transport: a scripted direct client defines its session.
func newFixtureExecutor(t *testing.T, cfg *config.ExecutorConfig, counter ratelimit.PacketCount, storage scheduler.Scheduler) *Executor {
	t.Helper()
	acquire := ratelimit.New
	if counter != nil {
		acquire = func(*net.Interface, *zap.Logger) (ratelimit.PacketCount, error) { return counter, nil }
	}
	node, err := newNode(cfg, zap.NewNop(), acquire)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := node.Close(); err != nil {
			t.Error(err)
		}
	})
	e, err := newExecutor(node, storage)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// These are real loopback gRPC endpoints. The root integration test may reuse
// this helper with an actual SQLite scheduler and its own dispatcher service.
func newExecutorRPCFixture(t *testing.T, peer pb.DispatcherServiceServer, storage scheduler.Scheduler) (*Executor, pb.ExecutorServiceClient) {
	t.Helper()
	return newExecutorRPCFixtureForBinding(t, peer, storage, operationBinding())
}

func newExecutorRPCFixtureForBinding(t *testing.T, peer pb.DispatcherServiceServer, storage scheduler.Scheduler, expected controlsession.Binding) (*Executor, pb.ExecutorServiceClient) {
	t.Helper()
	if storage == nil {
		storage = newFixtureMemoryStorage(t)
	}
	e := newFixtureExecutor(t, fixtureConfig(), nil, storage)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.WaitForHandlers(true))
	pb.RegisterDispatcherServiceServer(server, peer)
	pb.RegisterExecutorServiceServer(server, &operationExecutorServer{executor: e, binding: expected})
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		server.Stop()
		listener.Close()
		<-served
		t.Fatal(err)
	}
	e.clientFor = func(ctx context.Context, binding controlsession.Binding) (pb.DispatcherServiceClient, error) {
		if binding != expected {
			return nil, errors.New("fixture received wrong captured binding")
		}
		return pb.NewDispatcherServiceClient(conn), nil
	}
	t.Cleanup(func() {
		conn.Close()
		stopped := make(chan struct{})
		go func() { server.Stop(); close(stopped) }()
		if !operationAwait(t, stopped, "RPC handlers to join") {
			<-stopped
		}
		listener.Close()
		select {
		case err := <-served:
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		case <-time.After(operationTestBound):
			t.Error("RPC serve loop did not join")
		}
	})
	return e, pb.NewExecutorServiceClient(conn)
}

type operationExecutorServer struct {
	pb.UnimplementedExecutorServiceServer
	executor *Executor
	binding  controlsession.Binding
}

func (s *operationExecutorServer) Upload(ctx context.Context, req *pb.UploadRequest) (*pb.UploadResponse, error) {
	return s.executor.OnUpload(ctx, s.binding, req)
}
func (s *operationExecutorServer) Abort(ctx context.Context, req *pb.AbortRequest) (*pb.AbortResponse, error) {
	return s.executor.OnAbort(ctx, s.binding, req)
}
func (s *operationExecutorServer) InspectRetainedRun(ctx context.Context, req *pb.InspectRetainedRunRequest) (*pb.InspectRetainedRunResponse, error) {
	return s.executor.OnInspectRetainedRun(ctx, s.binding, req)
}

type operationPeer struct {
	pb.UnimplementedDispatcherServiceServer
	allocate    func(context.Context, *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error)
	state       func(context.Context, *pb.DebugletStateRequest) (*pb.DebugletStateResponse, error)
	stream      func(grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error
	exit        func(context.Context, *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error)
	reports     chan *pb.DebugletExitRequest
	reportCalls atomic.Int32
}

func newOperationPeer() *operationPeer {
	return &operationPeer{reports: make(chan *pb.DebugletExitRequest, 16)}
}
func (p *operationPeer) DebugletAllocate(ctx context.Context, req *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error) {
	if p.allocate != nil {
		return p.allocate(ctx, req)
	}
	return &pb.DebugletAllocateResponse{}, nil
}
func (p *operationPeer) DebugletState(ctx context.Context, req *pb.DebugletStateRequest) (*pb.DebugletStateResponse, error) {
	if p.state != nil {
		return p.state(ctx, req)
	}
	return &pb.DebugletStateResponse{}, nil
}
func (p *operationPeer) DebugletExit(ctx context.Context, req *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
	p.reportCalls.Add(1)
	select {
	case p.reports <- req:
	default:
		return nil, errors.New("too many fixture exit reports")
	}
	if p.exit != nil {
		return p.exit(ctx, req)
	}
	return &pb.DebugletExitResponse{}, nil
}
func (p *operationPeer) DebugletStream(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
	if p.stream != nil {
		return p.stream(stream)
	}
	for {
		if _, err := stream.Recv(); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

type operationRuntime struct {
	init           func(context.Context) error
	run            func(context.Context, chan<- []byte) error
	close          func(context.Context) error
	lateCloseError func() error
	closeOnce      sync.Once
	closeErr       error
	starts         atomic.Int32
	closes         atomic.Int32
}

func (r *operationRuntime) InitRuntime(ctx context.Context, _ []byte) error {
	if r.init != nil {
		return r.init(ctx)
	}
	return ctx.Err()
}
func (r *operationRuntime) StartServers(ctx context.Context, _ debuglet.StartServersReq) error {
	return ctx.Err()
}
func (r *operationRuntime) Run(ctx context.Context, out chan<- []byte, _ []string) error {
	r.starts.Add(1)
	defer close(out)
	if r.run != nil {
		return r.run(ctx, out)
	}
	return ctx.Err()
}
func (r *operationRuntime) Close(ctx context.Context) error {
	r.closeOnce.Do(func() {
		r.closes.Add(1)
		if r.close != nil {
			r.closeErr = r.close(ctx)
		}
	})
	if r.lateCloseError != nil {
		return errors.Join(r.closeErr, r.lateCloseError())
	}
	return r.closeErr
}

func operationSpec() scheduler.Spec {
	return scheduler.Spec{Binding: operationBinding(), DebugletID: uuid.New(), TransactionID: "local-test", Policy: scheduler.Policy{FloorBW: 64000, CeilBW: 1000000, Timeout: time.Second, Addresses: []string{"127.0.0.1"}}}
}
func operationAwait(t *testing.T, done <-chan struct{}, what string) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(operationTestBound):
		t.Error("timed out waiting for", what)
		return false
	}
}

// Cleanup gives an in-flight bounded report time to finish before tearing down
// its RPC fixture. A failed join remains a test failure, and retains ownership
// until the package deadline rather than continuing with a live callback.
func operationJoinCleanup(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * scheduler.CleanupTimeout):
		t.Error("timed out joining", what)
		<-done
	}
}

func operationReport(t *testing.T, peer *operationPeer, id uuid.UUID) *pb.DebugletExitRequest {
	t.Helper()
	select {
	case report := <-peer.reports:
		if report.DebugletId != id.String() {
			t.Fatal("report identity mismatch")
		}
		if peer.reportCalls.Load() != 1 {
			t.Fatal("exit report was repeated")
		}
		select {
		case <-peer.reports:
			t.Fatal("duplicate exit report")
		default:
		}
		return report
	case <-time.After(operationTestBound):
		t.Fatal("missing exit report")
		return nil
	}
}

// operationRetriedReport joins a report the fixture peer rejects. The bounded
// retry repeats the identical chosen result and then stops.
func operationRetriedReport(t *testing.T, peer *operationPeer, id uuid.UUID) *pb.DebugletExitRequest {
	t.Helper()
	var first *pb.DebugletExitRequest
	for range maxExitReportAttempts {
		select {
		case report := <-peer.reports:
			if report.GetDebugletId() != id.String() {
				t.Fatal("report identity mismatch")
			}
			if first == nil {
				first = report
			} else if report.GetExitCode() != first.GetExitCode() || report.GetErrorMessage() != first.GetErrorMessage() {
				t.Fatal("a retry changed the chosen terminal result")
			}
		case <-time.After(operationTestBound):
			t.Fatal("missing exit report")
			return nil
		}
	}
	if got := peer.reportCalls.Load(); got != int32(maxExitReportAttempts) {
		t.Fatalf("rejected report made %d attempts, want %d", got, maxExitReportAttempts)
	}
	select {
	case <-peer.reports:
		t.Fatal("retry exceeded its bound")
	default:
	}
	return first
}

func operationBinding() controlsession.Binding {
	return controlsession.Binding{Incarnation: "c31f0dc2-3f96-4a5a-aa2a-a4bcc16d88fb", SessionID: "6f2f15d8-f982-44a8-b22c-8d80fa5f8b62"}
}
func operationWireBinding() *pb.ControlBinding {
	binding := operationBinding()
	return &pb.ControlBinding{DispatcherIncarnation: binding.Incarnation, SessionId: binding.SessionID}
}
