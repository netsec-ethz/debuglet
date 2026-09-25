package executor

import (
	"context"
	"database/sql"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	dispatcherconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"
	dispatcherrpc "github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
	_ "modernc.org/sqlite"
)

// Cancellation traverses the actual Upload/Abort/Allocate/Exit RPC boundaries
// and canonical SQLite scheduler. No runtime may be constructed while Allocate
// is pending. Exit reporting is deliberately held to observe ownership before
// any harness cleanup, not merely an eventually absent process/container.
func TestAbortDuringAllocateSQLiteRPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db := newFixtureDatabase(t)
	storage := newFixtureStorage(t, db, func(binding controlsession.Binding) bool { return binding == operationBinding() })
	peer := newOperationPeer()
	allocating, allocateJoined, reporting := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseReport := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseReport) }) }
	var reportCalls atomic.Int32
	peer.allocate = func(ctx context.Context, _ *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error) {
		defer close(allocateJoined)
		close(allocating)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	peer.exit = func(ctx context.Context, req *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
		if reportCalls.Add(1) != 1 {
			t.Error("duplicate terminal report")
			return &pb.DebugletExitResponse{}, nil
		}
		if ctx.Err() != nil {
			t.Errorf("exit report inherited operation cancellation: %v", ctx.Err())
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > scheduler.CleanupTimeout {
			t.Error("exit report lacks the bounded fresh context")
		}
		if !strings.Contains(req.GetErrorMessage(), "cancel during allocation") {
			t.Errorf("exit lost selected cancellation cause: %q", req.GetErrorMessage())
		}
		close(reporting)
		select {
		case <-releaseReport:
			return &pb.DebugletExitResponse{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	e, client := newExecutorRPCFixture(t, peer, storage)
	var runtimeCreated atomic.Int32
	e.newRuntime = func(scheduler.Spec) runtimeDebuglet {
		runtimeCreated.Add(1)
		return &operationRuntime{}
	}
	loopCtx, stopLoop := context.WithCancel(ctx)
	loopDone := make(chan error, 1)
	go func() { loopDone <- storage.StartLoop(loopCtx) }()
	// Registered after the RPC fixture: join all callbacks before its transport
	// and database cleanup. Release the scripted report even on assertion failure.
	t.Cleanup(func() {
		release()
		stopLoop()
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelCleanup()
		if err := storage.Shutdown(cleanupCtx); err != nil {
			t.Errorf("join scheduler: %v", err)
		}
		select {
		case err := <-loopDone:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, scheduler.ErrClosed) {
				t.Error(err)
			}
		case <-cleanupCtx.Done():
			t.Error("scheduler dispatcher did not join")
		}
	})
	upload := func(id uuid.UUID, future bool) {
		t.Helper()
		req := &pb.UploadRequest{ControlBinding: operationWireBinding(), Id: id.String(), TransactionId: "local-cancellation", Wasm: []byte("\x00asm\x01\x00\x00\x00"),
			Policy: &pb.DebugletPolicy{FloorBw: 64000, CeilBw: 1000000, TimeoutMs: 30000, Addresses: []string{"127.0.0.1"}}}
		if future {
			req.StartTime = timestamppb.New(time.Now().Add(time.Hour))
		}
		if _, err := client.Upload(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	id, sibling := uuid.New(), uuid.New()
	upload(sibling, true)
	upload(id, false)
	if !operationAwait(t, allocating, "actual Allocate handler") {
		t.FailNow()
	}
	var started sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT started_at FROM debuglets WHERE uuid = ?", id).Scan(&started); err != nil || !started.Valid {
		t.Fatalf("allocation was not preceded by persisted start marker: %+v %v", started, err)
	}
	abortDone := make(chan error, 1)
	go func() {
		_, err := client.Abort(ctx, &pb.AbortRequest{DebugletId: id.String(), Reason: "cancel during allocation"})
		abortDone <- err
	}()
	// Join the owned caller before the general fixture cleanup too.
	joinedAbort := false
	t.Cleanup(func() {
		release()
		if !joinedAbort {
			cancel()
			select {
			case <-abortDone:
			case <-time.After(5 * time.Second):
				t.Error("Abort caller did not join")
			}
		}
	})
	if !operationAwait(t, reporting, "uncancelled terminal report") {
		t.FailNow()
	}
	if !operationAwait(t, allocateJoined, "cancelled Allocate handler") {
		t.FailNow()
	}
	select {
	case err := <-abortDone:
		joinedAbort = true
		t.Fatalf("Abort returned before its terminal-report worker joined: %v", err)
	default:
	}
	var rows int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM debuglets WHERE uuid = ?", id).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("executor row retired before callback joined: rows=%d err=%v", rows, err)
	}
	release()
	select {
	case err := <-abortDone:
		joinedAbort = true
		if err != nil {
			t.Fatalf("Abort did not confirm local completion: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Abort failed to join after report release")
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM debuglets WHERE uuid = ?", id).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("successful Abort left restorable row: rows=%d err=%v", rows, err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM debuglets WHERE uuid = ? AND started_at IS NULL", sibling).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("cancellation disturbed queued sibling: rows=%d err=%v", rows, err)
	}
	e.mu.RLock()
	running := len(e.running)
	e.mu.RUnlock()
	if runtimeCreated.Load() != 0 || running != 0 || reportCalls.Load() != 1 {
		t.Fatalf("created=%d running=%d reports=%d", runtimeCreated.Load(), running, reportCalls.Load())
	}
}

// A real executor unwinds a real dispatcher's allocation rejection, including
// the destination the dispatcher charged and released again before rejecting,
// and reports the failed outcome before its canonical executor row
// disappears. Both databases use checked-in migrations.
func TestRejectedAllocationFinalizesBothSQLiteOwners(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	openDB := func(name, migrations string) *sql.DB {
		t.Helper()
		db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), name))
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		t.Cleanup(func() {
			if err := db.Close(); err != nil {
				t.Error(err)
			}
		})
		testutil.ApplyMigrations(t, db, migrations)
		return db
	}
	executorDB := openDB("executor.sqlite", "database/migrations")
	dispatcherDB := openDB("dispatcher.sqlite", "../dispatcher/database/migrations")
	logger := zap.NewNop()
	payment := payments.NewPaymentHandler(dispatcherDB, &dispatcherconfig.DispatcherConfig{Sui: dispatcherconfig.SuiConfig{Disabled: true}}, logger)
	d, err := dispatcher.New(logger, dispatcherDB, "cancellation-fixture", time.Minute, time.Second, payment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	binding, err := controlsession.NewBinding(d.ControlIncarnation())
	if err != nil {
		t.Fatal(err)
	}
	storage := newFixtureStorage(t, executorDB, func(candidate controlsession.Binding) bool { return candidate == binding })
	peer := newOperationPeer()
	e, client := newExecutorRPCFixtureForBinding(t, peer, storage, binding)
	var created atomic.Int32
	e.newRuntime = func(scheduler.Spec) runtimeDebuglet { created.Add(1); return &operationRuntime{} }
	id := uuid.New()
	const transaction = "local-partial-allocation"
	const floor = int64(64000)
	const destination, blocked = "127.0.0.1", "127.0.0.2"
	addresses := []string{destination, blocked}
	owner, err := dispatcherrpc.NewSessionOwner(e.cfg.Identity.ExecutorID, binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// This inherited fixture uses actual direct gRPC with explicit admitted
	// callback tickets. Full negotiation is covered by separate two-channel tests.
	peer.allocate = func(ctx context.Context, req *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error) {
		ticket, err := owner.AdmitMutation(ctx)
		if err != nil {
			return nil, err
		}
		defer ticket.Finish()
		return d.OnDebugletAllocate(ticket.Context(), ticket, req)
	}
	peer.state = func(ctx context.Context, req *pb.DebugletStateRequest) (*pb.DebugletStateResponse, error) {
		ticket, err := owner.AdmitMutation(ctx)
		if err != nil {
			return nil, err
		}
		defer ticket.Finish()
		return d.OnDebugletState(ticket.Context(), ticket, req)
	}
	peer.exit = func(ctx context.Context, req *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
		ticket, err := owner.AdmitMutation(ctx)
		if err != nil {
			return nil, err
		}
		defer ticket.Finish()
		return d.OnDebugletExit(ticket.Context(), ticket, req)
	}
	// Registration runs inside a setup operation the caller admits and finishes,
	// the way the real negotiation registers an executor.
	setup, err := owner.AdmitSetup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer setup.Finish()
	if err := d.RegisterExecutor(setup.Context(), owner, &pb.HelloResponse{
		ExecutorId: e.cfg.Identity.ExecutorID, Version: "local-fixture", PricePerBwS: 1, Currency: "TEST",
	}, destination); err != nil {
		t.Fatalf("register fixture executor: %v", err)
	}
	if !owner.MarkRegistered() {
		t.Fatal("fixture executor owner retired before registration completed")
	}
	resourceTicket, err := owner.AdmitMutation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.OnResources(resourceTicket.Context(), resourceTicket, &pb.ResourcesRequest{ExecutorId: e.cfg.Identity.ExecutorID, BandwidthCapacity: int64(resource.Megabit)})
	resourceTicket.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := payment.CreatePaymentIntent(transaction, floor, "TEST", "local-hash", ctx); err != nil {
		t.Fatal(err)
	}
	queries := dispatcherdb.New(dispatcherDB)
	if _, err := queries.CreateDebugletOrder(ctx, dispatcherdb.CreateDebugletOrderParams{TransactionID: transaction, OrderID: 1, ExecutorID: e.cfg.Identity.ExecutorID, Price: floor, Currency: "TEST", State: int64(models.Outstanding)}); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC()
	if _, err := queries.CreateDebuglet(ctx, dispatcherdb.CreateDebugletParams{DispatcherIncarnation: binding.Incarnation, SessionID: binding.SessionID, Uuid: id, StartTime: models.NewUTCTime(start), EndTime: models.NewUTCTime(start.Add(time.Minute)), Usage: floor, CeilBw: 2 * floor, ExecutorID: e.cfg.Identity.ExecutorID, Addresses: addresses, State: models.RunStateUploaded, TransactionID: transaction, OrderID: 1}); err != nil {
		t.Fatal(err)
	}
	if err := d.RestoreScheduler(ctx); err != nil {
		t.Fatal(err)
	}
	// The run fits on the first destination and not on the second, so the
	// dispatcher rejects the whole allocation after charging the first one.
	d.SetDestinationLimit(destination, resource.Bitrate(floor))
	d.SetDestinationLimit(blocked, resource.Bitrate(floor-1))
	if _, err := client.Upload(ctx, &pb.UploadRequest{ControlBinding: &pb.ControlBinding{DispatcherIncarnation: binding.Incarnation, SessionId: binding.SessionID}, Id: id.String(), TransactionId: transaction, Wasm: []byte("\x00asm\x01\x00\x00\x00"), Policy: &pb.DebugletPolicy{FloorBw: floor, CeilBw: 2 * floor, TimeoutMs: 30000, Addresses: addresses}}); err != nil {
		t.Fatal(err)
	}
	loopCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- storage.StartLoop(loopCtx) }()
	t.Cleanup(func() {
		stop()
		cleanupCtx, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		if err := storage.Shutdown(cleanupCtx); err != nil {
			t.Errorf("join rejected allocation: %v", err)
		}
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, scheduler.ErrClosed) {
				t.Error(err)
			}
		case <-cleanupCtx.Done():
			t.Error("scheduler loop did not join")
		}
	})
	report := operationReport(t, peer, id)
	if report.GetExitCode() == 0 || !strings.Contains(report.GetErrorMessage(), "allocate destination") {
		t.Fatalf("wrong rejection outcome: %+v", report)
	}
	// An observed report precedes callback return; wait separately for the
	// actual canonical deletion, then join the scheduler before asserting effects.
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var count int
		if err := executorDB.QueryRowContext(ctx, "SELECT count(*) FROM debuglets WHERE uuid = ?", id).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			break
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("executor finalization did not remove row")
		}
	}
	if err := storage.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	row, err := queries.GetDebugletByUUID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if row.State != models.RunStateExited || !row.Error.Valid || !strings.Contains(row.Error.String, "allocate destination") {
		t.Fatalf("dispatcher lost failed outcome: %+v", row)
	}
	if created.Load() != 0 {
		t.Fatalf("rejected allocation constructed %d runtimes", created.Load())
	}
	select {
	case extra := <-peer.reports:
		t.Fatalf("duplicate report: %+v", extra)
	default:
	}
	// The existing TEST refund limitation is preserved; no credit is invented.
	order, err := queries.GetDebugletOrder(ctx, dispatcherdb.GetDebugletOrderParams{TransactionID: transaction, OrderID: 1})
	if err != nil || order.State != int64(models.Outstanding) {
		t.Fatalf("TEST order = %+v, err=%v", order, err)
	}
}
