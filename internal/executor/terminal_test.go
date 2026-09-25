package executor

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/sqlite"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const terminalTestBound = 30 * time.Second

// newTerminalStorage owns a real executor database. Shutdown is registered
// after the database, so owned callbacks always join before it is closed.
func newTerminalStorage(t *testing.T) (*sqlite.SqliteStorage, *sql.DB) {
	t.Helper()
	db := newFixtureDatabase(t)
	storage := newFixtureStorage(t, db, func(b controlsession.Binding) bool { return b == operationBinding() })
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*scheduler.CleanupTimeout)
		defer cancel()
		if err := storage.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	return storage, db
}

func terminalFailure(t *testing.T, e *Executor, spec scheduler.Spec) {
	t.Helper()
	completion := e.OnDebugletFailed(context.Background(), spec, errors.New("held start failure"))
	if completion.CleanupErr != nil {
		t.Fatal(completion.CleanupErr)
	}
}

// A lost reply is retried inside the same session, and every attempt carries
// the identical chosen result. The acknowledged result is then released.
func TestTerminalReportRetriesWithinItsSession(t *testing.T) {
	storage, _ := newTerminalStorage(t)
	peer := newOperationPeer()
	var calls atomic.Int32
	peer.exit = func(context.Context, *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
		if calls.Add(1) < int32(maxExitReportAttempts) {
			return nil, errors.New("held dispatcher failure")
		}
		return &pb.DebugletExitResponse{}, nil
	}
	e, _ := newExecutorRPCFixture(t, peer, storage)
	spec := operationSpec()
	terminalFailure(t, e, spec)

	if got := peer.reportCalls.Load(); got != int32(maxExitReportAttempts) {
		t.Fatalf("bounded retry made %d attempts, want %d", got, maxExitReportAttempts)
	}
	for range maxExitReportAttempts {
		report := <-peer.reports
		if report.GetDebugletId() != spec.DebugletID.String() || report.GetExitCode() != -1 || report.GetErrorMessage() == "" {
			t.Fatalf("a retry changed the chosen terminal result: %+v", report)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), terminalTestBound)
	defer cancel()
	if _, found, err := storage.RetainedTerminal(ctx, spec.DebugletID); err != nil || found {
		t.Fatalf("acknowledged result stayed retained: found=%v error=%v", found, err)
	}
}

// When no attempt is acknowledged the executor keeps the evidence: the chosen
// result, its run identity and binding, and how many attempts were made.
func TestTerminalReportRetainsUnacknowledgedResult(t *testing.T) {
	storage, _ := newTerminalStorage(t)
	peer := newOperationPeer()
	peer.exit = func(context.Context, *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
		return nil, errors.New("dispatcher rejected the report")
	}
	e, _ := newExecutorRPCFixture(t, peer, storage)
	spec := operationSpec()
	terminalFailure(t, e, spec)

	if got := peer.reportCalls.Load(); got != int32(maxExitReportAttempts) {
		t.Fatalf("retry was not bounded at %d attempts: %d", maxExitReportAttempts, got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), terminalTestBound)
	defer cancel()
	event, found, err := storage.RetainedTerminal(ctx, spec.DebugletID)
	if err != nil || !found {
		t.Fatalf("unacknowledged result was not retained: found=%v error=%v", found, err)
	}
	if event.Binding != spec.Binding || event.ExitCode != -1 || event.ErrorMessage == nil {
		t.Fatalf("retained event lost the chosen result: %+v", event)
	}
	if event.Attempts != int64(maxExitReportAttempts) || event.LastError == "" || event.LastAttemptAt.IsZero() {
		t.Fatalf("retained event did not record its attempts: %+v", event)
	}
	events, err := storage.ListRetainedTerminals(ctx, spec.Binding, 8)
	if err != nil || len(events) != 1 || events[0].DebugletID != spec.DebugletID {
		t.Fatalf("unreconciled event was not inspectable: %d error=%v", len(events), err)
	}
}

// Reconciliation delivers what is still retained under the same binding. It
// reads and sends only: no runtime is constructed and no guest runs again.
func TestTerminalReconciliationDeliversWithoutReplay(t *testing.T) {
	storage, _ := newTerminalStorage(t)
	peer := newOperationPeer()
	var accept atomic.Bool
	peer.exit = func(context.Context, *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
		if !accept.Load() {
			return nil, errors.New("dispatcher unavailable")
		}
		return &pb.DebugletExitResponse{}, nil
	}
	e, _ := newExecutorRPCFixture(t, peer, storage)
	var runtimes atomic.Int32
	e.newRuntime = func(scheduler.Spec) runtimeDebuglet { runtimes.Add(1); return &operationRuntime{} }
	spec := operationSpec()
	terminalFailure(t, e, spec)

	ctx, cancel := context.WithTimeout(context.Background(), terminalTestBound)
	defer cancel()
	accept.Store(true)
	e.reconcileTerminals(ctx, operationBinding())
	if _, found, err := storage.RetainedTerminal(ctx, spec.DebugletID); err != nil || found {
		t.Fatalf("reconciled result stayed retained: found=%v error=%v", found, err)
	}
	delivered := peer.reportCalls.Load()
	e.reconcileTerminals(ctx, operationBinding())
	if peer.reportCalls.Load() != delivered {
		t.Fatal("reconciliation redelivered an already acknowledged result")
	}
	if runtimes.Load() != 0 {
		t.Fatalf("reconciliation constructed %d runtimes", runtimes.Load())
	}
}

// A replacement session never redelivers the previous session's results: the
// retained event stays exactly where a later reconciliation can inspect it.
func TestTerminalReconciliationSkipsAnotherSession(t *testing.T) {
	storage, _ := newTerminalStorage(t)
	peer := newOperationPeer()
	peer.exit = func(context.Context, *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
		return nil, errors.New("dispatcher unavailable")
	}
	e, _ := newExecutorRPCFixture(t, peer, storage)
	spec := operationSpec()
	terminalFailure(t, e, spec)
	attempted := peer.reportCalls.Load()

	ctx, cancel := context.WithTimeout(context.Background(), terminalTestBound)
	defer cancel()
	successor := controlsession.Binding{Incarnation: operationBinding().Incarnation, SessionID: "0f3b31ce-2d0b-4d5f-9df3-5a2d9b1c6a11"}
	e.reconcileTerminals(ctx, successor)
	if peer.reportCalls.Load() != attempted {
		t.Fatal("a replacement session redelivered another session's result")
	}
	event, found, err := storage.RetainedTerminal(ctx, spec.DebugletID)
	if err != nil || !found || event.Binding != operationBinding() {
		t.Fatalf("retained event changed ownership: %+v found=%v error=%v", event, found, err)
	}
}

// A hung dispatcher consumes the reporting budget instead of extending it, so
// resource cleanup and scheduler joins stay bounded when reporting fails.
func TestTerminalReportStaysBoundedWhenDeliveryHangs(t *testing.T) {
	storage, _ := newTerminalStorage(t)
	peer := newOperationPeer()
	peer.exit = func(ctx context.Context, _ *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	e, _ := newExecutorRPCFixture(t, peer, storage)
	spec := operationSpec()
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.OnDebugletFailed(context.Background(), spec, errors.New("held start failure"))
	}()
	select {
	case <-done:
	case <-time.After(4 * scheduler.CleanupTimeout):
		t.Fatal("terminal reporting outlived its bound")
	}
	if got := peer.reportCalls.Load(); got != 1 {
		t.Fatalf("a hung attempt was retried inside its own budget: %d", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), terminalTestBound)
	defer cancel()
	event, found, err := storage.RetainedTerminal(ctx, spec.DebugletID)
	if err != nil || !found || event.Attempts != 1 {
		t.Fatalf("hung delivery left no evidence: %+v found=%v error=%v", event, found, err)
	}
}

// Schedulers without durable retention keep reporting exactly as before.
func TestTerminalReportWithoutRetention(t *testing.T) {
	peer := newOperationPeer()
	e, _ := newExecutorRPCFixture(t, peer, nil)
	spec := operationSpec()
	spec.DebugletID = uuid.New()
	terminalFailure(t, e, spec)
	if got := peer.reportCalls.Load(); got != 1 {
		t.Fatalf("volatile scheduler reported %d times", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), terminalTestBound)
	defer cancel()
	e.reconcileTerminals(ctx, operationBinding())
	if got := peer.reportCalls.Load(); got != 1 {
		t.Fatalf("volatile scheduler reconciled %d times", got)
	}
}

func terminalStaleBinding() controlsession.Binding {
	return controlsession.Binding{Incarnation: operationBinding().Incarnation, SessionID: "0f3b31ce-2d0b-4d5f-9df3-5a2d9b1c6a11"}
}

// Results no session can deliver never occupy a pass: more retained results
// than one pass carries, all owned by a replaced session, still leave the live
// session's own result deliverable.
func TestTerminalReconciliationIsNotStarvedByStaleResults(t *testing.T) {
	storage, _ := newTerminalStorage(t)
	peer := newOperationPeer()
	e, _ := newExecutorRPCFixture(t, peer, storage)
	ctx, cancel := context.WithTimeout(context.Background(), terminalTestBound)
	defer cancel()

	base := time.Now().UTC().Add(-time.Hour)
	for i := range maxReconciledPerPass + 8 {
		event := scheduler.TerminalEvent{
			DebugletID: uuid.New(), Binding: terminalStaleBinding(), ExitCode: -1,
			RecordedAt: base.Add(time.Duration(i) * time.Second),
		}
		if err := storage.RecordTerminal(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	live := uuid.New()
	if err := storage.RecordTerminal(ctx, scheduler.TerminalEvent{
		DebugletID: live, Binding: operationBinding(), ExitCode: 0, RecordedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	e.reconcileTerminals(ctx, operationBinding())
	if got := peer.reportCalls.Load(); got != 1 {
		t.Fatalf("stale results crowded out the deliverable one: %d deliveries", got)
	}
	if report := <-peer.reports; report.GetDebugletId() != live.String() {
		t.Fatalf("delivered the wrong result: %+v", report)
	}
	if _, found, err := storage.RetainedTerminal(ctx, live); err != nil || found {
		t.Fatalf("delivered result stayed retained: found=%v error=%v", found, err)
	}
	all, err := storage.ListAllRetainedTerminals(ctx, 128)
	if err != nil || len(all) != maxReconciledPerPass+8 {
		t.Fatalf("stale results were disturbed: %d error=%v", len(all), err)
	}
}

// A refusal the dispatcher would only repeat stops the retry at once, keeps
// the result as evidence and leaves the reconciliation set.
func TestTerminalReportStopsOnPermanentRejection(t *testing.T) {
	for _, code := range []codes.Code{codes.PermissionDenied, codes.NotFound, codes.InvalidArgument} {
		t.Run(code.String(), func(t *testing.T) {
			storage, _ := newTerminalStorage(t)
			peer := newOperationPeer()
			peer.exit = func(context.Context, *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
				return nil, status.Error(code, "dispatcher refused the report")
			}
			e, _ := newExecutorRPCFixture(t, peer, storage)
			spec := operationSpec()
			terminalFailure(t, e, spec)
			if got := peer.reportCalls.Load(); got != 1 {
				t.Fatalf("a permanent refusal was retried %d times", got)
			}
			ctx, cancel := context.WithTimeout(context.Background(), terminalTestBound)
			defer cancel()
			event, found, err := storage.RetainedTerminal(ctx, spec.DebugletID)
			if err != nil || !found || !event.Rejected || event.Attempts != 1 || event.LastError == "" {
				t.Fatalf("refused result lost its evidence: %+v found=%v error=%v", event, found, err)
			}
			deliverable, err := storage.ListRetainedTerminals(ctx, spec.Binding, 32)
			if err != nil || len(deliverable) != 0 {
				t.Fatalf("refused result stayed deliverable: %d error=%v", len(deliverable), err)
			}
			e.reconcileTerminals(ctx, operationBinding())
			if got := peer.reportCalls.Load(); got != 1 {
				t.Fatalf("refused result was retried by a later pass: %d", got)
			}
			if _, found, err := storage.RetainedTerminal(ctx, spec.DebugletID); err != nil || !found {
				t.Fatalf("refused result stopped being inspectable: found=%v error=%v", found, err)
			}
		})
	}
}

// Reporting and reconciliation never settle the same result at once.
func TestTerminalDeliveryIsClaimedOnce(t *testing.T) {
	storage, _ := newTerminalStorage(t)
	peer := newOperationPeer()
	e, _ := newExecutorRPCFixture(t, peer, storage)
	ctx, cancel := context.WithTimeout(context.Background(), terminalTestBound)
	defer cancel()

	id := uuid.New()
	if err := storage.RecordTerminal(ctx, scheduler.TerminalEvent{
		DebugletID: id, Binding: operationBinding(), ExitCode: 0, RecordedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if !e.beginDelivery(id) {
		t.Fatal("a fresh identity was already claimed")
	}
	if e.beginDelivery(id) {
		t.Fatal("one identity was claimed twice")
	}
	e.reconcileTerminals(ctx, operationBinding())
	if got := peer.reportCalls.Load(); got != 0 {
		t.Fatalf("a pass delivered a result another caller owned: %d", got)
	}
	if _, found, err := storage.RetainedTerminal(ctx, id); err != nil || !found {
		t.Fatalf("skipped result was released: found=%v error=%v", found, err)
	}
	e.endDelivery(id)
	e.reconcileTerminals(ctx, operationBinding())
	if got := peer.reportCalls.Load(); got != 1 {
		t.Fatalf("released claim did not allow delivery: %d", got)
	}
}

// The heartbeat only kicks reconciliation; the pass itself runs on the loop,
// which delivers what it finds and returns when its session ends.
func TestTerminalReconcileLoopRunsOffTheHeartbeat(t *testing.T) {
	storage, _ := newTerminalStorage(t)
	peer := newOperationPeer()
	e, _ := newExecutorRPCFixture(t, peer, storage)
	ctx, cancel := context.WithTimeout(context.Background(), terminalTestBound)
	defer cancel()

	first := uuid.New()
	if err := storage.RecordTerminal(ctx, scheduler.TerminalEvent{
		DebugletID: first, Binding: operationBinding(), ExitCode: 0, RecordedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	loopCtx, stopLoop := context.WithCancel(ctx)
	joined := make(chan struct{})
	go func() { defer close(joined); e.reconcileLoop(loopCtx, operationBinding()) }()
	select {
	case report := <-peer.reports:
		if report.GetDebugletId() != first.String() {
			t.Fatalf("loop delivered the wrong result: %+v", report)
		}
	case <-ctx.Done():
		t.Fatal("the loop never made its first pass")
	}

	second := uuid.New()
	if err := storage.RecordTerminal(ctx, scheduler.TerminalEvent{
		DebugletID: second, Binding: operationBinding(), ExitCode: 0, RecordedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	e.kickReconcile()
	e.kickReconcile() // A pending request covers a second one.
	select {
	case report := <-peer.reports:
		if report.GetDebugletId() != second.String() {
			t.Fatalf("kicked pass delivered the wrong result: %+v", report)
		}
	case <-ctx.Done():
		t.Fatal("a kick did not produce a pass")
	}
	stopLoop()
	select {
	case <-joined:
	case <-time.After(2 * scheduler.CleanupTimeout):
		t.Fatal("the reconciliation loop did not join its session")
	}
}
