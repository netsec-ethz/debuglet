package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

type statementBudget struct {
	remaining time.Duration
	bounded   bool
	err       error
}
type budgetConnection struct {
	database.DBTX
	budgets chan<- statementBudget
}

func (db *budgetConnection) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	deadline, bounded := ctx.Deadline()
	db.budgets <- statementBudget{time.Until(deadline), bounded, ctx.Err()}
	return db.DBTX.ExecContext(ctx, query, args...)
}
func awaitPoolWaiters(t *testing.T, db *sql.DB, want int64) {
	t.Helper()
	deadline := time.NewTimer(cancellationTestBound)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for db.Stats().WaitCount < want {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("database admission waiters=%d want at least%d", db.Stats().WaitCount, want)
		}
	}
}

// All three waits occur on the actual one-connection sql.DB pool: an accepted
// queued deletion, a completed callback's finalizer, and a reserved new Insert.
// They remain owned beyond the SQL budget. Caller/Shutdown deadlines cannot
// release that ownership or turn a successfully persisted Insert into rejection.
func TestSQLiteSQLBudgetAfterConnectionAdmission(t *testing.T) {
	db := newSchedulerTestDB(t)
	s := newTestStorage(t, db, storageTestEligibility)
	cancellationCleanup(t, s)
	budgets := make(chan statementBudget, 8)
	s.decorate = func(conn database.DBTX) database.DBTX { return &budgetConnection{conn, budgets} }
	gate := newCancellationGate(t)
	started := make(chan struct{})
	var callbacks atomic.Int32
	s.RegisterOnStart(func(context.Context, scheduler.Spec) scheduler.Completion {
		callbacks.Add(1)
		close(started)
		gate.hold(context.Background())
		return scheduler.Completion{}
	})
	future := time.Now().Add(time.Hour)
	queuedSpec := insertTestSpec()
	queuedSpec.StartTime = &future
	activeSpec := insertTestSpec()
	activeSpec.DebugletID = uuid.New()
	for _, spec := range []scheduler.Spec{queuedSpec, activeSpec} {
		if err := s.Insert(context.Background(), spec); err != nil {
			t.Fatal(err)
		}
	}
	cancellationLoop(t, s)
	cancellationAwait(t, started, "callback after actual start marker")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	held, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Release only this fixture's connection, including all assertion failures.
	t.Cleanup(func() { held.Close() })
	baseline := db.Stats().WaitCount
	for len(budgets) > 0 {
		<-budgets
	}

	queuedDone, queuedWaiting := cancellationCall(t, s, queuedSpec.DebugletID, nil, 50*time.Millisecond)
	cancellationAwait(t, queuedWaiting, "queued cancellation admitted")
	gate.open() // The callback finishes, but its actual finalizer needs the pool.
	acceptedSpec := insertTestSpec()
	acceptedSpec.DebugletID = uuid.New()
	acceptedSpec.StartTime = &future
	insertDone := cancellationCaller(t, func() { held.Close(); cancel() }, func() error { return s.Insert(ctx, acceptedSpec) })
	awaitPoolWaiters(t, db, baseline+3)
	if result := cancellationAwait(t, queuedDone, "queued caller timeout"); !result.found || !errors.Is(result.err, context.DeadlineExceeded) {
		t.Fatalf("queued cancellation while pool held: %+v", result)
	}
	activeDone, activeWaiting := cancellationCall(t, s, activeSpec.DebugletID, nil, 50*time.Millisecond)
	cancellationAwait(t, activeWaiting, "active finalizer joined")
	if result := cancellationAwait(t, activeDone, "active caller timeout"); !result.found || !errors.Is(result.err, context.DeadlineExceeded) {
		t.Fatalf("active finalization while pool held: %+v", result)
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 50*time.Millisecond)
	if err := s.Shutdown(shutdownCtx); !errors.Is(err, context.DeadlineExceeded) {
		cancelShutdown()
		t.Fatalf("owned admission was discarded: Shutdown=%v", err)
	}
	cancelShutdown()

	// A real elapsed interval is necessary: a timer installed before pool
	// admission must expire here. No SQL durability setting is changed.
	hold := time.NewTimer(scheduler.CleanupTimeout + 100*time.Millisecond)
	select {
	case err := <-insertDone:
		hold.Stop()
		t.Fatalf("Insert ended while pool remained owned: %v", err)
	case <-hold.C:
	case <-ctx.Done():
		hold.Stop()
		t.Fatal("fixture deadline while holding pool")
	}
	if len(budgets) != 0 {
		t.Fatal("statement began without acquiring the held connection")
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cancellationAwait(t, insertDone, "accepted reserved Insert after admission"); err != nil {
		t.Fatalf("connection wait consumed statement budget: %v", err)
	}
	joinCtx, cancelJoin := context.WithTimeout(context.Background(), cancellationTestBound)
	defer cancelJoin()
	if err := s.Shutdown(joinCtx); err != nil {
		t.Fatalf("retained admission/finalizers did not join: %v", err)
	}
	if len(budgets) != 3 {
		t.Fatalf("statement attempts after admission=%d want3", len(budgets))
	}
	for range 3 {
		budget := <-budgets
		if !budget.bounded || budget.err != nil || budget.remaining > scheduler.CleanupTimeout || budget.remaining < scheduler.CleanupTimeout-time.Second {
			t.Fatalf("statement did not receive a fresh five-second execution budget: %+v", budget)
		}
	}
	if callbacks.Load() != 1 {
		t.Fatal("callback was replayed while finalizer waited")
	}
	insertAssertRows(t, db, acceptedSpec)
}

type cancelledMarkerConnection struct {
	database.DBTX
	t      *testing.T
	cancel context.CancelCauseFunc
	cause  error
}

func (db *cancelledMarkerConnection) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	if !strings.Contains(query, "-- name: UpdateDebugletStarted") {
		return db.DBTX.QueryRowContext(ctx, query, args...)
	}
	// SQLite may return a successful row after operation cancellation. Forward
	// this actual update under a separately bounded fixture context so its row
	// remains consumable after cancellation; no result row is manufactured.
	sqlCtx, cancelSQL := context.WithTimeout(context.WithoutCancel(ctx), scheduler.CleanupTimeout)
	db.t.Cleanup(cancelSQL)
	row := db.DBTX.QueryRowContext(sqlCtx, query, args...)
	db.cancel(db.cause)
	return row
}

func TestSQLiteCancelledSuccessfulMarkerUsesFailedCallback(t *testing.T) {
	db := newSchedulerTestDB(t)
	s := newTestStorage(t, db, storageTestEligibility)
	cancellationCleanup(t, s)
	gate := newCancellationGate(t)
	ctx, cancel := context.WithCancelCause(context.Background())
	cause := errors.New("cancel before executor callback")
	s.decorate = func(conn database.DBTX) database.DBTX { return &cancelledMarkerConnection{conn, t, cancel, cause} }
	var starts atomic.Int32
	failed := make(chan error, 1)
	s.RegisterOnStart(func(context.Context, scheduler.Spec) scheduler.Completion {
		starts.Add(1)
		return scheduler.Completion{}
	})
	s.RegisterFailed(func(_ context.Context, _ scheduler.Spec, err error) scheduler.Completion {
		failed <- err
		gate.hold(context.Background())
		return scheduler.Completion{}
	})
	spec := insertTestSpec()
	if err := s.Insert(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.StartLoop(ctx) }()
	t.Cleanup(func() {
		cancel(context.Canceled)
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) && !errors.Is(err, scheduler.ErrClosed) {
				t.Errorf("marker fixture dispatcher: %v", err)
			}
		case <-time.After(cancellationTestBound):
			t.Error("marker fixture dispatcher did not join")
		}
	})
	if err := cancellationAwait(t, failed, "FailedFunc after successful cancelled marker"); !errors.Is(err, cause) {
		t.Fatalf("failed callback cause=%v", err)
	}
	queryCtx, cancelQuery := context.WithTimeout(context.Background(), cancellationTestBound)
	defer cancelQuery()
	marker, err := database.New(db).GetDebugletStarted(queryCtx, spec.DebugletID)
	if err != nil || marker.IsZero() {
		t.Fatalf("fixture did not exercise a successful actual marker update: %v %v", marker, err)
	}
	if starts.Load() != 0 {
		t.Fatal("cancelled successful marker entered StartFunc")
	}
	gate.open()
	if err := s.Shutdown(queryCtx); err != nil {
		t.Fatalf("failed callback/finalizer join: %v", err)
	}
	insertAssertRows(t, db)
	if len(failed) != 0 {
		t.Fatal("failure callback repeated")
	}
}
