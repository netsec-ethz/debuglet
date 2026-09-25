package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

func TestSQLiteInsertAcceptance(t *testing.T) {
	t.Run("pre_cancelled", func(t *testing.T) {
		db := newSchedulerTestDB(t)
		storage := newTestStorage(t, db, storageTestEligibility)
		observedDB := &insertObservedDB{}
		storage.decorate = observedDB.decorate
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		spec := insertTestSpec()
		if err := storage.Insert(ctx, spec); !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-cancelled insert: %v", err)
		}
		if calls := observedDB.calls.Load(); calls != 0 {
			t.Fatalf("pre-cancelled insert attempted %d database writes", calls)
		}
		insertAssertRows(t, db)
		insertAssertNotQueued(t, storage, spec.DebugletID)
	})

	t.Run("cancelled_after_persistence", func(t *testing.T) {
		db := newSchedulerTestDB(t)
		storage := newTestStorage(t, db, storageTestEligibility)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		observedDB := &insertObservedDB{afterSuccess: cancel}
		storage.decorate = observedDB.decorate
		spec := insertTestSpec()
		if err := storage.Insert(ctx, spec); err != nil {
			t.Fatalf("successful persistence must remain accepted after cancellation: %v", err)
		}
		if calls := observedDB.calls.Load(); calls != 1 || !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("post-write cancellation was not exercised: writes=%d context=%v", calls, ctx.Err())
		}
		insertAssertRows(t, db, spec)
		insertRunAccepted(t, storage, spec)
		// insertRunAccepted joins actual s.onStart, and the shared finalizer,
		// before the database is inspected or closed by the shared fixture.
		insertAssertRows(t, db)
	})

	t.Run("database_constraint_failure", func(t *testing.T) {
		db := newSchedulerTestDB(t)
		storage := newTestStorage(t, db, storageTestEligibility)
		original := insertTestSpec()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		// Seed through the generated query only, leaving the memory queue empty.
		// Reusing this UUID must fail the real schema's unique constraint.
		if err := database.New(db).CreateDebuglet(ctx, insertTestParams(original)); err != nil {
			t.Fatal(err)
		}
		observedDB := &insertObservedDB{}
		storage.decorate = observedDB.decorate
		replacement := original
		replacement.Args = []string{"must not replace the persisted job"}
		replacement.Wasm = []byte("different bytes")
		if err := storage.Insert(ctx, replacement); err == nil {
			t.Fatal("duplicate UUID passed the real SQLite constraint")
		} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("database constraint was obscured by context expiry: %v", err)
		}
		if calls := observedDB.calls.Load(); calls != 1 {
			t.Fatalf("expected one actual failed write, got %d", calls)
		}
		insertAssertRows(t, db, original)
		insertAssertNotQueued(t, storage, original.DebugletID)
	})
}

// Forward every query to the real database. Cancellation happens only after
// SQLite has completed a successful write, before CreateDebuglet returns to
// the storage implementation. No SQL outcome or scheduler is simulated.
type insertObservedDB struct {
	calls        atomic.Int32
	afterSuccess func()
	successOnce  sync.Once
}

type insertConnection struct {
	database.DBTX
	*insertObservedDB
}

func (db *insertObservedDB) decorate(conn database.DBTX) database.DBTX {
	return &insertConnection{conn, db}
}
func (db *insertConnection) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	db.calls.Add(1)
	result, err := db.DBTX.ExecContext(ctx, query, args...)
	if err == nil && db.afterSuccess != nil {
		db.successOnce.Do(db.afterSuccess)
	}
	return result, err
}

func insertTestSpec() scheduler.Spec {
	start := time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC)
	return scheduler.Spec{
		Binding:       storageTestBinding(),
		DebugletID:    uuid.MustParse("7a100001-1234-4234-8234-123456789abc"),
		StartTime:     &start,
		Args:          []string{"first,second", "", "naïve\nvalue"},
		Wasm:          []byte{0, 'a', 's', 'm', 1, 0, 0, 0, 255, 0},
		TransactionID: "opaque/transaction,7a1",
		Policy: scheduler.Policy{
			FloorBW: 7, CeilBW: 99, Timeout: 1500 * time.Millisecond,
			Addresses:   []string{"127.0.0.1:7", "[::1]:8", "comma,value"},
			RequireICMP: true, ListenUDP: true, ListenTCP: false, ListenSCION: true,
		},
	}
}

func insertTestParams(spec scheduler.Spec) database.CreateDebugletParams {
	return database.CreateDebugletParams{
		DispatcherIncarnation: spec.Binding.Incarnation, SessionID: spec.Binding.SessionID,
		Uuid: spec.DebugletID, StartTime: database.NewUTCTime(*spec.StartTime),
		Args: spec.Args, Wasm: spec.Wasm, TransactionID: spec.TransactionID,
		FloorBw: spec.Policy.FloorBW, CeilBw: spec.Policy.CeilBW, TimeoutMs: spec.Policy.Timeout.Milliseconds(),
		Addresses: spec.Policy.Addresses, RequireIcmp: spec.Policy.RequireICMP,
		ListenUdp: spec.Policy.ListenUDP, ListenTcp: spec.Policy.ListenTCP, ListenScion: spec.Policy.ListenSCION,
	}
}

func insertAssertRows(t *testing.T, db *sql.DB, expected ...scheduler.Spec) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rows, err := database.New(db).ListDebuglets(ctx, database.ListDebugletsParams{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(expected) {
		t.Fatalf("persisted row count: got %d, want %d", len(rows), len(expected))
	}
	for i, spec := range expected {
		want := database.Debuglet{
			ID: rows[i].ID, DispatcherIncarnation: spec.Binding.Incarnation, SessionID: spec.Binding.SessionID,
			Uuid: spec.DebugletID, StartTime: database.NewUTCTime(*spec.StartTime),
			Args: spec.Args, Wasm: spec.Wasm, TransactionID: spec.TransactionID,
			FloorBw: spec.Policy.FloorBW, CeilBw: spec.Policy.CeilBW, TimeoutMs: spec.Policy.Timeout.Milliseconds(),
			Addresses: spec.Policy.Addresses, RequireIcmp: spec.Policy.RequireICMP,
			ListenUdp: spec.Policy.ListenUDP, ListenTcp: spec.Policy.ListenTCP, ListenScion: spec.Policy.ListenSCION,
		}
		if rows[i].ID <= 0 || !reflect.DeepEqual(rows[i], want) {
			t.Fatalf("persisted row mismatch:\n got: %#v\nwant: %#v", rows[i], want)
		}
	}
}

func insertAssertNotQueued(t *testing.T, storage *SqliteStorage, id uuid.UUID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// No loop has started, so Remove can directly observe queued acceptance.
	// Use the memory operation to avoid deleting the row under examination.
	if removed, err := storage.local.Remove(ctx, id); err != nil || removed {
		t.Fatalf("rejected insertion left queued work: removed=%t err=%v", removed, err)
	}
}

func insertRunAccepted(t *testing.T, storage *SqliteStorage, expected scheduler.Spec) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var mu sync.Mutex
	accepting, active, calls := true, 0, 0
	var observed []scheduler.Spec
	var callbackErrors []error
	completed, joined := make(chan struct{}), make(chan struct{})
	var completedOnce sync.Once
	storage.RegisterOnStart(func(ctx context.Context, spec scheduler.Spec) scheduler.Completion {
		mu.Lock()
		defer mu.Unlock()
		observed = append(observed, spec)
		if err := ctx.Err(); err != nil {
			callbackErrors = append(callbackErrors, err)
		}
		return scheduler.Completion{}
	})
	storage.RegisterFailed(func(_ context.Context, _ scheduler.Spec, err error) scheduler.Completion {
		mu.Lock()
		defer mu.Unlock()
		callbackErrors = append(callbackErrors, err)
		return scheduler.Completion{}
	})
	storage.local.RegisterOnStart(func(ctx context.Context, spec scheduler.Spec) scheduler.Completion {
		mu.Lock()
		if !accepting {
			mu.Unlock()
			t.Error("callback admitted after scheduler shutdown")
			return scheduler.Completion{CleanupErr: errors.New("callback admitted after scheduler shutdown")}
		}
		active++
		calls++
		mu.Unlock()
		defer func() {
			mu.Lock()
			active--
			if !accepting && active == 0 {
				close(joined)
			}
			mu.Unlock()
			completedOnce.Do(func() { close(completed) })
		}()
		return storage.onStart(ctx, spec)
	})
	loopDone := make(chan error, 1)
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			select {
			case err := <-loopDone:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("scheduler loop shutdown: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Error("scheduler loop did not join")
			}
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), scheduler.CleanupTimeout)
			if err := storage.Shutdown(shutdownCtx); err != nil {
				t.Errorf("owned SQLite shutdown: %v", err)
			}
			shutdownCancel()
			mu.Lock()
			accepting = false
			if active == 0 {
				close(joined)
			}
			mu.Unlock()
			select {
			case <-joined:
			case <-time.After(2 * time.Second):
				t.Error("actual SQLite callbacks did not join")
			}
		})
	}
	t.Cleanup(stop)
	go func() { loopDone <- storage.StartLoop(ctx) }()
	select {
	case <-completed:
	case <-time.After(2 * time.Second):
		t.Fatal("accepted persisted job did not complete its actual SQLite callback")
	}
	stop()
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 || len(observed) != 1 || len(callbackErrors) != 0 {
		t.Fatalf("accepted callback counts: entered=%d successful=%d errors=%v", calls, len(observed), callbackErrors)
	}
	if !reflect.DeepEqual(observed[0], expected) {
		t.Fatalf("accepted callback lost stored spec or WASM:\n got: %#v\nwant: %#v", observed[0], expected)
	}
}

func storageTestBinding() controlsession.Binding {
	return controlsession.Binding{Incarnation: "c31f0dc2-3f96-4a5a-aa2a-a4bcc16d88fb", SessionID: "6f2f15d8-f982-44a8-b22c-8d80fa5f8b62"}
}
func storageTestEligibility(binding controlsession.Binding) bool {
	return binding == storageTestBinding()
}
