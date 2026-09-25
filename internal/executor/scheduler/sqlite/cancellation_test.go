package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

const cancellationTestBound = 3 * time.Second

type cancellationResult struct {
	found bool
	err   error
}

// These gates surround actual generated SQL, never synthesize a SQL result.
// A post-write gate deliberately ignores caller cancellation: SQLite has already
// committed, and the storage must report that acceptance when Exec returns.
type cancellationDB struct {
	creates, deletes, lists atomic.Int32
	afterCreate             func(database.DBTX, error)
	beforeDelete            func(context.Context)
	beforeList              func(context.Context)
}

type cancellationConnection struct {
	database.DBTX
	*cancellationDB
}

func (db *cancellationDB) decorate(conn database.DBTX) database.DBTX {
	return &cancellationConnection{conn, db}
}
func (db *cancellationConnection) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	create := strings.Contains(query, "-- name: CreateDebuglet")
	if create {
		db.creates.Add(1)
	}
	if strings.Contains(query, "-- name: DeleteDebuglet") {
		db.deletes.Add(1)
		if db.beforeDelete != nil {
			db.beforeDelete(ctx)
		}
	}
	result, err := db.DBTX.ExecContext(ctx, query, args...)
	if create && db.afterCreate != nil {
		db.afterCreate(db.DBTX, err)
	}
	return result, err
}

func (db *cancellationConnection) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	if strings.Contains(query, "-- name: ListDebuglets") {
		db.lists.Add(1)
		if db.beforeList != nil {
			db.beforeList(ctx)
		}
	}
	return db.DBTX.QueryContext(ctx, query, args...)
}

type cancellationGate struct {
	entered, release chan struct{}
	once, closeOnce  sync.Once
}

func newCancellationGate(t *testing.T) *cancellationGate {
	g := &cancellationGate{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(g.open)
	return g
}
func (g *cancellationGate) open() { g.closeOnce.Do(func() { close(g.release) }) }
func (g *cancellationGate) hold(ctx context.Context) {
	g.once.Do(func() { close(g.entered) })
	select {
	case <-g.release:
	case <-ctx.Done():
	}
}

// Done is reached only after Cancel has elected/joined its attempt under the
// ownership guard. This synchronizes duplicate callers without timing guesses.
type cancellationWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *cancellationWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}
func cancellationAwait[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(cancellationTestBound):
		t.Fatalf("timed out waiting for %s", what)
	}
	var zero T
	return zero
}
func cancellationStillWaiting[T any](t *testing.T, ch <-chan T, what string) {
	t.Helper()
	select {
	case value := <-ch:
		t.Fatalf("%s completed before its owned gate joined: %v", what, value)
	default:
	}
}

// The result and caller-join channels are separate, so an assertion may consume
// the result while cleanup still joins the sending goroutine exactly once.
func cancellationCaller[T any](t *testing.T, release func(), call func() T) <-chan T {
	t.Helper()
	result, joined := make(chan T, 1), make(chan struct{})
	go func() { defer close(joined); result <- call() }()
	t.Cleanup(func() {
		release()
		select {
		case <-joined:
		case <-time.After(scheduler.CleanupTimeout + time.Second):
			t.Error("fixture caller did not join after releasing its owned gate/context")
		}
	})
	return result
}

func cancellationCall(t *testing.T, s *SqliteStorage, id uuid.UUID, cause error, timeout time.Duration) (<-chan cancellationResult, <-chan struct{}) {
	t.Helper()
	base, cancel := context.WithTimeout(context.Background(), timeout)
	ctx := &cancellationWaitContext{Context: base, waiting: make(chan struct{})}
	done := cancellationCaller(t, cancel, func() cancellationResult {
		found, err := s.Cancel(ctx, id, cause)
		return cancellationResult{found, err}
	})
	return done, ctx.waiting
}
func cancellationShutdown(t *testing.T, s *SqliteStorage) <-chan error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), cancellationTestBound)
	done := cancellationCaller(t, cancel, func() error { return s.Shutdown(ctx) })
	return done
}
func cancellationClosed(t *testing.T, s *SqliteStorage) {
	t.Helper()
	deadline := time.NewTimer(cancellationTestBound)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		// Unknown Cancel is read-only before closing and ErrClosed afterward.
		_, err := s.Cancel(context.Background(), uuid.Nil, nil)
		if errors.Is(err, scheduler.ErrClosed) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("Shutdown never closed admission")
		}
	}
}
func cancellationCleanup(t *testing.T, s *SqliteStorage) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), scheduler.CleanupTimeout)
		defer cancel()
		// Stored fixture errors are expected in failure cases. An expired join
		// would permit database teardown beneath owned operations and is a failure.
		if err := s.Shutdown(ctx); errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			t.Errorf("scheduler cleanup did not join: %v", err)
		}
	})
}
func cancellationLoop(t *testing.T, s *SqliteStorage) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.StartLoop(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) && !errors.Is(err, scheduler.ErrClosed) {
				t.Errorf("loop stopped: %v", err)
			}
		case <-time.After(cancellationTestBound):
			t.Error("loop did not join")
		}
	})
	return done
}
func cancellationRejectDeletes(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), cancellationTestBound)
	defer cancel()
	if _, err := db.ExecContext(ctx, "CREATE TRIGGER reject_delete BEFORE DELETE ON debuglets BEGIN SELECT RAISE(FAIL, 'owned deletion fixture'); END"); err != nil {
		t.Fatal(err)
	}
}
func cancellationAllowDeletes(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), cancellationTestBound)
	defer cancel()
	if _, err := db.ExecContext(ctx, "DROP TRIGGER reject_delete"); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteReservedInsertAndShutdown(t *testing.T) {
	db := newSchedulerTestDB(t)
	s := newTestStorage(t, db, storageTestEligibility)
	cancellationCleanup(t, s)
	gate := newCancellationGate(t)
	written := make(chan error, 1)
	observed := &cancellationDB{afterCreate: func(conn database.DBTX, err error) {
		if err != nil {
			written <- err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), cancellationTestBound)
		defer cancel()
		var rows int
		err = conn.QueryRowContext(ctx, "SELECT count(*) FROM debuglets").Scan(&rows)
		if err == nil && rows != 1 {
			err = errors.New("committed row not visible on owned connection")
		}
		written <- err
		gate.hold(ctx)
	}}
	s.decorate = observed.decorate
	spec := insertTestSpec()
	insertDone := cancellationCaller(t, gate.open, func() error { return s.Insert(context.Background(), spec) })
	cancellationAwait(t, gate.entered, "committed SQLite write")
	if err := cancellationAwait(t, written, "committed row observation"); err != nil {
		t.Fatal(err)
	}
	shutdown := cancellationShutdown(t, s)
	cancellationClosed(t, s)
	cancellationStillWaiting(t, shutdown, "Shutdown during reserved Insert")
	other := spec
	other.DebugletID = uuid.New()
	if err := s.Insert(context.Background(), other); !errors.Is(err, scheduler.ErrClosed) {
		t.Fatalf("new Insert after closing: %v", err)
	}
	if observed.creates.Load() != 1 {
		t.Fatal("closed insertion reached SQL")
	}
	gate.open()
	if err := cancellationAwait(t, insertDone, "accepted Insert"); err != nil {
		t.Fatalf("committed Insert lost acceptance: %v", err)
	}
	if err := cancellationAwait(t, shutdown, "reserved admission join"); err != nil {
		t.Fatal(err)
	}
	insertAssertRows(t, db, spec)
	if found, err := s.Cancel(context.Background(), spec.DebugletID, nil); found || !errors.Is(err, scheduler.ErrClosed) {
		t.Fatalf("new cancellation after shutdown: %t %v", found, err)
	}
	if found, err := s.Remove(context.Background(), spec.DebugletID); found || !errors.Is(err, scheduler.ErrClosed) {
		t.Fatalf("new removal after shutdown: %t %v", found, err)
	}
	if observed.deletes.Load() != 0 {
		t.Fatal("SQL deletion began after successful Shutdown")
	}
	// A new scheduler over the same canonical DB proves the accepted row is
	// recoverable; the closed incarnation cannot dispatch it.
	restarted := newTestStorage(t, db, storageTestEligibility)
	if err := restarted.RestoreFromDatabase(context.Background()); err != nil {
		t.Fatal(err)
	}
	insertRunAccepted(t, restarted, spec)
	insertAssertRows(t, db)
}

func TestSQLiteCancellationDuringPersistence(t *testing.T) {
	for _, failCreate := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "constraint_failure"}[failCreate], func(t *testing.T) {
			db := newSchedulerTestDB(t)
			s := newTestStorage(t, db, storageTestEligibility)
			cancellationCleanup(t, s)
			spec := insertTestSpec()
			if failCreate {
				if err := database.New(db).CreateDebuglet(context.Background(), insertTestParams(spec)); err != nil {
					t.Fatal(err)
				}
			}
			gate := newCancellationGate(t)
			observed := &cancellationDB{afterCreate: func(database.DBTX, error) {
				ctx, cancel := context.WithTimeout(context.Background(), cancellationTestBound)
				defer cancel()
				gate.hold(ctx)
			}}
			s.decorate = observed.decorate
			insertDone := cancellationCaller(t, gate.open, func() error { return s.Insert(context.Background(), spec) })
			cancellationAwait(t, gate.entered, "actual Create result before return")
			first, waiting := cancellationCall(t, s, spec.DebugletID, errors.New("first admitted cancellation"), 50*time.Millisecond)
			cancellationAwait(t, waiting, "pending cancellation admitted")
			if result := cancellationAwait(t, first, "caller deadline"); !result.found || !errors.Is(result.err, context.DeadlineExceeded) {
				t.Fatalf("pending wait result: %+v", result)
			}
			second, joined := cancellationCall(t, s, spec.DebugletID, nil, cancellationTestBound)
			cancellationAwait(t, joined, "second caller joining pending cancellation")
			shutdown := cancellationShutdown(t, s)
			cancellationClosed(t, s)
			gate.open()
			insertErr := cancellationAwait(t, insertDone, "Create return")
			result := cancellationAwait(t, second, "admitted cancellation after persistence")
			if err := cancellationAwait(t, shutdown, "pending cancellation shutdown join"); err != nil {
				t.Fatal(err)
			}
			if failCreate {
				if insertErr == nil || result.found || result.err != nil || observed.deletes.Load() != 0 {
					t.Fatalf("failed Create must not delete existing row: insert=%v cancel=%+v deletes=%d", insertErr, result, observed.deletes.Load())
				}
				insertAssertRows(t, db, spec)
			} else {
				if insertErr != nil || !result.found || result.err != nil || observed.deletes.Load() != 1 {
					t.Fatalf("accepted cancellation not committed: insert=%v cancel=%+v deletes=%d", insertErr, result, observed.deletes.Load())
				}
				insertAssertRows(t, db)
			}
		})
	}
}

func TestSQLiteQueuedDeletionFailureRestoresWork(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "Cancel", true: "Remove"}[remove], func(t *testing.T) {
			db := newSchedulerTestDB(t)
			s := newTestStorage(t, db, storageTestEligibility)
			cancellationCleanup(t, s)
			observed := &cancellationDB{}
			s.decorate = observed.decorate
			spec := insertTestSpec()
			if err := s.Insert(context.Background(), spec); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if found, err := s.Cancel(ctx, spec.DebugletID, nil); found || !errors.Is(err, context.Canceled) {
				t.Fatalf("pre-cancelled request: %t %v", found, err)
			}
			if observed.deletes.Load() != 0 {
				t.Fatal("pre-cancelled request deleted")
			}
			cancellationRejectDeletes(t, db)
			var found bool
			var err error
			if remove {
				found, err = s.Remove(context.Background(), spec.DebugletID)
			} else {
				found, err = s.Cancel(context.Background(), spec.DebugletID, errors.New("provisional cause"))
			}
			if !found || err == nil {
				t.Fatalf("actual SQLite delete failure acknowledged: %t %v", found, err)
			}
			if observed.deletes.Load() != 1 {
				t.Fatal("queued deletion retried implicitly")
			}
			insertAssertRows(t, db, spec)
			cancellationAllowDeletes(t, db)
			// The original full spec, due time and WASM must execute once under a
			// fresh, uncancelled context; a failed provisional cause cannot poison it.
			insertRunAccepted(t, s, spec)
			insertAssertRows(t, db)
			if observed.deletes.Load() != 2 {
				t.Fatalf("expected one failed cancellation and one callback finalizer; got %d", observed.deletes.Load())
			}
		})
	}
}

func TestSQLitePendingDeletionPreventsDispatch(t *testing.T) {
	db := newSchedulerTestDB(t)
	s := newTestStorage(t, db, storageTestEligibility)
	cancellationCleanup(t, s)
	gate := newCancellationGate(t)
	observed := &cancellationDB{beforeDelete: gate.hold}
	s.decorate = observed.decorate
	spec := insertTestSpec()
	if err := s.Insert(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	first, _ := cancellationCall(t, s, spec.DebugletID, nil, cancellationTestBound)
	cancellationAwait(t, gate.entered, "reserved queued deletion")
	var callbacks atomic.Int32
	s.RegisterOnStart(func(context.Context, scheduler.Spec) scheduler.Completion {
		callbacks.Add(1)
		return scheduler.Completion{}
	})
	cancellationLoop(t, s)
	second, waiting := cancellationCall(t, s, spec.DebugletID, nil, cancellationTestBound)
	cancellationAwait(t, waiting, "duplicate queued cancellation")
	shutdown := cancellationShutdown(t, s)
	cancellationClosed(t, s)
	cancellationStillWaiting(t, first, "queued deletion")
	cancellationStillWaiting(t, shutdown, "queued deletion shutdown")
	gate.open()
	for _, done := range []<-chan cancellationResult{first, second} {
		if result := cancellationAwait(t, done, "queued cancellation"); !result.found || result.err != nil {
			t.Fatalf("queued cancellation: %+v", result)
		}
	}
	if err := cancellationAwait(t, shutdown, "queued deletion join"); err != nil {
		t.Fatal(err)
	}
	if callbacks.Load() != 0 || observed.deletes.Load() != 1 {
		t.Fatalf("pending deletion dispatched or duplicated: callbacks=%d deletes=%d", callbacks.Load(), observed.deletes.Load())
	}
	insertAssertRows(t, db)
}

func TestSQLiteActiveCancellationJoinsCallback(t *testing.T) {
	db := newSchedulerTestDB(t)
	s := newTestStorage(t, db, storageTestEligibility)
	cancellationCleanup(t, s)
	gate := newCancellationGate(t)
	started := make(chan scheduler.Spec, 1)
	cancelled := make(chan error, 1)
	var calls atomic.Int32
	s.RegisterOnStart(func(ctx context.Context, spec scheduler.Spec) scheduler.Completion {
		calls.Add(1)
		started <- spec
		<-ctx.Done()
		cancelled <- context.Cause(ctx)
		gate.hold(context.Background())
		return scheduler.Completion{}
	})
	spec := insertTestSpec()
	if err := s.Insert(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	cancellationLoop(t, s)
	if got := cancellationAwait(t, started, "actual SQLite-started callback"); !reflect.DeepEqual(got, spec) {
		t.Fatal("started callback lost spec")
	}
	marker, err := database.New(db).GetDebugletStarted(context.Background(), spec.DebugletID)
	if err != nil || marker.IsZero() {
		t.Fatalf("callback preceded actual started marker: %v %v", marker, err)
	}
	if found, err := s.Remove(context.Background(), spec.DebugletID); found || err == nil {
		t.Fatalf("Remove deleted active work: %t %v", found, err)
	}
	cause := errors.New("operator cancellation")
	first, _ := cancellationCall(t, s, spec.DebugletID, cause, 50*time.Millisecond)
	if got := cancellationAwait(t, cancelled, "signal before callback join"); !errors.Is(got, cause) {
		t.Fatalf("cause=%v", got)
	}
	if result := cancellationAwait(t, first, "bounded active cancellation wait"); !result.found || !errors.Is(result.err, context.DeadlineExceeded) {
		t.Fatalf("active wait: %+v", result)
	}
	second, waiting := cancellationCall(t, s, spec.DebugletID, errors.New("must not replace cause"), cancellationTestBound)
	cancellationAwait(t, waiting, "second active cancellation")
	shutdown := cancellationShutdown(t, s)
	cancellationClosed(t, s)
	cancellationStillWaiting(t, second, "active callback")
	cancellationStillWaiting(t, shutdown, "active callback Shutdown")
	gate.open()
	if result := cancellationAwait(t, second, "joined active cancellation"); !result.found || result.err != nil {
		t.Fatalf("active cancellation: %+v", result)
	}
	if err := cancellationAwait(t, shutdown, "active shutdown"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("callback repeated")
	}
	insertAssertRows(t, db)
}

func TestSQLiteFinalizationRetryOnly(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "database_retry", true: "immutable_cleanup_error"}[cleanupFails], func(t *testing.T) {
			db := newSchedulerTestDB(t)
			s := newTestStorage(t, db, storageTestEligibility)
			cancellationCleanup(t, s)
			gate := newCancellationGate(t)
			observed := &cancellationDB{beforeDelete: gate.hold}
			s.decorate = observed.decorate
			cancellationRejectDeletes(t, db)
			cleanupErr := errors.New("resource close fixture")
			var calls atomic.Int32
			s.RegisterOnStart(func(context.Context, scheduler.Spec) scheduler.Completion {
				calls.Add(1)
				if cleanupFails {
					return scheduler.Completion{CleanupErr: cleanupErr}
				}
				return scheduler.Completion{}
			})
			spec := insertTestSpec()
			if err := s.Insert(context.Background(), spec); err != nil {
				t.Fatal(err)
			}
			cancellationLoop(t, s)
			cancellationAwait(t, gate.entered, "callback completed and finalizer entered")
			first, waiting := cancellationCall(t, s, spec.DebugletID, nil, cancellationTestBound)
			cancellationAwait(t, waiting, "first finalizer join")
			second, waiting2 := cancellationCall(t, s, spec.DebugletID, nil, cancellationTestBound)
			cancellationAwait(t, waiting2, "duplicate finalizer join")
			gate.open()
			one := cancellationAwait(t, first, "failed finalizer")
			two := cancellationAwait(t, second, "same failed finalizer")
			if !one.found || one.err == nil || !two.found || two.err != one.err {
				t.Fatalf("waiters did not share immutable attempt: %+v %+v", one, two)
			}
			if cleanupFails && !errors.Is(one.err, cleanupErr) {
				t.Fatal("callback cleanup result lost")
			}
			if calls.Load() != 1 || observed.deletes.Load() != 1 {
				t.Fatal("failed attempt reran callback or retried")
			}
			marker, err := database.New(db).GetDebugletStarted(context.Background(), spec.DebugletID)
			if err != nil || marker.IsZero() {
				t.Fatalf("failed finalization lost restorable started row: %v", err)
			}
			cancellationAllowDeletes(t, db)
			found, err := s.Cancel(context.Background(), spec.DebugletID, nil)
			if !found || cleanupFails && !errors.Is(err, cleanupErr) || !cleanupFails && err != nil {
				t.Fatalf("DB-only retry: %t %v", found, err)
			}
			if calls.Load() != 1 || observed.deletes.Load() != 2 {
				t.Fatalf("DB retry effects: callbacks=%d deletes=%d", calls.Load(), observed.deletes.Load())
			}
			insertAssertRows(t, db)
			found, err = s.Cancel(context.Background(), spec.DebugletID, nil)
			if cleanupFails {
				if !found || !errors.Is(err, cleanupErr) {
					t.Fatal("cleanup failure was erased")
				}
			} else if found || err != nil {
				t.Fatalf("retired ID was not absent: %t %v", found, err)
			}
			if observed.deletes.Load() != 2 {
				t.Fatal("no remaining database error, but repeated deletion")
			}
		})
	}
}

func TestSQLiteShutdownBlocksFailedFinalizerRetry(t *testing.T) {
	db := newSchedulerTestDB(t)
	s := newTestStorage(t, db, storageTestEligibility)
	cancellationCleanup(t, s)
	gate := newCancellationGate(t)
	observed := &cancellationDB{beforeDelete: gate.hold}
	s.decorate = observed.decorate
	cancellationRejectDeletes(t, db)
	s.RegisterOnStart(func(context.Context, scheduler.Spec) scheduler.Completion { return scheduler.Completion{} })
	spec := insertTestSpec()
	if err := s.Insert(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	cancellationLoop(t, s)
	cancellationAwait(t, gate.entered, "initial callback finalizer")
	shutdown := cancellationShutdown(t, s)
	cancellationClosed(t, s)
	joined, waiting := cancellationCall(t, s, spec.DebugletID, nil, cancellationTestBound)
	cancellationAwait(t, waiting, "join existing finalizer after closing")
	gate.open()
	if result := cancellationAwait(t, joined, "failed finalizer join"); !result.found || result.err == nil {
		t.Fatalf("failed finalizer: %+v", result)
	}
	if err := cancellationAwait(t, shutdown, "failed Shutdown"); err == nil {
		t.Fatal("Shutdown obscured failed finalization")
	}
	cancellationAllowDeletes(t, db)
	for range 20 {
		if found, err := s.Cancel(context.Background(), spec.DebugletID, nil); found || !errors.Is(err, scheduler.ErrClosed) {
			t.Fatalf("post-close retry: %t %v", found, err)
		}
		if found, err := s.Remove(context.Background(), spec.DebugletID); found || err == nil {
			t.Fatalf("post-close Remove: %t %v", found, err)
		}
	}
	if err := s.Shutdown(context.Background()); err == nil {
		t.Fatal("repeat Shutdown retried or discarded recorded error")
	}
	if observed.deletes.Load() != 1 {
		t.Fatal("database work started after closed owner joined")
	}
	marker, err := database.New(db).GetDebugletStarted(context.Background(), spec.DebugletID)
	if err != nil || marker.IsZero() {
		t.Fatalf("failed finalization row lost: %v", err)
	}
}

func TestSQLiteStartMarkerFailureReportsOnce(t *testing.T) {
	db := newSchedulerTestDB(t)
	s := newTestStorage(t, db, storageTestEligibility)
	cancellationCleanup(t, s)
	if _, err := db.Exec("CREATE TRIGGER reject_started BEFORE UPDATE OF started_at ON debuglets BEGIN SELECT RAISE(FAIL, 'start marker fixture'); END"); err != nil {
		t.Fatal(err)
	}
	failed := make(chan error, 1)
	var calls atomic.Int32
	s.RegisterOnStart(func(context.Context, scheduler.Spec) scheduler.Completion {
		calls.Add(1)
		return scheduler.Completion{}
	})
	s.RegisterFailed(func(_ context.Context, _ scheduler.Spec, err error) scheduler.Completion {
		failed <- err
		return scheduler.Completion{}
	})
	spec := insertTestSpec()
	if err := s.Insert(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	cancellationLoop(t, s)
	if err := cancellationAwait(t, failed, "start failure callback"); err == nil || !strings.Contains(err.Error(), "write debuglet start marker") {
		t.Fatalf("start failure: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cancellationTestBound)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("execution failure became cleanup failure: %v", err)
	}
	if calls.Load() != 0 || len(failed) != 0 {
		t.Fatal("failed start executed or reported twice")
	}
	insertAssertRows(t, db)
}

func TestSQLiteShutdownJoinsRestore(t *testing.T) {
	db := newSchedulerTestDB(t)
	s := newTestStorage(t, db, storageTestEligibility)
	cancellationCleanup(t, s)
	gate := newCancellationGate(t)
	observed := &cancellationDB{beforeList: gate.hold}
	s.decorate = observed.decorate
	ctx, cancel := context.WithTimeout(context.Background(), cancellationTestBound)
	defer cancel()
	restored := cancellationCaller(t, func() { gate.open(); cancel() }, func() error { return s.RestoreFromDatabase(ctx) })
	cancellationAwait(t, gate.entered, "reserved canonical restore query")
	shutdown := cancellationShutdown(t, s)
	cancellationClosed(t, s)
	cancellationStillWaiting(t, shutdown, "Shutdown with admitted restore")
	gate.open()
	if err := cancellationAwait(t, restored, "empty canonical restore"); err != nil {
		t.Fatal(err)
	}
	if err := cancellationAwait(t, shutdown, "restore join"); err != nil {
		t.Fatal(err)
	}
	if err := s.RestoreFromDatabase(context.Background()); !errors.Is(err, scheduler.ErrClosed) {
		t.Fatalf("restore after shutdown: %v", err)
	}
	if observed.lists.Load() != 1 {
		t.Fatalf("SQL after shutdown barrier: queries=%d", observed.lists.Load())
	}
}
