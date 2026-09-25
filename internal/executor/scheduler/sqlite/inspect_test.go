package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

// inspectConnection records every statement an inspection executes, so the
// test can prove what a lookup reads and that it writes nothing at all.
type inspectConnection struct {
	database.DBTX
	queries *[]string
	execs   *[]string
	mu      *sync.Mutex
	hold    func(string)
}

func (db *inspectConnection) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	db.mu.Lock()
	*db.queries = append(*db.queries, query)
	db.mu.Unlock()
	if db.hold != nil {
		db.hold(query)
	}
	return db.DBTX.QueryRowContext(ctx, query, args...)
}
func (db *inspectConnection) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	db.mu.Lock()
	*db.queries = append(*db.queries, query)
	db.mu.Unlock()
	return db.DBTX.QueryContext(ctx, query, args...)
}
func (db *inspectConnection) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	db.mu.Lock()
	*db.execs = append(*db.execs, query)
	db.mu.Unlock()
	return db.DBTX.ExecContext(ctx, query, args...)
}

func inspectRow(t *testing.T, db *sql.DB, id uuid.UUID, binding controlsession.Binding, started bool, start time.Time, transaction string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), retentionTestBound)
	defer cancel()
	queries := database.New(db)
	if err := queries.CreateDebuglet(ctx, database.CreateDebugletParams{
		Uuid: id, DispatcherIncarnation: binding.Incarnation, SessionID: binding.SessionID,
		StartTime: database.NewUTCTime(start), Args: []string{"argument"},
		Wasm: []byte("\x00asm\x01\x00\x00\x00 stored guest program"), TransactionID: transaction,
		FloorBw: 64000, CeilBw: 128000, TimeoutMs: 1000, Addresses: []string{"127.0.0.1"},
	}); err != nil {
		t.Fatal(err)
	}
	if started {
		if _, err := queries.UpdateDebugletStarted(ctx, database.UpdateDebugletStartedParams{
			Uuid: id, StartedAt: database.NewUTCTime(time.Now()),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// Rows owned by the current binding are excluded, everything else that exists
// yields validated metadata, and an identity nothing stored is reported as
// absent rather than as a filtered miss.
func TestInspectRetainedRunClassification(t *testing.T) {
	db := newSchedulerTestDB(t)
	storage := newTestStorage(t, db, storageTestEligibility)
	var mu sync.Mutex
	var queries, execs []string
	storage.decorate = func(conn database.DBTX) database.DBTX {
		return &inspectConnection{DBTX: conn, queries: &queries, execs: &execs, mu: &mu}
	}
	ctx, cancel := context.WithTimeout(context.Background(), retentionTestBound)
	defer cancel()

	current := storageTestBinding()
	old := retentionOtherBinding()
	legacy := controlsession.Binding{}
	due := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	live, unstarted, started, orphan, missing := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	inspectRow(t, db, live, current, false, due, "live")
	inspectRow(t, db, unstarted, old, false, due, "old-unstarted")
	inspectRow(t, db, started, old, true, due, "old-started")
	inspectRow(t, db, orphan, legacy, true, time.Time{}, "legacy")

	for _, tc := range []struct {
		name    string
		id      uuid.UUID
		status  scheduler.RetainedRunStatus
		binding controlsession.Binding
		started bool
	}{
		{"current_binding_is_filtered", live, scheduler.RetainedRunFiltered, controlsession.Binding{}, false},
		{"old_binding_unstarted", unstarted, scheduler.RetainedRunFound, old, false},
		{"old_binding_started", started, scheduler.RetainedRunFound, old, true},
		{"legacy_row", orphan, scheduler.RetainedRunFound, legacy, true},
		{"unknown_identity_is_absent", missing, scheduler.RetainedRunAbsent, controlsession.Binding{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, err := storage.InspectRetainedRun(ctx, tc.id, current)
			if err != nil {
				t.Fatal(err)
			}
			if run.Status != tc.status {
				t.Fatalf("status=%s want=%s", run.Status, tc.status)
			}
			if tc.status != scheduler.RetainedRunFound {
				return
			}
			if run.DebugletID != tc.id || run.Binding != tc.binding || run.Started() != tc.started {
				t.Fatalf("metadata mismatch: %+v", run)
			}
			if tc.started == run.StartedAt.IsZero() {
				t.Fatalf("start marker disagrees with its timestamp: %+v", run)
			}
		})
	}

	mu.Lock()
	defer mu.Unlock()
	for _, query := range queries {
		if strings.Contains(query, "GetDebugletIdentity") && strings.Contains(query, "wasm") {
			t.Fatal("inspection selected the stored guest program")
		}
	}
	for _, statement := range execs {
		if strings.Contains(statement, "DeleteDebuglet") || strings.Contains(statement, "UpdateDebugletStarted") {
			t.Fatalf("inspection wrote to storage: %s", statement)
		}
	}
	remaining, err := database.New(db).ListDebuglets(ctx, database.ListDebugletsParams{Limit: 16})
	if err != nil || len(remaining) != 4 {
		t.Fatalf("inspection changed stored rows: %d error=%v", len(remaining), err)
	}
}

// A reader keeps its connection until the backend actually returns it. The
// caller's cancellation bounds only the caller, and the session that replaces
// this one still finds the row untouched.
func TestInspectRetainedRunHoldsItsReader(t *testing.T) {
	db := newSchedulerTestDB(t)
	storage := newTestStorage(t, db, storageTestEligibility)
	entered, release := make(chan struct{}), make(chan struct{})
	var held atomic.Bool
	var mu sync.Mutex
	var queries, execs []string
	storage.decorate = func(conn database.DBTX) database.DBTX {
		return &inspectConnection{DBTX: conn, queries: &queries, execs: &execs, mu: &mu, hold: func(query string) {
			if strings.Contains(query, "GetDebugletIdentity") && held.CompareAndSwap(false, true) {
				close(entered)
				<-release
			}
		}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), retentionTestBound)
	defer cancel()
	id := uuid.New()
	inspectRow(t, db, id, retentionOtherBinding(), true, time.Time{}, "held")

	lookupCtx, abandon := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, err := storage.InspectRetainedRun(lookupCtx, id, storageTestBinding())
		done <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		close(release)
		t.Fatal("inspection never reached its reader")
	}
	abandon() // The caller gives up; the backend still owns its connection.

	short, end := context.WithTimeout(context.Background(), 250*time.Millisecond)
	err := storage.Shutdown(short)
	end()
	if !errors.Is(err, context.DeadlineExceeded) {
		close(release)
		t.Fatalf("shutdown abandoned a held reader: %v", err)
	}
	close(release)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("held reader never returned")
	}
	if err := storage.Shutdown(ctx); err != nil {
		t.Fatalf("joined shutdown: %v", err)
	}

	// The replacement session reads the same untouched row.
	successor := newTestStorage(t, db, storageTestEligibility)
	run, err := successor.InspectRetainedRun(ctx, id, storageTestBinding())
	if err != nil || run.Status != scheduler.RetainedRunFound || !run.Started() {
		t.Fatalf("replacement session lost the retained row: %+v error=%v", run, err)
	}
	if err := successor.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

// A malformed identity and a closed core are errors, never a successful answer
// that no such row exists.
func TestInspectRetainedRunRejectsMalformedAndClosed(t *testing.T) {
	db := newSchedulerTestDB(t)
	storage := newTestStorage(t, db, storageTestEligibility)
	ctx, cancel := context.WithTimeout(context.Background(), retentionTestBound)
	defer cancel()

	if run, err := storage.InspectRetainedRun(ctx, uuid.Nil, storageTestBinding()); err == nil {
		t.Fatalf("nil identity produced an answer: %+v", run)
	} else if strings.Contains(err.Error(), "absent") {
		t.Fatalf("malformed identity was reported as absent: %v", err)
	}
	if err := storage.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if run, err := storage.InspectRetainedRun(ctx, uuid.New(), storageTestBinding()); !errors.Is(err, scheduler.ErrClosed) {
		t.Fatalf("closed storage answered a lookup: %+v error=%v", run, err)
	}
}
