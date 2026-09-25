package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

func bindingRows(t *testing.T, db *sql.DB) map[uuid.UUID]database.Debuglet {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), cancellationTestBound)
	defer cancel()
	rows, err := database.New(db).ListDebuglets(ctx, database.ListDebugletsParams{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[uuid.UUID]database.Debuglet, len(rows))
	for _, row := range rows {
		result[row.Uuid] = row
	}
	return result
}
func seedBindingRow(t *testing.T, db *sql.DB, binding controlsession.Binding, started bool) scheduler.Spec {
	t.Helper()
	s := insertTestSpec()
	s.DebugletID = uuid.New()
	s.Binding = binding
	ctx, cancel := context.WithTimeout(context.Background(), cancellationTestBound)
	defer cancel()
	q := database.New(db)
	if err := q.CreateDebuglet(ctx, insertTestParams(s)); err != nil {
		t.Fatal(err)
	}
	if started {
		if _, err := q.UpdateDebugletStarted(ctx, database.UpdateDebugletStartedParams{Uuid: s.DebugletID, StartedAt: database.NewUTCTime(time.Now().UTC())}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestSQLiteBindingQuarantinePreservesRows(t *testing.T) {
	db := newSchedulerTestDB(t)
	bound := storageTestBinding()
	foreignSession := bound
	foreignSession.SessionID = uuid.NewString()
	foreignIncarnation := bound
	foreignIncarnation.Incarnation = uuid.NewString()
	for _, row := range []struct {
		binding controlsession.Binding
		started bool
	}{
		{controlsession.Binding{}, false}, {controlsession.Binding{}, true}, {controlsession.Binding{Incarnation: bound.Incarnation}, false}, {foreignSession, true}, {foreignIncarnation, false},
	} {
		seedBindingRow(t, db, row.binding, row.started)
	}
	accepted := seedBindingRow(t, db, bound, false)
	before := bindingRows(t, db)
	delete(before, accepted.DebugletID)
	s := newTestStorage(t, db, storageTestEligibility)
	cancellationCleanup(t, s)
	started := make(chan scheduler.Spec, 1)
	var unexpected atomic.Int32
	s.RegisterOnStart(func(_ context.Context, spec scheduler.Spec) scheduler.Completion {
		if spec.DebugletID != accepted.DebugletID {
			unexpected.Add(1)
		} else {
			started <- spec
		}
		return scheduler.Completion{}
	})
	s.RegisterFailed(func(context.Context, scheduler.Spec, error) scheduler.Completion {
		unexpected.Add(1)
		return scheduler.Completion{}
	})
	ctx, cancel := context.WithTimeout(context.Background(), cancellationTestBound)
	defer cancel()
	if err := s.RestoreFromDatabase(ctx); err != nil {
		t.Fatal(err)
	}
	if s.QuarantinedCount() != 5 {
		t.Fatalf("quarantined=%d want5", s.QuarantinedCount())
	}
	cancellationLoop(t, s)
	got := cancellationAwait(t, started, "eligible restored callback")
	if !reflect.DeepEqual(got, accepted) {
		t.Fatalf("restored binding/spec/WASM mismatch: got%#v want%#v", got, accepted)
	}
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if unexpected.Load() != 0 {
		t.Fatalf("quarantined work reached start/failed callback %d times", unexpected.Load())
	}
	if after := bindingRows(t, db); !reflect.DeepEqual(after, before) {
		t.Fatalf("quarantine changed retained rows/started markers/WASM: got%#v want%#v", after, before)
	}
}

func TestSQLiteBindingQuarantineRequiresValidBindingAndExplicitPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		binding controlsession.Binding
		policy  scheduler.RestoreEligibility
	}{
		{"legacy_even_if_policy_accepts", controlsession.Binding{}, func(controlsession.Binding) bool { return true }},
		{"malformed_even_if_policy_accepts", controlsession.Binding{Incarnation: storageTestBinding().Incarnation, SessionID: "invalid"}, func(controlsession.Binding) bool { return true }},
		{"valid_with_nil_policy", storageTestBinding(), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newSchedulerTestDB(t)
			row := seedBindingRow(t, db, tc.binding, true)
			before := bindingRows(t, db)
			s := newTestStorage(t, db, tc.policy)
			cancellationCleanup(t, s)
			ctx, cancel := context.WithTimeout(context.Background(), cancellationTestBound)
			defer cancel()
			for attempt := 0; attempt < 2; attempt++ {
				if err := s.RestoreFromDatabase(ctx); err != nil {
					t.Fatal(err)
				}
				if s.QuarantinedCount() != 1 {
					t.Fatalf("latest restore count=%d want1", s.QuarantinedCount())
				}
			}
			// The unbound local operation is used only to observe queue absence. If a
			// broken restore emitted it, this assertion fails even though cleanup deletes it.
			if found, err := s.local.Remove(ctx, row.DebugletID); found || err != nil {
				t.Fatalf("quarantined row entered local queue: %t/%v", found, err)
			}
			if !reflect.DeepEqual(bindingRows(t, db), before) {
				t.Fatal("quarantine modified its canonical row")
			}
		})
	}
}

func TestSQLiteCancelBoundClassifiesQuarantineWithoutDeleting(t *testing.T) {
	db := newSchedulerTestDB(t)
	binding := storageTestBinding()
	foreign := binding
	foreign.SessionID = uuid.NewString()
	same := seedBindingRow(t, db, binding, true)
	legacy := seedBindingRow(t, db, controlsession.Binding{}, false)
	other := seedBindingRow(t, db, foreign, true)
	before := bindingRows(t, db)
	s := newTestStorage(t, db, nil)
	cancellationCleanup(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), cancellationTestBound)
	defer cancel()
	for _, tc := range []struct {
		id       uuid.UUID
		mismatch bool
	}{{same.DebugletID, false}, {legacy.DebugletID, true}, {other.DebugletID, true}, {uuid.New(), false}} {
		found, err := s.CancelBound(ctx, tc.id, binding, nil)
		if found || errors.Is(err, scheduler.ErrBindingMismatch) != tc.mismatch || (!tc.mismatch && err != nil) {
			t.Fatalf("quarantined/absent classification: found=%t error=%v mismatch=%t", found, err, tc.mismatch)
		}
	}
	if !reflect.DeepEqual(bindingRows(t, db), before) {
		t.Fatal("bound absent-owner inspection deleted/modified canonical rows")
	}
}

type bindingInspectConnection struct {
	database.DBTX
	gate   *cancellationGate
	joined chan struct{}
	calls  *atomic.Int32
}

func (c *bindingInspectConnection) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	if strings.Contains(query, "-- name: GetDebugletByUUID ") {
		c.calls.Add(1)
		defer close(c.joined)
		c.gate.once.Do(func() { close(c.gate.entered) })
		<-c.gate.release // Model a real driver call whose actual return is still held.
	}
	return c.DBTX.QueryRowContext(ctx, query, args...)
}
func TestSQLiteCancelBoundInspectorIsJoined(t *testing.T) {
	db := newSchedulerTestDB(t)
	row := seedBindingRow(t, db, controlsession.Binding{}, true)
	before := bindingRows(t, db)
	s := newTestStorage(t, db, nil)
	cancellationCleanup(t, s)
	gate := newCancellationGate(t)
	queryJoined := make(chan struct{})
	var calls atomic.Int32
	s.decorate = func(conn database.DBTX) database.DBTX {
		return &bindingInspectConnection{conn, gate, queryJoined, &calls}
	}
	ctx, cancel := context.WithTimeout(context.Background(), cancellationTestBound)
	defer cancel()
	inspected := cancellationCaller(t, gate.open, func() cancellationResult {
		f, e := s.CancelBound(ctx, row.DebugletID, storageTestBinding(), nil)
		return cancellationResult{f, e}
	})
	cancellationAwait(t, gate.entered, "actual owned SQLite inspection")
	short, end := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err := s.Shutdown(short)
	end()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown did not join admitted row inspection: %v", err)
	}
	gate.open()
	result := cancellationAwait(t, inspected, "inspector caller")
	cancellationAwait(t, queryJoined, "actual query return")
	if result.found || !errors.Is(result.err, scheduler.ErrBindingMismatch) || calls.Load() != 1 {
		t.Fatalf("inspection=%+v calls=%d", result, calls.Load())
	}
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bindingRows(t, db), before) {
		t.Fatal("inspection changed quarantined row")
	}
}
