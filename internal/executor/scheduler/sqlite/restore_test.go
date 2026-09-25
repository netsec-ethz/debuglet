package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

type restoreRow struct {
	spec    scheduler.Spec
	started bool
}

type restoreObservation struct {
	spec scheduler.Spec
	err  error
}

type restoreDeletion struct {
	id  uuid.UUID
	err error
}
type restoreConnection struct {
	database.DBTX
	deleted  chan<- restoreDeletion
	overflow *atomic.Bool
}

func (db *restoreConnection) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	result, err := db.DBTX.ExecContext(ctx, query, args...)
	if strings.Contains(query, "-- name: DeleteDebuglet") {
		id, _ := args[0].(uuid.UUID)
		select {
		case db.deleted <- restoreDeletion{id, err}:
		default:
			db.overflow.Store(true)
		}
	}
	return result, err
}

func TestRestoreBeforeStartLoop(t *testing.T) {
	for _, count := range []int{0, 1, 32, 33, 1000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			rows := make([]restoreRow, count)
			for i := range rows {
				rows[i].spec = restoreSpec(i)
			}
			checkRestoredQueue(t, rows)
		})
	}
	t.Run("future_rows_remain_pending", func(t *testing.T) {
		rows := make([]restoreRow, 40)
		for i := range rows {
			rows[i].spec = restoreSpec(i)
			if i >= 37 {
				future := time.Now().UTC().Truncate(time.Second).Add(24 * time.Hour)
				rows[i].spec.StartTime = &future
			}
		}
		checkRestoredQueue(t, rows)
	})
}

func TestRestoreDoesNotReplayStartedWork(t *testing.T) {
	checkRestoredQueue(t, []restoreRow{{spec: restoreSpec(0), started: true}, {spec: restoreSpec(1)}})
}

func restoreSpec(index int) scheduler.Spec {
	spec := scheduler.Spec{
		Binding:    storageTestBinding(),
		DebugletID: uuid.New(), TransactionID: fmt.Sprintf("%032x", index+1),
		Args: []string{fmt.Sprintf("job-%d", index), "comma,quote\"", "line\nbreak"},
		Wasm: []byte(fmt.Sprintf("persisted WASM bytes %d\x00", index)),
		Policy: scheduler.Policy{
			FloorBW: int64(64000 + index), CeilBW: int64(128000 + index),
			Timeout:   time.Duration(1000+index) * time.Millisecond,
			Addresses: []string{"127.0.0.1", "::1"}, RequireICMP: index%2 == 0,
			ListenUDP: index%3 == 0, ListenTCP: index%4 == 0, ListenSCION: index%5 == 0,
		},
	}
	if index%2 != 0 {
		past := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		spec.StartTime = &past
	}
	return spec
}

// restoreProgressTimeout bounds each wait for the next restored callback or
// finalizer, never the whole run, so it decides only whether the scheduler has
// stopped completing them. Each due row costs synchronous SQLite writes through
// the pool's one connection: with every fsync slowed by 11ms a thousand rows
// took over two minutes, yet consecutive completions stayed under 1.5s apart.
const restoreProgressTimeout = 90 * time.Second

// Restore runs before its consumer, as required by serialized startup. The
// failure cleanup also releases the original blocking-send implementation:
// callbacks cannot delete rows until paged restoration has finished.
func checkRestoredQueue(t *testing.T, rows []restoreRow) {
	t.Helper()
	db := newSchedulerTestDB(t)
	// The 1,000-row case retains SQLite's normal synchronous writes for each
	// started/deleted row. Bound restore itself separately from that disk work;
	// ctx covers setup and restore, and the waits for the disk work are bounded
	// by progress instead.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	queries := database.New(tx)
	expected := make(map[uuid.UUID]restoreRow, len(rows))
	due := 0
	for _, row := range rows {
		spec := row.spec
		start := time.Time{}
		if spec.StartTime != nil {
			start = *spec.StartTime
		}
		if err := queries.CreateDebuglet(ctx, database.CreateDebugletParams{
			DispatcherIncarnation: spec.Binding.Incarnation, SessionID: spec.Binding.SessionID,
			Uuid: spec.DebugletID, StartTime: database.NewUTCTime(start), Args: spec.Args,
			Wasm: spec.Wasm, TransactionID: spec.TransactionID, FloorBw: spec.Policy.FloorBW,
			CeilBw: spec.Policy.CeilBW, TimeoutMs: spec.Policy.Timeout.Milliseconds(),
			Addresses: spec.Policy.Addresses, RequireIcmp: spec.Policy.RequireICMP,
			ListenUdp: spec.Policy.ListenUDP, ListenTcp: spec.Policy.ListenTCP, ListenScion: spec.Policy.ListenSCION,
		}); err != nil {
			t.Fatal(err)
		}
		if row.started {
			if _, err := queries.UpdateDebugletStarted(ctx, database.UpdateDebugletStartedParams{
				Uuid: spec.DebugletID, StartedAt: database.NewUTCTime(time.Now().UTC()),
			}); err != nil {
				t.Fatal(err)
			}
		}
		expected[spec.DebugletID] = row
		if start.IsZero() || !start.After(time.Now()) {
			due++
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	storage := newTestStorage(t, db, storageTestEligibility)
	observations := make(chan restoreObservation, len(rows)+1)
	completed := make(chan uuid.UUID, len(rows)+1)
	var overflow atomic.Bool
	deleted := make(chan restoreDeletion, len(rows)+1)
	storage.decorate = func(conn database.DBTX) database.DBTX { return &restoreConnection{conn, deleted, &overflow} }
	observe := func(spec scheduler.Spec, err error) {
		select {
		case observations <- restoreObservation{spec, err}:
		default:
			overflow.Store(true)
		}
	}
	storage.RegisterOnStart(func(_ context.Context, spec scheduler.Spec) scheduler.Completion {
		observe(spec, nil)
		return scheduler.Completion{}
	})
	storage.RegisterFailed(func(_ context.Context, spec scheduler.Spec, err error) scheduler.Completion {
		observe(spec, err)
		return scheduler.Completion{}
	})
	gate := make(chan struct{})
	var release sync.Once
	var callbacks sync.WaitGroup
	var admission sync.Mutex
	acceptCallbacks := true
	storage.local.RegisterOnStart(func(callbackCtx context.Context, spec scheduler.Spec) scheduler.Completion {
		admission.Lock()
		if !acceptCallbacks {
			admission.Unlock()
			t.Error("callback admitted after scheduler shutdown")
			return scheduler.Completion{CleanupErr: errors.New("callback admitted after scheduler shutdown")}
		}
		callbacks.Add(1)
		admission.Unlock()
		defer callbacks.Done()
		<-gate
		result := storage.onStart(callbackCtx, spec)
		select {
		case completed <- spec.DebugletID:
		default:
			overflow.Store(true)
		}
		return result
	})

	loopCtx, stopLoop := context.WithCancel(context.Background())
	loopDone := make(chan error, 1)
	var startOnce sync.Once
	startLoop := func() { startOnce.Do(func() { go func() { loopDone <- storage.StartLoop(loopCtx) }() }) }
	loopJoined := false
	callbacksJoined := false
	joinLoopAndCallbacks := func() {
		stopLoop()
		startLoop()
		if !loopJoined {
			select {
			case err := <-loopDone:
				loopJoined = true
				if !errors.Is(err, context.Canceled) {
					t.Error("loop stop:", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("scheduler loop did not join")
			}
		}
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), scheduler.CleanupTimeout)
		if err := storage.Shutdown(shutdownCtx); err != nil {
			t.Errorf("owned callbacks/finalizers did not join: %v", err)
		}
		shutdownCancel()
		admission.Lock()
		acceptCallbacks = false
		admission.Unlock()
		if !callbacksJoined {
			joined := make(chan struct{})
			go func() { callbacks.Wait(); close(joined) }()
			select {
			case <-joined:
				callbacksJoined = true
			case <-time.After(5 * time.Second):
				t.Error("SQLite callbacks did not join")
			}
		}
	}
	restoreDone := make(chan error, 1)
	restoreJoined := false
	go func() { restoreDone <- storage.RestoreFromDatabase(ctx) }()
	// Explicit deferred teardown precedes the helper's registered DB close.
	defer func() {
		if !restoreJoined {
			startLoop()
			select {
			case <-restoreDone:
				restoreJoined = true
			case <-time.After(5 * time.Second):
				t.Error("restore producer did not join after starting cleanup consumer")
			}
		}
		release.Do(func() { close(gate) })
		joinLoopAndCallbacks()
	}()

	select {
	case err := <-restoreDone:
		restoreJoined = true
		if err != nil {
			t.Fatal("restore before loop:", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("restore blocked before its consumer started")
	}
	if len(observations) != 0 || len(completed) != 0 {
		t.Fatal("restore executed work before the loop started")
	}
	release.Do(func() { close(gate) })
	startLoop()
	seen := make(map[uuid.UUID]bool, due)
	for range due {
		select {
		case id := <-completed:
			if _, ok := expected[id]; !ok || seen[id] {
				t.Fatal("unknown or repeated restored callback:", id)
			}
			seen[id] = true
		case <-time.After(restoreProgressTimeout):
			t.Fatal("restored callbacks did not all complete:", len(seen), "of", due)
		}
	}
	for range due {
		select {
		case actual := <-observations:
			row, ok := expected[actual.spec.DebugletID]
			if !ok {
				t.Fatal("unexpected callback identity")
			}
			want := row.spec
			if want.StartTime == nil {
				zero := time.Time{} // NULL scans into a pointer to zero time.
				want.StartTime = &zero
			}
			if row.started {
				if !errors.Is(actual.err, scheduler.ErrDebugletAlreadyStarted) {
					t.Fatal("previously started work was replayed:", actual.err)
				}
				want.Wasm = nil // The failure callback does not load WASM.
			} else if actual.err != nil {
				t.Fatal("restored work failed:", actual.err)
			}
			if !reflect.DeepEqual(actual.spec, want) {
				t.Fatalf("restored spec differs:\ngot %#v\nwant %#v", actual.spec, want)
			}
		default:
			t.Fatal("completion had no corresponding start/failure observation")
		}
	}
	// SQL finalization now follows callback completion. Observe every real
	// successful DELETE, again bounded by progress, before asking Shutdown to
	// join the final bookkeeping and release of Conn.
	deletedIDs := make(map[uuid.UUID]bool, due)
	for range due {
		select {
		case result := <-deleted:
			if !seen[result.id] || deletedIDs[result.id] || result.err != nil {
				t.Fatalf("unexpected/failed real finalizer: %+v", result)
			}
			deletedIDs[result.id] = true
		case <-time.After(restoreProgressTimeout):
			t.Fatalf("actual finalizers completed%d of%d", len(deletedIDs), due)
		}
	}
	joinLoopAndCallbacks()
	if !loopJoined || !callbacksJoined {
		t.Fatal("cannot inspect retained rows before loop and callbacks join")
	}
	if overflow.Load() || len(completed) != 0 || len(observations) != 0 || len(deleted) != 0 {
		t.Fatal("unexpected additional callback")
	}
	// The waits above may outlast ctx, so this single read has its own bound.
	readCtx, readCancel := context.WithTimeout(context.Background(), scheduler.CleanupTimeout)
	remaining, err := database.New(db).ListDebuglets(readCtx, database.ListDebugletsParams{Limit: int64(len(rows) + 1)})
	readCancel()
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != len(rows)-due {
		t.Fatalf("remaining rows: got %d want %d", len(remaining), len(rows)-due)
	}
	for _, row := range remaining {
		want, ok := expected[row.Uuid]
		if !ok || want.spec.StartTime == nil || !want.spec.StartTime.After(time.Now()) || !row.StartTime.Equal(*want.spec.StartTime) || !row.StartedAt.IsZero() || !reflect.DeepEqual(row.Wasm, want.spec.Wasm) {
			t.Fatal("future row was consumed, changed or unexpectedly started")
		}
	}
}
