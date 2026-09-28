// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func cleanupResult(run tgDebuglet) database.CompleteDebugletParams {
	return database.CompleteDebugletParams{
		Uuid: run.id, ExecutorID: run.row.ExecutorID, ExitedState: models.RunStateExited,
		DispatcherIncarnation: run.row.DispatcherIncarnation, SessionID: run.row.SessionID,
		Error: tgText("original terminal result"),
	}
}

func cleanupPending(t *testing.T, f *tgFixture, run tgDebuglet, want bool) {
	t.Helper()
	_, err := f.q.GetTerminalCleanup(f.ctx, run.id)
	if want && err != nil || !want && !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("pending cleanup=%v, want present=%v", err, want)
	}
}

func cleanupExec(t *testing.T, f *tgFixture, statement string) {
	t.Helper()
	if _, err := f.db.ExecContext(f.ctx, statement); err != nil {
		t.Fatal(err)
	}
}

// The fixture stops at concrete production helper boundaries, then reopens the
// real SQLite file. This models process interruption, not host power failure.
func TestTerminalCleanupRestartsAtEachResourceBoundary(t *testing.T) {
	for _, phase := range []string{"terminal committed", "destinations released", "floor released"} {
		t.Run(phase, func(t *testing.T) {
			f := newTGFixture(t, nil)
			a, b := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
			const destination = "192.0.2.28"
			for _, run := range []tgDebuglet{a, b} {
				allocationBind(t, f, run, destination)
				f.d.mu.Lock()
				err := f.d.destinations.Insert(run.id, destination, tgExecutorID, run.floor, 2*run.floor)
				f.d.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			chosen, err := f.d.completeTerminal(f.ctx, cleanupResult(a))
			if err != nil {
				t.Fatal(err)
			}
			cleanupPending(t, f, a, true)
			f.d.mu.Lock()
			if phase != "terminal committed" {
				for _, address := range chosen.Addresses {
					f.d.destinations.Remove(chosen.Uuid, address)
				}
			}
			if phase == "floor released" {
				f.d.releaseFloor(chosen.Uuid)
			}
			f.d.mu.Unlock()
			if phase != "terminal committed" {
				allocationCharged(t, f.d, destination, tgFloorB)
			}

			g := restartTG(t, f)
			if err := g.d.RestoreScheduler(g.ctx); err != nil {
				t.Fatal(err)
			}
			cleanupPending(t, g, a, false)
			tgAssertRow(t, g.row(t, a.id), models.RunStateExited, cleanupResult(a).Error)
			tgAssertReserved(t, g, b, tgFloorB)
			// A crash before payment is not repaired by resource reconciliation.
			tgAssertOrder(t, g, a, models.Outstanding)
			tgAssertEarnings(t, g, 0)
			fresh := g.seedDirect(t, tgFloorA)
			if err := g.exit(t, a.id, 0, nil); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("replacement session accepted old terminal: %v", err)
			}
			if err := g.d.finishTerminalCleanup(g.ctx, a.id); err != nil {
				t.Fatal(err)
			}
			tgAssertReserved(t, g, fresh, tgFloorA+tgFloorB)
			tgAssertOrder(t, g, a, models.Outstanding)
		})
	}
}

func TestTerminalCleanupDuplicateAfterCompletionWriteFailure(t *testing.T) {
	f := newTGFixture(t, nil)
	a, b := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
	const destination = "192.0.2.28"
	for _, run := range []tgDebuglet{a, b} {
		allocationBind(t, f, run, destination)
		f.d.mu.Lock()
		err := f.d.destinations.Insert(run.id, destination, tgExecutorID, run.floor, 2*run.floor)
		f.d.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	cleanupExec(t, f, `CREATE TRIGGER reject_cleanup BEFORE DELETE ON debuglet_terminal_cleanup
		BEGIN SELECT RAISE(ABORT, 'cleanup completion unavailable'); END`)
	if err := f.exit(t, a.id, 0, nil); err == nil || !strings.Contains(err.Error(), "cleanup completion unavailable") {
		t.Fatalf("cleanup failure was acknowledged: %v", err)
	}
	cleanupPending(t, f, a, true)
	tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgNull)
	tgAssertReserved(t, f, b, tgFloorB)
	allocationCharged(t, f.d, destination, tgFloorB)
	tgAssertEarnings(t, f, tgOrderPrice(tgFloorA))
	if err := f.exit(t, a.id, 5, tgStr("different result")); err == nil {
		t.Fatal("duplicate ignored pending completion failure")
	}
	tgAssertReserved(t, f, b, tgFloorB)
	allocationCharged(t, f.d, destination, tgFloorB)
	tgAssertEarnings(t, f, tgOrderPrice(tgFloorA))
	cleanupExec(t, f, "DROP TRIGGER reject_cleanup")
	if err := f.exit(t, a.id, 5, tgStr("different result")); err != nil {
		t.Fatal(err)
	}
	cleanupPending(t, f, a, false)
	tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgNull)
	tgAssertReserved(t, f, b, tgFloorB)
	allocationCharged(t, f.d, destination, tgFloorB)
	tgAssertEarnings(t, f, tgOrderPrice(tgFloorA))
}

func TestTerminalCleanupSelectionRollsBackOnStorageFailure(t *testing.T) {
	for _, failure := range []string{"insert", "commit"} {
		t.Run(failure, func(t *testing.T) {
			f := newTGFixture(t, nil)
			a, b := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
			before := f.snapshot(t)
			if failure == "insert" {
				cleanupExec(t, f, `CREATE TRIGGER reject_cleanup BEFORE INSERT ON debuglet_terminal_cleanup
					BEGIN SELECT RAISE(ABORT, 'cleanup insertion unavailable'); END`)
			} else {
				cleanupExec(t, f, `CREATE TABLE cleanup_parent (id INTEGER PRIMARY KEY);
					CREATE TABLE cleanup_deferred (parent_id INTEGER REFERENCES cleanup_parent(id) DEFERRABLE INITIALLY DEFERRED);
					CREATE TRIGGER reject_cleanup AFTER INSERT ON debuglet_terminal_cleanup
					BEGIN INSERT INTO cleanup_deferred VALUES (1); END`)
			}
			if err := f.exit(t, a.id, 0, nil); err == nil {
				t.Fatal("failed transaction was acknowledged")
			}
			cleanupPending(t, f, a, false)
			tgAssertSnapshot(t, f, before, "terminal transaction failure")
			tgAssertReserved(t, f, b, tgFloorA+tgFloorB)
			cleanupExec(t, f, "DROP TRIGGER reject_cleanup")
			if err := f.exit(t, a.id, 0, nil); err != nil {
				t.Fatal(err)
			}
			tgAssertReserved(t, f, b, tgFloorB)
			tgAssertEarnings(t, f, tgOrderPrice(tgFloorA))
		})
	}
}

func TestTerminalCleanupRestoreFailureIsRetryable(t *testing.T) {
	f := newTGFixture(t, nil)
	a, b := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
	if _, err := f.d.completeTerminal(f.ctx, cleanupResult(a)); err != nil {
		t.Fatal(err)
	}
	cleanupExec(t, f, `CREATE TRIGGER reject_cleanup BEFORE DELETE ON debuglet_terminal_cleanup
		BEGIN SELECT RAISE(ABORT, 'cleanup completion unavailable'); END`)
	g := restartTG(t, f)
	if err := g.d.RestoreScheduler(g.ctx); err == nil {
		t.Fatal("restore ignored pending completion failure")
	}
	cleanupPending(t, g, a, true)
	tgAssertReserved(t, g, b, 0)
	cleanupExec(t, g, "DROP TRIGGER reject_cleanup")
	if err := g.d.RestoreScheduler(g.ctx); err != nil {
		t.Fatal(err)
	}
	cleanupPending(t, g, a, false)
	tgAssertReserved(t, g, b, tgFloorB)
	if err := g.d.RestoreScheduler(g.ctx); err == nil {
		t.Fatal("second restore was accepted")
	}
	tgAssertReserved(t, g, b, tgFloorB)
}

func TestTerminalCleanupUnboundCancellationCompletesPendingWork(t *testing.T) {
	f := newTGFixture(t, nil)
	a, b := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
	registryRegister(t, f.d, tgExecutorID)
	cleanupExec(t, f, `CREATE TRIGGER reject_cleanup BEFORE DELETE ON debuglet_terminal_cleanup
		BEGIN SELECT RAISE(ABORT, 'cleanup completion unavailable'); END`)
	if err := f.abort(t, a.id, "first cancellation"); err == nil {
		t.Fatal("unbound cancellation ignored failed cleanup completion")
	}
	chosen := f.row(t, a.id)
	cleanupPending(t, f, a, true)
	tgAssertReserved(t, f, b, tgFloorB)
	cleanupExec(t, f, "DROP TRIGGER reject_cleanup")
	if err := f.abort(t, a.id, "replacement reason"); err != nil {
		t.Fatal(err)
	}
	cleanupPending(t, f, a, false)
	tgAssertRow(t, f.row(t, a.id), models.RunStateExited, chosen.Error)
	tgAssertReserved(t, f, b, tgFloorB)
	tgAssertEarnings(t, f, 0)
}

func TestTerminalCleanupAdmissionRollbackDropsRunReservation(t *testing.T) {
	for _, failure := range []string{"later invalid spec", "insert"} {
		t.Run(failure, func(t *testing.T) {
			f := newTGFixture(t, nil)
			specs := f.batch(t, tgFloorA, tgFloorB)
			if failure == "later invalid spec" {
				specs[1].Policy.FloorBW = -1
			} else {
				cleanupExec(t, f, `CREATE TRIGGER reject_admission BEFORE INSERT ON debuglets
					BEGIN SELECT RAISE(ABORT, 'admission unavailable'); END`)
			}
			_, err := f.d.SubmitDebuglets(f.ctx, specs, nil)
			if failure == "later invalid spec" && !errors.Is(err, ErrInvalidPolicy) || failure == "insert" && (err == nil || !strings.Contains(err.Error(), "admission unavailable")) {
				t.Fatalf("unexpected admission error: %v", err)
			}
			f.d.mu.RLock()
			remaining := len(f.d.reservations)
			f.d.mu.RUnlock()
			if remaining != 0 {
				t.Fatalf("rollback left %d run reservations", remaining)
			}
			if floor := f.d.scheduler.QueryMaxExec(tgExecutorID, f.start, f.start.Add(time.Minute)); floor != 0 {
				t.Fatalf("rollback left floor %v", floor)
			}
		})
	}
}

// Keep the real SQLite restore snapshot open while a second connection commits
// a terminal result. Cleanup must wait for reconstruction, then remove only
// that run's floor. The same SQL gate is used by the unrelated-peer drain test.
func TestTerminalCleanupCommitOverlapsRestoreSnapshot(t *testing.T) {
	release, open := siGate()
	gate := &fencingSQLGate{query: "ListDebugletsEndAfter", entered: make(chan struct{}), release: release}
	d := fencingDispatcher(t, gate)
	if _, err := d.db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatal(err)
	}
	d.db.SetMaxOpenConns(2)
	owner := registryRegister(t, d, "cleanup-restore")
	a, b := fencingRun(t, d, owner), fencingRun(t, d, owner)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	defer open()
	var calls sync.WaitGroup
	t.Cleanup(func() { open(); cancel(); calls.Wait() })
	restored := make(chan error, 1)
	calls.Add(1)
	go func() { defer calls.Done(); restored <- d.RestoreScheduler(ctx) }()
	siAwait(t, gate.entered, "restore snapshot before reconstruction")
	selected := make(chan error, 1)
	calls.Add(1)
	go func() {
		defer calls.Done()
		_, err := d.completeTerminal(ctx, database.CompleteDebugletParams{
			Uuid: a.Uuid, ExecutorID: a.ExecutorID, DispatcherIncarnation: a.DispatcherIncarnation,
			SessionID: a.SessionID, ExitedState: models.RunStateExited,
		})
		selected <- err
	}()
	select {
	case err := <-selected:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("terminal commit waited for the registry lock")
	}
	finished := make(chan error, 1)
	calls.Add(1)
	go func() { defer calls.Done(); finished <- d.finishTerminalCleanup(ctx, a.Uuid) }()
	open()
	for _, result := range []<-chan error{restored, finished} {
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("restore/cleanup failed to join")
		}
	}
	if floor := d.scheduler.QueryMaxExec(b.ExecutorID, b.StartTime.Time, b.EndTime.Time); floor != 1000 {
		t.Fatalf("sibling floor=%v, want 1000", floor)
	}
	if _, err := database.New(d.db).GetTerminalCleanup(ctx, a.Uuid); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cleanup not completed: %v", err)
	}
}
