// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

func cleanupExec(t *testing.T, f *tgFixture, statement string) {
	t.Helper()
	if _, err := f.db.ExecContext(f.ctx, statement); err != nil {
		t.Fatal(err)
	}
}

// A terminal write can commit without its caller releasing the run's
// resources, for example when the commit's result is lost. A later duplicate
// delivery must release them exactly once: the first duplicate frees the run's
// destination and floor, and further duplicates subtract nothing from a
// sibling sharing the same rounded buckets and destination. Neither repeats
// payment. Releasing by stored window, or by incarnation and restore time,
// would subtract the floor again on the second duplicate.
func TestTerminalDuplicateReleasesUnreleasedWinnerOnce(t *testing.T) {
	for _, duplicate := range []string{"exit", "unbound cancellation"} {
		t.Run(duplicate, func(t *testing.T) {
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
			result := tgText("original terminal result")
			if _, err := f.q.CompleteDebuglet(f.ctx, database.CompleteDebugletParams{
				Uuid: a.id, ExecutorID: a.row.ExecutorID, ExitedState: models.RunStateExited,
				DispatcherIncarnation: a.row.DispatcherIncarnation, SessionID: a.row.SessionID,
				Error: result,
			}); err != nil {
				t.Fatal(err)
			}
			tgAssertReserved(t, f, b, tgFloorA+tgFloorB)
			allocationCharged(t, f.d, destination, tgFloorA+tgFloorB)
			if duplicate == "unbound cancellation" {
				registryRegister(t, f.d, tgExecutorID)
			}
			deliver := func(n int) {
				t.Helper()
				var err error
				if duplicate == "exit" {
					err = f.exit(t, a.id, 5, tgStr("different result"))
				} else {
					err = f.abort(t, a.id, "replacement reason")
				}
				if err != nil {
					t.Fatalf("duplicate %d: %v", n, err)
				}
				tgAssertRow(t, f.row(t, a.id), models.RunStateExited, result)
				tgAssertReserved(t, f, b, tgFloorB)
				allocationCharged(t, f.d, destination, tgFloorB)
				tgAssertOrder(t, f, a, models.Outstanding)
				tgAssertEarnings(t, f, 0)
			}
			deliver(1)
			deliver(2)
			f.d.mu.RLock()
			_, held := f.d.reservations[a.id]
			remaining := len(f.d.reservations)
			f.d.mu.RUnlock()
			if held || remaining != 1 {
				t.Fatalf("reservations after duplicates: a held=%v, %d remaining, want only b", held, remaining)
			}
		})
	}
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
