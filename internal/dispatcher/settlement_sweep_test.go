// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

func TestSettlementSweepRecoversCancellationAfterRestart(t *testing.T) {
	f := newTGFixture(t, nil)
	run := f.seedDirect(t, tgFloorA)
	ssClaim(t, f, run)
	registryRegister(t, f.d, tgExecutorID)
	ssRefuseSettlements(t, f)
	if err := f.abort(t, run.id, "cancelled via API"); err != nil {
		t.Fatal(err)
	}
	tgAssertRow(t, f.row(t, run.id), models.RunStateExited, tgText(deadCancelError))
	tgAssertOrder(t, f, run, models.Outstanding)

	loop := newWELoop()
	g := reopenTG(t, f, loop.install)
	ssAllowSettlements(t, g)
	if err := g.d.RestoreScheduler(g.ctx); err != nil {
		t.Fatal(err)
	}
	loop.tick(t)
	tgAssertOrder(t, g, run, models.Refunded)
	tgAssertEarnings(t, g, 0)
	if n := ssSettlements(t, g, "refund"); n != 1 {
		t.Fatalf("refund settlements = %d, want 1", n)
	}
	if observed, err := g.q.GetMeasurementExecution(g.ctx, run.row.ID); !errors.Is(err, sql.ErrNoRows) && (err != nil || observed.ExitCode.Valid || observed.TerminalObservedNs.Valid) {
		t.Fatalf("cancellation invented an execution observation: %+v, %v", observed, err)
	}
	if err := g.abort(t, run.id, "second cancellation"); err != nil {
		t.Fatal(err)
	}
	if settled, failed, _, _, err := g.ph.SettlePendingOrders(g.ctx, 0, settlementSweepLimit); settled != 0 || failed != 0 || err != nil {
		t.Fatalf("repeat pass: settled %d, failed %d, error %v", settled, failed, err)
	}
}

func TestSettlementSweepPreservesCancellationTerminalWinner(t *testing.T) {
	for _, first := range []string{"completion", "cancellation", "concurrent"} {
		t.Run(first, func(t *testing.T) {
			f := newTGFixture(t, nil)
			run := f.seedDirect(t, tgFloorA)
			ssClaim(t, f, run)
			if _, err := f.d.requestCancellation(f.ctx, run.row.ID, "cancelled"); err != nil {
				t.Fatal(err)
			}
			identity, err := f.q.GetDebugletIdentityByUUID(f.ctx, run.id)
			if err != nil {
				t.Fatal(err)
			}
			ssRefuseSettlements(t, f)
			calls := []func() error{
				func() error { return f.exit(t, run.id, 0, nil) },
				func() error { return f.d.recordCancellationResult(f.ctx, identity, run.id, "cancelled") },
			}
			if first == "cancellation" {
				calls[0], calls[1] = calls[1], calls[0]
			}
			errs := make([]error, len(calls))
			if first == "concurrent" {
				start := make(chan struct{})
				var wg sync.WaitGroup
				for i, call := range calls {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						errs[i] = call()
					}()
				}
				close(start)
				wg.Wait()
			} else {
				for i, call := range calls {
					errs[i] = call()
				}
			}
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			winner := f.row(t, run.id)
			g := reopenTG(t, f)
			ssAllowSettlements(t, g)
			if settled, failed, _, _, err := g.ph.SettlePendingOrders(g.ctx, 0, 32); settled != 1 || failed != 0 || err != nil {
				t.Fatalf("settled %d, failed %d, error %v", settled, failed, err)
			}
			record, err := g.q.GetCancellation(g.ctx, run.row.ID)
			if err != nil || record.TerminalRecordedAt.Valid != winner.Error.Valid {
				t.Fatalf("decision does not match winner: %+v, %v; winner %+v", record, err, winner)
			}
			wantState, wantEarnings := models.Credited, tgOrderPrice(tgFloorA)
			if winner.Error.Valid {
				wantState, wantEarnings = models.Refunded, 0
			}
			tgAssertOrder(t, g, run, wantState)
			tgAssertEarnings(t, g, wantEarnings)
			if err := g.abort(t, run.id, "duplicate after restart"); err != nil {
				t.Fatal(err)
			}
			if settled, failed, _, _, err := g.ph.SettlePendingOrders(g.ctx, 0, 32); settled != 0 || failed != 0 || err != nil {
				t.Fatalf("duplicate settled %d, failed %d, error %v", settled, failed, err)
			}
			tgAssertRow(t, g.row(t, run.id), winner.State, winner.Error)
		})
	}
}

// ssSettlements counts the recorded order settlements of kind.
func ssSettlements(t *testing.T, f *tgFixture, kind string) int {
	t.Helper()
	var n int
	if err := f.db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM order_settlements WHERE kind = ?", kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// ssRefuseSettlements makes every settlement write fail until
// ssAllowSettlements is called.
func ssRefuseSettlements(t *testing.T, f *tgFixture) {
	t.Helper()
	if _, err := f.db.ExecContext(f.ctx, `CREATE TRIGGER ss_refuse_settlement BEFORE INSERT ON order_settlements
BEGIN SELECT RAISE(ABORT, 'settlement refused'); END;`); err != nil {
		t.Fatal(err)
	}
}

func ssAllowSettlements(t *testing.T, f *tgFixture) {
	t.Helper()
	if _, err := f.db.ExecContext(f.ctx, "DROP TRIGGER ss_refuse_settlement"); err != nil {
		t.Fatal(err)
	}
}

// ssClaim records run as the run of its order, as admission does; seedDirect
// creates the run without that claim.
func ssClaim(t *testing.T, f *tgFixture, run tgDebuglet) {
	t.Helper()
	if _, err := f.db.ExecContext(f.ctx, "UPDATE debuglet_order SET debuglet_id = (SELECT id FROM debuglets WHERE uuid = ?) WHERE transaction_id = ? AND order_id = ?",
		run.id, run.txID, run.orderID); err != nil {
		t.Fatal(err)
	}
}

// ssExit is one exit report of a run.
type ssExit struct {
	run  tgDebuglet
	code int32
}

// ssExitRefused reports the exits of runs while settlement is refused, so the
// terminal path leaves their orders Outstanding, and then reopens the database
// in a dispatcher whose maintenance loop has not started; prepare runs on it
// first. Settlement is allowed again in the reopened database.
func ssExitRefused(t *testing.T, f *tgFixture, exits []ssExit, prepare ...func(*Dispatcher)) *tgFixture {
	t.Helper()
	ssRefuseSettlements(t, f)
	for _, exit := range exits {
		ssClaim(t, f, exit.run)
		if err := f.exit(t, exit.run.id, exit.code, nil); err != nil {
			t.Fatalf("exit %d of %s: %v", exit.code, exit.run.id, err)
		}
		if row := f.row(t, exit.run.id); row.State != models.RunStateExited {
			t.Fatalf("run %s is %s after its exit", exit.run.id, row.State)
		}
		tgAssertOrder(t, f, exit.run, models.Outstanding)
	}
	tgAssertEarnings(t, f, 0)
	// While the settlement is still refused a pass settles nothing and
	// reports the failure.
	if settled, failed, _, _, err := f.ph.SettlePendingOrders(f.ctx, 0, settlementSweepLimit); settled != 0 || failed != len(exits) || err == nil {
		t.Fatalf("pass while refused settled %d, failed %d, error %v", settled, failed, err)
	}
	g := reopenTG(t, f, prepare...)
	ssAllowSettlements(t, g)
	return g
}

// A terminal run whose settlement failed after the terminal report is settled
// by the next pass of the maintenance loop, also after a restart, once: the
// successful run is credited and the failed TEST run refunded locally. A
// second pass finds nothing to settle.
func TestSettlementSweepDeliversFailedInlineSettlements(t *testing.T) {
	f := newTGFixture(t, nil)
	succeeded, failed := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
	loop := newWELoop()
	g := ssExitRefused(t, f, []ssExit{{succeeded, 0}, {failed, 3}}, loop.install)
	if err := g.d.RestoreScheduler(g.ctx); err != nil {
		t.Fatalf("restore: %v", err)
	}
	loop.tick(t)
	tgAssertOrder(t, g, succeeded, models.Credited)
	tgAssertOrder(t, g, failed, models.Refunded)
	tgAssertEarnings(t, g, tgOrderPrice(tgFloorA))
	if credits, refunds := ssSettlements(t, g, "credit"), ssSettlements(t, g, "refund"); credits != 1 || refunds != 1 {
		t.Fatalf("%d credit and %d refund settlements, want one each", credits, refunds)
	}

	if settled, failed, _, _, err := g.ph.SettlePendingOrders(g.ctx, 0, settlementSweepLimit); settled != 0 || failed != 0 || err != nil {
		t.Fatalf("second pass settled %d, failed %d, error %v", settled, failed, err)
	}
	loop.set(time.Now().Add(time.Hour))
	loop.tick(t)
	tgAssertEarnings(t, g, tgOrderPrice(tgFloorA))
	if n := ssSettlements(t, g, "credit") + ssSettlements(t, g, "refund"); n != 2 {
		t.Fatalf("%d settlements after a second pass, want 2", n)
	}
}

// Only an order whose run is terminal with a recorded exit code is settled. A
// run that is not terminal, and a terminal run without a recorded exit code,
// keep their order Outstanding: nothing infers an outcome.
func TestSettlementSweepSkipsRunsWithoutATerminalExitCode(t *testing.T) {
	f := newTGFixture(t, nil)
	running, unknown := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
	ssClaim(t, f, running)
	ssClaim(t, f, unknown)
	// The run that is not terminal has an exit code recorded, so only its
	// state keeps it from being settled.
	if _, err := f.db.ExecContext(f.ctx, "INSERT INTO measurement_execution (debuglet_id, exit_code) SELECT id, 0 FROM debuglets WHERE uuid = ?", running.id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, "UPDATE debuglets SET state = ? WHERE uuid = ?", models.RunStateExited, unknown.id); err != nil {
		t.Fatal(err)
	}
	// Even a retained request and ACK do not prove cancellation won.
	if _, err := f.d.requestCancellation(f.ctx, unknown.row.ID, "old request"); err != nil {
		t.Fatal(err)
	}
	cleanupExec(t, f, "UPDATE debuglet_cancellations SET acknowledged_at=1")

	if settled, failed, _, _, err := f.ph.SettlePendingOrders(f.ctx, 0, settlementSweepLimit); settled != 0 || failed != 0 || err != nil {
		t.Fatalf("pass settled %d, failed %d, error %v", settled, failed, err)
	}
	f.d.sweepPendingSettlements(time.Time{})
	tgAssertOrder(t, f, running, models.Outstanding)
	tgAssertOrder(t, f, unknown, models.Outstanding)
	tgAssertEarnings(t, f, 0)
	if n := ssSettlements(t, f, "credit") + ssSettlements(t, f, "refund"); n != 0 {
		t.Fatalf("%d settlements recorded for unsettleable runs", n)
	}
}

// A pass settles at most its limit, in run order; the rest waits for the next.
func TestSettlementSweepIsBoundedByItsLimit(t *testing.T) {
	f := newTGFixture(t, nil)
	first, second := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
	ssRefuseSettlements(t, f)
	ssClaim(t, f, first)
	ssClaim(t, f, second)
	if err := f.exit(t, first.id, 0, nil); err != nil {
		t.Fatal(err)
	}
	registryRegister(t, f.d, tgExecutorID)
	if err := f.abort(t, second.id, "cancelled via API"); err != nil {
		t.Fatal(err)
	}
	g := reopenTG(t, f)
	ssAllowSettlements(t, g)

	settled, failed, _, next, err := g.ph.SettlePendingOrders(g.ctx, 0, 1)
	if settled != 1 || failed != 0 || next != first.row.ID || err != nil {
		t.Fatalf("bounded pass settled %d, failed %d, next %d, error %v", settled, failed, next, err)
	}
	tgAssertOrder(t, g, first, models.Credited)
	tgAssertOrder(t, g, second, models.Outstanding)
	if settled, failed, _, next, err := g.ph.SettlePendingOrders(g.ctx, next, 1); settled != 1 || failed != 0 || next != second.row.ID || err != nil {
		t.Fatalf("next pass settled %d, failed %d, next %d, error %v", settled, failed, next, err)
	}
	tgAssertOrder(t, g, second, models.Refunded)
	tgAssertEarnings(t, g, tgOrderPrice(tgFloorA))
}

// A closed dispatcher does not sweep.
func TestSettlementSweepSkipsAClosedDispatcher(t *testing.T) {
	f := newTGFixture(t, nil)
	run := f.seedDirect(t, tgFloorA)
	g := ssExitRefused(t, f, []ssExit{{run, 0}})
	g.d.Close()
	last := time.Unix(1, 0)
	if got := g.d.sweepPendingSettlements(last); !got.Equal(last) {
		t.Fatalf("closed sweep returned %v, want %v", got, last)
	}
	tgAssertOrder(t, g, run, models.Outstanding)
}

// A failing order does not keep later ones from being settled: each pass
// continues after the last run the previous one attempted and starts over once
// the listing is exhausted, so the failing orders are attempted again.
func TestSettlementSweepContinuesPastFailingOrders(t *testing.T) {
	f := newTGFixture(t, nil)
	a, b, c := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorA)
	g := ssExitRefused(t, f, []ssExit{{a, 0}, {b, 0}, {c, 0}})
	if _, err := g.db.ExecContext(g.ctx, fmt.Sprintf(`CREATE TRIGGER ss_refuse_two BEFORE INSERT ON order_settlements
WHEN NEW.debuglet_id IN (%d, %d) BEGIN SELECT RAISE(ABORT, 'settlement refused'); END;`, a.row.ID, b.row.ID)); err != nil {
		t.Fatal(err)
	}
	after := int64(0)
	for i, want := range []struct {
		settled, failed int
		next            int64
	}{
		{0, 2, b.row.ID},
		{1, 0, 0},
		{0, 2, b.row.ID},
	} {
		settled, failed, deferred, next, err := g.ph.SettlePendingOrders(g.ctx, after, 2)
		if settled != want.settled || failed != want.failed || deferred != 0 || next != want.next || (err == nil) != (failed == 0) {
			t.Fatalf("pass %d after %d: settled %d, failed %d, deferred %d, next %d, error %v; want %+v",
				i+1, after, settled, failed, deferred, next, err, want)
		}
		after = next
	}
	tgAssertOrder(t, g, a, models.Outstanding)
	tgAssertOrder(t, g, b, models.Outstanding)
	tgAssertOrder(t, g, c, models.Credited)
	tgAssertEarnings(t, g, tgOrderPrice(tgFloorA))
}

// The maintenance sweep keeps its position between passes.
func TestSettlementSweepKeepsItsPosition(t *testing.T) {
	f := newTGFixture(t, nil)
	a, b := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
	g := ssExitRefused(t, f, []ssExit{{a, 0}, {b, 0}})
	if _, err := g.db.ExecContext(g.ctx, fmt.Sprintf(`CREATE TRIGGER ss_refuse_one BEFORE INSERT ON order_settlements
WHEN NEW.debuglet_id = %d BEGIN SELECT RAISE(ABORT, 'settlement refused'); END;`, a.row.ID)); err != nil {
		t.Fatal(err)
	}
	g.d.settlementAfter = a.row.ID
	g.d.sweepPendingSettlements(time.Time{})
	if g.d.settlementAfter != 0 {
		t.Fatalf("an exhausted pass continues after %d, want a new start", g.d.settlementAfter)
	}
	tgAssertOrder(t, g, a, models.Outstanding)
	tgAssertOrder(t, g, b, models.Credited)
	g.d.sweepPendingSettlements(time.Time{})
	tgAssertOrder(t, g, a, models.Outstanding)
	if g.d.settlementAfter != 0 {
		t.Fatalf("a short pass continues after %d, want a new start", g.d.settlementAfter)
	}
}
