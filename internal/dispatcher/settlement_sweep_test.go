// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

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
	if settled, failed, err := f.ph.SettlePendingOrders(f.ctx, settlementSweepLimit); settled != 0 || failed != len(exits) || err == nil {
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

	if settled, failed, err := g.ph.SettlePendingOrders(g.ctx, settlementSweepLimit); settled != 0 || failed != 0 || err != nil {
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

	if settled, failed, err := f.ph.SettlePendingOrders(f.ctx, settlementSweepLimit); settled != 0 || failed != 0 || err != nil {
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
	g := ssExitRefused(t, f, []ssExit{{first, 0}, {second, 0}})

	if settled, failed, err := g.ph.SettlePendingOrders(g.ctx, 1); settled != 1 || failed != 0 || err != nil {
		t.Fatalf("bounded pass settled %d, failed %d, error %v", settled, failed, err)
	}
	tgAssertOrder(t, g, first, models.Credited)
	tgAssertOrder(t, g, second, models.Outstanding)
	if settled, failed, err := g.ph.SettlePendingOrders(g.ctx, 1); settled != 1 || failed != 0 || err != nil {
		t.Fatalf("next pass settled %d, failed %d, error %v", settled, failed, err)
	}
	tgAssertOrder(t, g, second, models.Credited)
	tgAssertEarnings(t, g, tgOrderPrice(tgFloorA)+tgOrderPrice(tgFloorB))
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
