// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

// settlementOf returns the number of settlement rows of the test order and,
// when there is one, the row itself.
func settlementOf(t *testing.T, db *sql.DB) (int, database.OrderSettlement) {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM order_settlements").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		return 0, database.OrderSettlement{}
	}
	row, err := database.New(db).GetOrderSettlement(t.Context(), database.GetOrderSettlementParams{
		TransactionID: testTxID, OrderID: testOrderID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return n, row
}

// assertSettledOnce checks the single settlement row of the test order and
// that the order state and the executor's income agree with it.
func assertSettledOnce(t *testing.T, db *sql.DB, kind string) {
	t.Helper()
	n, row := settlementOf(t, db)
	if n != 1 || row.Kind != kind || row.Amount != testPrice || row.Currency != "TEST" || row.ExecutorID != testExecutor {
		t.Fatalf("%d settlement rows, first %+v; want one %s of %d TEST to %s", n, row, kind, testPrice, testExecutor)
	}
	wantState, wantIncome := models.Credited, testPrice
	if kind == settlementRefund {
		wantState, wantIncome = models.Refunded, 0
	}
	if got := orderState(t, db); got != wantState {
		t.Fatalf("order state %v after a %s, want %v", got, kind, wantState)
	}
	if got := totalIncome(t, db); got != wantIncome {
		t.Fatalf("total income %d after a %s, want %d", got, kind, wantIncome)
	}
}

// A successful run credits its order once and records one credit settlement;
// delivering the same decision again changes nothing.
func TestSettleTerminalOrderCreditsOnceWithOneSettlement(t *testing.T) {
	db := newRefundDatabase(t)
	h, rec := newDisabledHandler(t, db, true, true)
	seedTESTOrder(t, db, models.Outstanding)

	for i := range 2 {
		if err := h.SettleTerminalOrder(t.Context(), testDebuglet(), 0); err != nil {
			t.Fatalf("settlement %d: %v", i+1, err)
		}
	}
	assertSettledOnce(t, db, settlementCredit)
	if calls := rec.chain.Calls(); len(calls) != 0 {
		t.Fatalf("TEST settlement reached the chain backend: %v", calls)
	}
}

// A failed TEST run refunds its order locally: the order becomes Refunded with
// one refund settlement, nothing is credited and no chain call is made. A later
// success report for the same order does not credit it.
func TestSettleTerminalOrderRefundsFailedTESTRunLocally(t *testing.T) {
	db := newRefundDatabase(t)
	h, rec := newDisabledHandler(t, db, true, true)
	seedTESTOrder(t, db, models.Outstanding)

	if err := h.SettleTerminalOrder(t.Context(), testDebuglet(), 3); err != nil {
		t.Fatalf("refund of a failed TEST run: %v", err)
	}
	if err := h.SettleTerminalOrder(t.Context(), testDebuglet(), 0); err != nil {
		t.Fatalf("credit after the refund: %v", err)
	}
	assertSettledOnce(t, db, settlementRefund)
	if calls := rec.chain.Calls(); len(calls) != 0 {
		t.Fatalf("TEST refund reached the chain backend: %v", calls)
	}
}

// A refused settlement row rolls back the state transition and the earnings
// credit, and the error is returned; once the row can be written the same
// decision settles the order.
func TestSettleTerminalOrderRollsBackWhenTheSettlementIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name     string
		exitCode int32
		kind     string
	}{
		{"credit", 0, settlementCredit},
		{"TEST refund", 1, settlementRefund},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newRefundDatabase(t)
			h, _ := newDisabledHandler(t, db, true, true)
			seedTESTOrder(t, db, models.Outstanding)
			if _, err := db.ExecContext(t.Context(), `CREATE TRIGGER refuse_settlement BEFORE INSERT ON order_settlements
BEGIN SELECT RAISE(ABORT, 'settlement refused'); END;`); err != nil {
				t.Fatal(err)
			}

			err := h.SettleTerminalOrder(t.Context(), testDebuglet(), tc.exitCode)
			if err == nil || !strings.Contains(err.Error(), "settlement refused") {
				t.Fatalf("SettleTerminalOrder = %v, want the refused settlement", err)
			}
			if got := orderState(t, db); got != models.Outstanding {
				t.Fatalf("order state %v after a refused settlement, want %v", got, models.Outstanding)
			}
			if got := totalIncome(t, db); got != 0 {
				t.Fatalf("total income %d after a refused settlement", got)
			}
			var earnings int
			if err := db.QueryRow("SELECT COUNT(*) FROM earnings").Scan(&earnings); err != nil || earnings != 0 {
				t.Fatalf("%d earnings rows after a refused settlement (%v)", earnings, err)
			}
			if n, _ := settlementOf(t, db); n != 0 {
				t.Fatalf("%d settlement rows after a refused settlement", n)
			}

			if _, err := db.ExecContext(t.Context(), "DROP TRIGGER refuse_settlement"); err != nil {
				t.Fatal(err)
			}
			if err := h.SettleTerminalOrder(t.Context(), testDebuglet(), tc.exitCode); err != nil {
				t.Fatalf("settlement after the refusal ended: %v", err)
			}
			assertSettledOnce(t, db, tc.kind)
		})
	}
}

// A settlement row is never changed or removed.
func TestOrderSettlementIsImmutable(t *testing.T) {
	db := newRefundDatabase(t)
	h, _ := newDisabledHandler(t, db, true, true)
	seedTESTOrder(t, db, models.Outstanding)
	if err := h.SettleTerminalOrder(t.Context(), testDebuglet(), 0); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"UPDATE order_settlements SET kind = 'refund'",
		"UPDATE order_settlements SET amount = 0",
		"DELETE FROM order_settlements",
	} {
		if _, err := db.ExecContext(t.Context(), statement); err == nil || !strings.Contains(err.Error(), "order settlement is immutable") {
			t.Fatalf("%s = %v, want it refused", statement, err)
		}
	}
	assertSettledOnce(t, db, settlementCredit)
}

// An order in a state other than Outstanding, Credited or Refunded is not
// settled and the state is reported.
func TestSettleTerminalOrderRefusesAnUnsettleableState(t *testing.T) {
	db := newRefundDatabase(t)
	h, _ := newDisabledHandler(t, db, true, true)
	seedTESTOrder(t, db, models.Aborted)

	err := h.SettleTerminalOrder(t.Context(), testDebuglet(), 0)
	if err == nil || !strings.Contains(err.Error(), "cannot settle order") {
		t.Fatalf("SettleTerminalOrder(aborted order) = %v", err)
	}
	if n, _ := settlementOf(t, db); n != 0 || orderState(t, db) != models.Aborted || totalIncome(t, db) != 0 {
		t.Fatalf("an aborted order was settled: %d rows, state %v", n, orderState(t, db))
	}
}

// seedFailedUSDCRun stores a paid USDC order whose claimed run exited with code
// 3, as the terminal path leaves it before the order is settled.
func seedFailedUSDCRun(t *testing.T, db *sql.DB) database.Debuglet {
	t.Helper()
	ctx := t.Context()
	q := database.New(db)
	if _, err := q.CreateTransaction(ctx, database.CreateTransactionParams{
		ID: testTxID, Price: testPrice, Currency: "USDC", Method: "USDC",
		ExpiresAt: models.NewUTCTime(time.Now().Add(time.Hour)), Status: int64(models.Paid), Hash: testHash,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateDebugletOrder(ctx, database.CreateDebugletOrderParams{
		TransactionID: testTxID, OrderID: testOrderID, ExecutorID: testExecutor, Price: testPrice,
		Currency: "USDC", RefundAddress: testRefund, State: int64(models.Outstanding),
	}); err != nil {
		t.Fatal(err)
	}
	run, err := q.CreateDebuglet(ctx, database.CreateDebugletParams{
		Uuid: uuid.New(), StartTime: models.NewUTCTime(time.Now()), EndTime: models.NewUTCTime(time.Now()),
		ExecutorID: testExecutor, State: models.RunStateExited, TransactionID: testTxID, OrderID: testOrderID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RecordMeasurementTerminal(ctx, database.RecordMeasurementTerminalParams{
		DebugletID: run.ID, ExitCode: sql.NullInt64{Int64: 3, Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE debuglet_order SET debuglet_id = ? WHERE transaction_id = ? AND order_id = ?",
		run.ID, testTxID, testOrderID); err != nil {
		t.Fatal(err)
	}
	return run
}

// While chain payments are disabled a settlement pass defers a chain order
// without reaching the chain backend and leaves it Outstanding.
func TestSettlementPassDefersChainOrdersWhileDisabled(t *testing.T) {
	db := newRefundDatabase(t)
	h, rec := newDisabledHandler(t, db, true, true)
	seedFailedUSDCRun(t, db)
	settled, failed, deferred, next, err := h.SettlePendingOrders(t.Context(), 0, 32)
	if settled != 0 || failed != 0 || deferred != 1 || next != 0 || err != nil {
		t.Fatalf("pass: settled %d, failed %d, deferred %d, next %d, error %v", settled, failed, deferred, next, err)
	}
	if calls := rec.chain.Calls(); len(calls) != 0 {
		t.Fatalf("chain backend calls %v while disabled", calls)
	}
	if got := orderState(t, db); got != models.Outstanding {
		t.Fatalf("order state %v, want %v", got, models.Outstanding)
	}
}

func TestSettlementPassDefersCancelledChainOrderWhileDisabled(t *testing.T) {
	db := newRefundDatabase(t)
	h, rec := newDisabledHandler(t, db, true, true)
	seedCancelledUSDCRun(t, db)
	settled, failed, deferred, _, err := h.SettlePendingOrders(t.Context(), 0, 32)
	if settled != 0 || failed != 0 || deferred != 1 || err != nil {
		t.Fatalf("disabled pass: settled %d, failed %d, deferred %d, error %v", settled, failed, deferred, err)
	}
	if orderState(t, db) != models.Outstanding || len(rec.chain.Calls()) != 0 {
		t.Fatal("disabled pass settled or reached the chain")
	}
}
