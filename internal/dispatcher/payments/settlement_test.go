// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"database/sql"
	"strings"
	"testing"

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
