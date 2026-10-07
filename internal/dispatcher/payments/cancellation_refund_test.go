// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

// seedCancelledUSDCRun replaces the fixture's execution observation with a
// recorded dispatcher cancellation, as an unbound cancellation leaves it.
func seedCancelledUSDCRun(t *testing.T, db *sql.DB) database.Debuglet {
	t.Helper()
	run := seedFailedUSDCRun(t, db)
	if _, err := db.Exec("DELETE FROM measurement_execution WHERE debuglet_id=?", run.ID); err != nil {
		t.Fatal(err)
	}
	q := database.New(db)
	if err := q.CreateCancellation(t.Context(), database.CreateCancellationParams{
		DebugletID: run.ID, RequestID: "cancel-request", Reason: "cancelled", RequestedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.RecordCancellationTerminal(t.Context(), database.RecordCancellationTerminalParams{
		DebugletID: run.ID, TerminalRecordedAt: sql.NullInt64{Int64: 2, Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	return run
}

func TestCancellationRefundRecoversBeforeReservation(t *testing.T) {
	for _, failure := range []string{"preparation", "reservation"} {
		t.Run(failure, func(t *testing.T) {
			r := newRehearsal(t, false, false)
			run := seedCancelledUSDCRun(t, r.db)
			r.chain.onPrepare = func() { creditEarning(t, r.db, testExecutor, 0) }
			r.chain.onExecute = func() {
				creditEarning(t, r.db, testExecutor, 0)
				if row := onlyTransfer(t, r.db); row.State != transferReserved || orderState(t, r.db) != models.Refunded {
					t.Errorf("execution preceded reservation: %+v", row)
				}
			}
			if failure == "preparation" {
				r.chain.transferErr = errors.New("preparation unavailable")
			} else {
				r.exec(`CREATE TRIGGER refuse_transfer BEFORE INSERT ON chain_transfers
BEGIN SELECT RAISE(ABORT, 'reservation unavailable'); END`)
			}
			if err := r.h.SettleTerminalOrder(r.ctx(), &run, -1); err == nil {
				t.Fatal("inline refund succeeded despite failure")
			}
			if orderState(t, r.db) != models.Outstanding || len(transferRows(t, r.db)) != 0 {
				t.Fatal("failed reservation changed the order or retained a transfer")
			}
			if n, _ := settlementOf(t, r.db); n != 0 || count(r.chain.Calls(), "ExecuteTransfer") != 0 {
				t.Fatal("failed reservation settled or sent a refund")
			}
			r.restart()
			r.chain.transferErr = nil
			r.exec("DROP TRIGGER IF EXISTS refuse_transfer")
			for _, want := range []int{1, 0} {
				settled, failed, deferred, _, err := r.h.SettlePendingOrders(r.ctx(), 0, 32)
				if settled != want || failed != 0 || deferred != 0 || err != nil {
					t.Fatalf("recovery: settled %d, failed %d, deferred %d, error %v; want %d", settled, failed, deferred, err, want)
				}
				r.restart()
			}
			if row := onlyTransfer(t, r.db); row.State != transferSent || row.Amount != testPrice || row.Receiver != testRefund {
				t.Fatalf("refund: %+v", row)
			}
			if n, row := settlementOf(t, r.db); n != 1 || row.Kind != settlementRefund || orderState(t, r.db) != models.Refunded {
				t.Fatalf("settlements %d, row %+v", n, row)
			}
			if count(r.chain.Calls(), "ExecuteTransfer") != 1 {
				t.Fatalf("refund sent more than once: %v", r.chain.Calls())
			}
			if observed, err := database.New(r.db).GetMeasurementExecution(r.ctx(), run.ID); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("refund created an execution observation: %+v, %v", observed, err)
			}
		})
	}
}
