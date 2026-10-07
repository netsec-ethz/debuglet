// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

func TestSettlementMetricsFollowDurableObligationsWhileDisabled(t *testing.T) {
	for _, cancellation := range []bool{false, true} {
		t.Run(map[bool]string{false: "reported_exit", true: "recorded_cancellation"}[cancellation], func(t *testing.T) {
			db := newRefundDatabase(t)
			h, rec := newDisabledHandler(t, db, true, true)
			if got := h.CollectMetrics(t.Context()); got != (SettlementMetrics{}) {
				t.Fatalf("empty: %+v", got)
			}
			var run database.Debuglet
			if cancellation {
				run = seedCancelledUSDCRun(t, db)
			} else {
				run = seedFailedUSDCRun(t, db)
			}
			pending, err := database.New(db).ListPendingSettlements(t.Context(), database.ListPendingSettlementsParams{
				OutstandingState: int64(models.Outstanding), ExitedState: models.RunStateExited, RowLimit: 100,
			})
			if err != nil || len(pending) != 1 {
				t.Fatalf("settlement owner: %v, %v", pending, err)
			}
			if got := h.CollectMetrics(t.Context()); got != (SettlementMetrics{PendingRefund: 1}) {
				t.Fatalf("refund: %+v", got)
			}
			if !cancellation {
				if _, err := db.Exec("UPDATE measurement_execution SET exit_code=0 WHERE debuglet_id=?", run.ID); err != nil {
					t.Fatal(err)
				}
				if got := h.CollectMetrics(t.Context()); got != (SettlementMetrics{PendingCredit: 1}) {
					t.Fatalf("credit: %+v", got)
				}
			}
			// Once a refund reservation exists the sweep must no longer own it,
			// including failed/uncertain outcomes and a transaction-wide refund.
			for _, state := range []string{transferReserved, transferSent, transferUnknown, transferFailed, transferConfirmed} {
				if _, err := db.Exec("DELETE FROM chain_transfers"); err != nil {
					t.Fatal(err)
				}
				metricsTransfer(t, db, transferRefund, testTxID, state)
				got := h.CollectMetrics(t.Context())
				want := SettlementMetrics{}
				switch state {
				case transferReserved:
					want.Reserved = 1
				case transferSent:
					want.Sent = 1
				case transferUnknown:
					want.Unknown = 1
				case transferFailed:
					want.Failed = 1
				}
				if got != want {
					t.Fatalf("%s: %+v, want %+v", state, got, want)
				}
			}
			// Deleting the transfer returns ownership to the pending sweep.
			// Settle locally in TEST and observe the actual durable transition.
			if _, err := db.Exec("DELETE FROM chain_transfers"); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("UPDATE debuglet_order SET currency='TEST'"); err != nil {
				t.Fatal(err)
			}
			settled, failed, deferred, _, err := h.SettlePendingOrders(t.Context(), 0, 100)
			if err != nil || settled != 1 || failed != 0 || deferred != 0 {
				t.Fatalf("settle: %d %d %d %v", settled, failed, deferred, err)
			}
			if got := h.CollectMetrics(t.Context()); got != (SettlementMetrics{}) {
				t.Fatalf("settled order remains pending: %+v", got)
			}
			if calls := rec.chain.Calls(); len(calls) != 0 {
				t.Fatalf("metrics reached chain: %v", calls)
			}
		})

	}
}

func metricsTransfer(t *testing.T, db *sql.DB, kind, transaction, state string) {
	t.Helper()
	_, err := database.New(db).InsertChainTransfer(t.Context(), database.InsertChainTransferParams{
		Kind: kind, TransactionID: transaction, Amount: 1, Currency: "USDC", Receiver: "not-read-by-metrics", State: state,
		CreatedAt: models.NewUTCTime(time.Now()), UpdatedAt: models.NewUTCTime(time.Now()), SignedTransaction: []byte{},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSettlementMetricsOmitIncompleteCounts(t *testing.T) {
	db := newRefundDatabase(t)
	h, _ := newDisabledHandler(t, db, true, true)
	seedCancelledUSDCRun(t, db)
	_, err := db.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?)
		INSERT INTO chain_transfers(kind, amount, currency, receiver, state, created_at, updated_at)
		SELECT 'payout',1,'USDC','','reserved',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM n`, metricsRowLimit+1)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.CollectMetrics(t.Context()); got != (SettlementMetrics{Unavailable: "limit"}) {
		t.Fatalf("partial total: %+v", got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := h.CollectMetrics(ctx); got != (SettlementMetrics{Unavailable: "storage"}) {
		t.Fatalf("cancelled query: %+v", got)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if got := h.CollectMetrics(t.Context()); got != (SettlementMetrics{Unavailable: "storage"}) {
		t.Fatalf("closed storage: %+v", got)
	}
}
