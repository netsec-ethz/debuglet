// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func admissionRefundFixture(t *testing.T, currency string) (*sql.DB, *PaymentHandler, *fakeChain) {
	t.Helper()
	db := newRefundDatabase(t)
	h, recorder := newEnabledHandler(t, db, enabledConfig(t))
	q := database.New(db)
	method := "SUI"
	if currency == "TEST" {
		method = "TEST"
	}
	if _, err := q.CreateTransaction(t.Context(), database.CreateTransactionParams{
		ID: testTxID, AuthKey: "key", Price: testPrice, Currency: currency, Method: method,
		ExpiresAt: models.NewUTCTime(time.Now().Add(time.Hour)), Status: int64(models.Paid), Hash: testHash,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateDebugletOrder(t.Context(), database.CreateDebugletOrderParams{
		TransactionID: testTxID, OrderID: testOrderID, ExecutorID: testExecutor, Price: testPrice,
		Currency: currency, RefundAddress: testRefund, State: int64(models.Outstanding),
	}); err != nil {
		t.Fatal(err)
	}
	return db, h, recorder.chain
}

// Keep the tentative run and its order claim in the same transaction, as
// admission does. A lost claim must leave no run behind.
func claimRefundOrder(ctx context.Context, db *sql.DB) (bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	q := database.New(tx)
	now := time.Now()
	run, err := q.CreateDebuglet(ctx, database.CreateDebugletParams{
		Uuid: uuid.New(), StartTime: models.NewUTCTime(now), EndTime: models.NewUTCTime(now.Add(time.Second)),
		Usage: 1000, CeilBw: 1000, ExecutorID: testExecutor, State: models.RunStateUploading,
		TransactionID: testTxID, OrderID: testOrderID,
	})
	if err != nil {
		return false, err
	}
	n, err := q.ClaimDebugletOrder(ctx, database.ClaimDebugletOrderParams{
		DebugletID: sql.NullInt64{Int64: run.ID, Valid: true}, TransactionID: testTxID, OrderID: testOrderID,
		OutstandingState: int64(models.Outstanding), PaidStatus: int64(models.Paid),
	})
	if err != nil || n != 1 {
		return false, err
	}
	err = tx.Commit()
	return err == nil, err
}

func TestUnadmittedRefundAndAdmissionHaveOneWinner(t *testing.T) {
	t.Run("admission before refusal refund", func(t *testing.T) {
		db, h, chain := admissionRefundFixture(t, "USDC")
		if claimed, err := claimRefundOrder(t.Context(), db); err != nil || !claimed {
			t.Fatalf("claim: %t, %v", claimed, err)
		}
		if err := h.RefundUnadmittedTransaction(testTxID, t.Context()); !errors.Is(err, ErrTransactionClaimed) {
			t.Fatalf("refund admitted work: %v", err)
		}
		if got := orderState(t, db); got != models.Outstanding || len(chain.Calls()) != 0 {
			t.Fatalf("refusal changed order %v or called chain: %v", got, chain.Calls())
		}
		// The separate, existing own-post-admission fallback keeps its policy.
		if err := h.RefundTransaction(testTxID, t.Context()); err != nil {
			t.Fatalf("transaction-wide fallback: %v", err)
		}
		if orderState(t, db) != models.Refunded || strings.Join(chain.Calls(), ",") != "PrepareTransfer,ExecuteTransfer" {
			t.Fatal("transaction-wide fallback changed")
		}
	})
	t.Run("refund before stale paid preflight", func(t *testing.T) {
		db, h, chain := admissionRefundFixture(t, "USDC")
		if err := h.RefundUnadmittedTransaction(testTxID, t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, latePayment := range []bool{false, true} {
			if latePayment {
				// A repeated payment notification must not revive a refunded order.
				if _, err := h.ApplyPaymentReceipt(t.Context(), sui.PaymentReceipt{Digest: "late-payment", Nonce: testTxID}); err != nil {
					t.Fatal(err)
				}
			}
			if claimed, err := claimRefundOrder(t.Context(), db); err != nil || claimed {
				t.Fatalf("claim refunded order: %t, %v", claimed, err)
			}
		}
		var runs int
		if err := db.QueryRow("SELECT COUNT(*) FROM debuglets").Scan(&runs); err != nil || runs != 0 {
			t.Fatalf("refused admission left %d runs: %v", runs, err)
		}
		if orderState(t, db) != models.Refunded || strings.Join(chain.Calls(), ",") != "PrepareTransfer,ExecuteTransfer" {
			t.Fatal("refund or spent order changed")
		}
	})
}

func TestUnadmittedRefundFailureLeavesIntentSpendable(t *testing.T) {
	for _, currency := range []string{"TEST", "USDC"} {
		t.Run(currency, func(t *testing.T) {
			db, h, chain := admissionRefundFixture(t, currency)
			chain.transferErr = errors.New("fixture refund rejected")
			if err := h.RefundUnadmittedTransaction(testTxID, t.Context()); err == nil {
				t.Fatal("unsupported or rejected refund succeeded")
			}
			transaction, err := database.New(db).GetTransactionByID(t.Context(), testTxID)
			if err != nil || transaction.Status != int64(models.Paid) || orderState(t, db) != models.Outstanding {
				t.Fatalf("refund failure changed paid intent: %+v, %v", transaction, err)
			}
			if currency == "TEST" && len(chain.Calls()) != 0 {
				t.Fatalf("TEST refund reached chain: %v", chain.Calls())
			}
			if claimed, err := claimRefundOrder(t.Context(), db); err != nil || !claimed {
				t.Fatalf("rolled-back intent no longer spendable: %t, %v", claimed, err)
			}
		})
	}
}

func TestUnadmittedRefundRacesAdmissionOnTwoHandles(t *testing.T) {
	for attempt := range 4 {
		t.Run(fmt.Sprint(attempt), func(t *testing.T) {
			db, h, chain := admissionRefundFixture(t, "USDC")
			var seq int64
			var name, path string
			if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
				t.Fatal(err)
			}
			other, err := sqlitedb.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = other.Close() })
			var claimed bool
			errs := raceCalls([]func() error{
				func() error {
					var err error
					claimed, err = claimRefundOrder(t.Context(), other)
					return err
				},
				func() error { return h.RefundUnadmittedTransaction(testTxID, t.Context()) },
			})
			for _, err := range errs {
				if err != nil && !errors.Is(err, ErrTransactionClaimed) && !strings.Contains(err.Error(), "database is locked") {
					t.Fatal(err)
				}
			}
			refunded := errs[1] == nil
			if claimed == refunded {
				t.Fatalf("need one winner: claimed=%t refunded=%t errors=%v", claimed, refunded, errs)
			}
			var runs int
			if err := db.QueryRow("SELECT COUNT(*) FROM debuglets").Scan(&runs); err != nil {
				t.Fatal(err)
			}
			if refunded {
				if runs != 0 || orderState(t, db) != models.Refunded || strings.Join(chain.Calls(), ",") != "PrepareTransfer,ExecuteTransfer" {
					t.Fatal("refund winner also admitted work or transferred twice")
				}
			} else if runs != 1 || orderState(t, db) != models.Outstanding || strings.Contains(strings.Join(chain.Calls(), ","), "ExecuteTransfer") {
				t.Fatal("admission winner was refunded or duplicated")
			}
		})
	}
}
