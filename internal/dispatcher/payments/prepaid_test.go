// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func personalTopUp(t *testing.T, f communityPaymentFixture, key, purpose string, amount int64) sui.PaymentReceipt {
	t.Helper()
	tx, err := f.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	intent, err := f.handler.CreatePrepaidTopUpIn(t.Context(), tx, f.owner.Uuid, uuid.NewString(), key, purpose, amount, testRefund)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	r := validReceipt(uuid.NewString())
	r.Nonce = intent.Intent.(sui.SuiPaymentIntent).TransactionId
	r.Amount = uint64(amount)
	r.CoinType = sui.GetCoinType("SUI", "testnet")
	return r
}
func personalReserve(t *testing.T, f communityPaymentFixture, db *sql.DB, id string, prices ...int64) error {
	t.Helper()
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var total int64
	for _, p := range prices {
		total += p
	}
	if _, err = f.handler.CreatePersonalIntentIn(tx, f.owner.Uuid, id, total, "SUI", testHash, t.Context()); err != nil {
		return err
	}
	q := database.New(tx)
	for i, price := range prices {
		if _, err = q.CreateDebugletOrder(t.Context(), database.CreateDebugletOrderParams{TransactionID: id, OrderID: int64(i) + testOrderID, ExecutorID: testExecutor, Price: price, Currency: "SUI", State: int64(models.Outstanding)}); err != nil {
			return err
		}
	}
	if err = q.SetTransactionOwner(t.Context(), database.SetTransactionOwnerParams{TransactionID: id, Uuid: f.owner.Uuid}); err != nil {
		return err
	}
	return tx.Commit()
}
func assertPersonal(t *testing.T, f communityPaymentFixture, want CommunityBudget) {
	t.Helper()
	got, err := f.handler.PersonalBalance(t.Context(), f.db, f.owner.Uuid, "SUI")
	if err != nil || got != want {
		t.Fatalf("budget %+v want %+v: %v", got, want, err)
	}
}

func TestPersonalTopUpReceiptRestartAndIdempotency(t *testing.T) {
	f := newCommunityPaymentFixture(t)
	r := personalTopUp(t, f, "browser-retry", "personal", 10)
	again := personalTopUp(t, f, "browser-retry", "personal", 10)
	if r.Nonce != again.Nonce {
		t.Fatal("retry issued a second payable intent")
	}
	assertPersonal(t, f, CommunityBudget{})
	if got := applyReceipt(t, f.handler, r); got != sui.ReceiptApplied {
		t.Fatal(got)
	}
	h, _ := newEnabledHandler(t, f.db, f.handler.cfg)
	h.sui = f.chain
	f.handler = h
	if got := applyReceipt(t, f.handler, r); got != sui.ReceiptDuplicate {
		t.Fatal(got)
	}
	r.Digest = "second-payment"
	if got := applyReceipt(t, f.handler, r); got != sui.ReceiptMismatch {
		t.Fatal(got)
	}
	assertPersonal(t, f, CommunityBudget{Funded: 10, Available: 10})
	if err := f.handler.CheckCommunitySubmission(t.Context(), f.db, r.Nonce, f.owner.Uuid); !errors.Is(err, ErrCommunityDeposit) {
		t.Fatalf("deposit admitted: %v", err)
	}
	f.handler.cfg.Sui.Network = "mainnet"
	if _, err := f.handler.PersonalBalance(t.Context(), f.db, f.owner.Uuid, "SUI"); !errors.Is(err, ErrUnsupportedPaymentMethod) {
		t.Fatalf("Testnet credit usable on mainnet: %v", err)
	}
}
func TestPersonalConcurrentBatchesNeverOverspend(t *testing.T) {
	f := newCommunityPaymentFixture(t)
	applyReceipt(t, f.handler, personalTopUp(t, f, "deposit", "personal", 10))
	var seq int64
	var name, path string
	if err := f.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	other, err := sqlitedb.Open(path, sqlitedb.BusyTimeout(5000))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	results := raceCalls([]func() error{func() error { return personalReserve(t, f, f.db, "batch-a", 3, 4) }, func() error { return personalReserve(t, f, other, "batch-b", 3, 4) }})
	accepted := 0
	for _, err := range results {
		if err == nil {
			accepted++
		} else if !errors.As(err, new(*CommunityFundsError)) {
			t.Fatal(err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d batches: %v", accepted, results)
	}
	assertPersonal(t, f, CommunityBudget{Funded: 10, Reserved: 7, Available: 3})
	var orders int
	if err := f.db.QueryRow(`SELECT count(*) FROM debuglet_order`).Scan(&orders); err != nil || orders != 2 {
		t.Fatalf("partial failed batch: %d orders %v", orders, err)
	}
}
func TestPersonalRefundAndCreditAreAppliedOnce(t *testing.T) {
	for _, exit := range []int32{0, 1} {
		t.Run(string(rune('0'+exit)), func(t *testing.T) {
			f := newCommunityPaymentFixture(t)
			applyReceipt(t, f.handler, personalTopUp(t, f, "deposit", "personal", 10))
			if err := personalReserve(t, f, f.db, testTxID, testPrice); err != nil {
				t.Fatal(err)
			}
			if claimed, err := claimRefundOrder(t.Context(), f.db); err != nil || !claimed {
				t.Fatalf("claim: %t %v", claimed, err)
			}
			for range 2 {
				if err := f.handler.SettleTerminalOrder(t.Context(), testDebuglet(), exit); err != nil {
					t.Fatal(err)
				}
			}
			want := CommunityBudget{Funded: 10, Available: 10}
			if exit == 0 {
				want.Spent = testPrice
				want.Available -= testPrice
			}
			assertPersonal(t, f, want)
			if calls := f.chain.Calls(); len(calls) != 1 || calls[0] != "CreatePaymentIntent" {
				t.Fatalf("credit/refund sent coins: %v", calls)
			}
		})
	}
}
func TestPersonalUnadmittedRefundReturnsWholeBatch(t *testing.T) {
	f := newCommunityPaymentFixture(t)
	applyReceipt(t, f.handler, personalTopUp(t, f, "deposit", "personal", 10))
	if err := personalReserve(t, f, f.db, "batch", 3, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := f.handler.RefundUnadmittedTransaction("batch", t.Context()); err != nil {
		t.Fatal(err)
	}
	_, _ = f.handler.RefundUnadmittedTransaction("batch", t.Context())
	assertPersonal(t, f, CommunityBudget{Funded: 10, Available: 10})
}
