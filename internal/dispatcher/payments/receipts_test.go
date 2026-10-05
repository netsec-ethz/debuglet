// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
)

// receiptFixture is a real database with one outstanding USDC transaction of
// testPrice, payable to enabledConfig's address "0xdead".
func receiptFixture(t *testing.T, method string, status models.TransactionState) (*sql.DB, *PaymentHandler) {
	t.Helper()
	db := newRefundDatabase(t)
	h, _ := newEnabledHandler(t, db, enabledConfig(t))
	if _, err := database.New(db).CreateTransaction(t.Context(), database.CreateTransactionParams{
		ID: testTxID, AuthKey: "key", Price: testPrice, Currency: method, Method: method,
		ExpiresAt: models.NewUTCTime(time.Now().Add(time.Hour)), Status: int64(status), Hash: testHash,
	}); err != nil {
		t.Fatal(err)
	}
	return db, h
}

// validReceipt pays testTxID exactly, written as the chain reports it: the
// coin type's package address without 0x and the receiver at full length.
func validReceipt(digest string) sui.PaymentReceipt {
	return sui.PaymentReceipt{
		Digest:     digest,
		Nonce:      testTxID,
		Amount:     uint64(testPrice),
		CoinType:   sui.GetCoinType("USDC", "testnet")[2:],
		Receiver:   "0x000000000000000000000000000000000000000000000000000000000000DEAD",
		Timestamp:  time.Now(),
		Checkpoint: 12,
	}
}

func applyReceipt(t *testing.T, h *PaymentHandler, r sui.PaymentReceipt) sui.ReceiptDisposition {
	t.Helper()
	disposition, err := h.ApplyPaymentReceipt(t.Context(), r)
	if err != nil {
		t.Fatalf("ApplyPaymentReceipt(%s): %v", r.Digest, err)
	}
	return disposition
}

func transactionStatus(t *testing.T, db *sql.DB) models.TransactionState {
	t.Helper()
	transaction, err := database.New(db).GetTransactionByID(t.Context(), testTxID)
	if err != nil {
		t.Fatal(err)
	}
	return models.TransactionState(transaction.Status)
}

func storedReceipt(t *testing.T, db *sql.DB, digest, nonce string) database.PaymentReceipt {
	t.Helper()
	row, err := database.New(db).GetPaymentReceipt(t.Context(), database.GetPaymentReceiptParams{TxDigest: digest, Nonce: nonce})
	if err != nil {
		t.Fatalf("receipt %s/%s: %v", digest, nonce, err)
	}
	return row
}

func TestApplyPaymentReceiptPaysOnce(t *testing.T) {
	db, h := receiptFixture(t, "USDC", models.Outstanding)

	if got := applyReceipt(t, h, validReceipt("d1")); got != sui.ReceiptApplied {
		t.Fatalf("first receipt %q", got)
	}
	if transactionStatus(t, db) != models.Paid {
		t.Fatal("applied receipt left the transaction unpaid")
	}
	row := storedReceipt(t, db, "d1", testTxID)
	if row.Disposition != "applied" || row.Amount != "7" || row.Checkpoint != (sql.NullInt64{Int64: 12, Valid: true}) || row.ObservedAt.IsZero() {
		t.Fatalf("applied row %+v", row)
	}
	// The same receipt again, as after a restart: recognized, not reapplied.
	if got := applyReceipt(t, h, validReceipt("d1")); got != sui.ReceiptDuplicate {
		t.Fatalf("repeated receipt %q", got)
	}
	// A second payment by another chain transaction does not pay twice.
	if got := applyReceipt(t, h, validReceipt("d2")); got != sui.ReceiptMismatch {
		t.Fatalf("second payment %q", got)
	}
	if row := storedReceipt(t, db, "d2", testTxID); row.Disposition != "mismatch" || row.Detail != "already paid by d1" {
		t.Fatalf("second payment row %+v", row)
	}
	// A recorded mismatch keeps its disposition when seen again.
	if got := applyReceipt(t, h, validReceipt("d2")); got != sui.ReceiptMismatch {
		t.Fatalf("repeated mismatch %q", got)
	}
	rows, err := database.New(db).ListPaymentReceiptsByNonce(t.Context(), testTxID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("receipt rows %+v, %v", rows, err)
	}
}

func TestApplyPaymentReceiptRecordsRejections(t *testing.T) {
	expired := validReceipt("d1")
	expired.Timestamp = time.Now().Add(2 * time.Hour)
	cases := []struct {
		name        string
		method      string
		status      models.TransactionState
		edit        func(r *sui.PaymentReceipt)
		disposition sui.ReceiptDisposition
		detail      string
		amount      string
	}{
		{"amount", "USDC", models.Outstanding, func(r *sui.PaymentReceipt) { r.Amount++ }, sui.ReceiptMismatch, "amount", "8"},
		{"amount beyond int64", "USDC", models.Outstanding, func(r *sui.PaymentReceipt) { r.Amount = math.MaxUint64 }, sui.ReceiptMismatch, "amount", "18446744073709551615"},
		{"coin type", "USDC", models.Outstanding, func(r *sui.PaymentReceipt) { r.CoinType = "0x2::sui::SUI" }, sui.ReceiptMismatch, "coin type", "7"},
		{"receiver", "USDC", models.Outstanding, func(r *sui.PaymentReceipt) { r.Receiver = "0xbeef" }, sui.ReceiptMismatch, "receiver", "7"},
		{"expired", "USDC", models.Outstanding, func(r *sui.PaymentReceipt) { *r = expired }, sui.ReceiptExpired, "", "7"},
		{"TEST method", "TEST", models.Outstanding, func(*sui.PaymentReceipt) {}, sui.ReceiptMismatch, "method", "7"},
		{"refunded transaction", "USDC", models.Refunded, func(*sui.PaymentReceipt) {}, sui.ReceiptMismatch, "transaction not outstanding", "7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, h := receiptFixture(t, tc.method, tc.status)
			r := validReceipt("d1")
			tc.edit(&r)
			if got := applyReceipt(t, h, r); got != tc.disposition {
				t.Fatalf("disposition %q, want %q", got, tc.disposition)
			}
			if transactionStatus(t, db) != tc.status {
				t.Fatal("rejected receipt changed the transaction")
			}
			row := storedReceipt(t, db, "d1", testTxID)
			if row.Disposition != string(tc.disposition) || row.Detail != tc.detail || row.Amount != tc.amount {
				t.Fatalf("row %+v", row)
			}
		})
	}
}

func TestApplyPaymentReceiptUnknownNonce(t *testing.T) {
	db, h := receiptFixture(t, "USDC", models.Outstanding)
	r := validReceipt("d1")
	r.Nonce = "unknown"
	if got := applyReceipt(t, h, r); got != sui.ReceiptUnknownIntent {
		t.Fatalf("unknown nonce to our address %q", got)
	}
	storedReceipt(t, db, "d1", "unknown")

	// Another payee's receipt is not ours and is not recorded.
	r.Digest, r.Receiver = "d2", "0xbeef"
	if got := applyReceipt(t, h, r); got != "" {
		t.Fatalf("receipt to another address %q", got)
	}
	if _, err := database.New(db).GetPaymentReceipt(t.Context(), database.GetPaymentReceiptParams{TxDigest: "d2", Nonce: "unknown"}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign receipt recorded: %v", err)
	}
}

func TestApplyPaymentReceiptDisabled(t *testing.T) {
	db := newRefundDatabase(t)
	h, _ := newDisabledHandler(t, db, true, false)
	_, err := h.ApplyPaymentReceipt(context.Background(), validReceipt("d1"))
	if !errors.Is(err, ErrPaymentsDisabled) {
		t.Fatalf("disabled mode: %v", err)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM payment_receipts").Scan(&n); err != nil || n != 0 {
		t.Fatalf("disabled mode recorded %d receipts: %v", n, err)
	}
}
