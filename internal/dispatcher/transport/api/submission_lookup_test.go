// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

// A failed database read says nothing about the supplied credentials. Exercise
// the real SQLite lookup, including a request canceled after its body arrived,
// without admitting work or changing the paid order.
func TestSubmissionTransactionLookupFailures(t *testing.T) {
	for _, kind := range []string{"canceled", "deadline", "database failure", "missing transaction", "wrong key"} {
		t.Run(kind, func(t *testing.T) {
			f := newMaintenanceFixture(t)
			batch := maintenanceBatch()
			f.seedOrder(modeChainTxID, modeChainAuthKey, batch, models.Paid)
			submission := SubmitDebugletsRequest{
				TransactionId: modeChainTxID, AuthKey: modeChainAuthKey, Debuglets: batch,
			}
			ctx := t.Context()
			status, code, message := http.StatusInternalServerError, CodeInternal, "failed to read transaction"
			switch kind {
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			case "database failure":
				if _, err := f.db.Exec("ALTER TABLE transactions RENAME TO unavailable_transactions"); err != nil {
					t.Fatal(err)
				}
			case "missing transaction":
				submission.TransactionId = "missing-transaction"
				status, code, message = http.StatusUnauthorized, CodeUnauthorized, "unknown transaction or wrong auth key"
			case "wrong key":
				submission.AuthKey = "wrong-private-key"
				status, code, message = http.StatusUnauthorized, CodeUnauthorized, "unknown transaction or wrong auth key"
			}
			body, err := json.Marshal(submission)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPut, "/debuglet", bytes.NewReader(body)).WithContext(ctx)
			request.Header.Set("Content-Type", "application/json")
			answer := httptest.NewRecorder()
			f.server.Config.Handler.ServeHTTP(answer, request)
			assertEnvelope(t, kind, answer, status, code, message)

			if kind == "database failure" {
				if _, err := f.db.Exec("ALTER TABLE unavailable_transactions RENAME TO transactions"); err != nil {
					t.Fatal(err)
				}
			}
			if got := f.count("debuglets"); got != 0 {
				t.Fatalf("failed lookup admitted %d runs", got)
			}
			transaction, err := f.d.Payment.GetTransaction(t.Context(), modeChainTxID)
			if err != nil {
				t.Fatal(err)
			}
			if transaction.Status != int64(models.Paid) {
				t.Fatalf("failed lookup changed paid transaction to %d", transaction.Status)
			}
			var orderState int64
			if err := f.db.QueryRow("SELECT state FROM debuglet_order WHERE transaction_id = ?", modeChainTxID).Scan(&orderState); err != nil {
				t.Fatal(err)
			}
			if orderState != int64(models.Outstanding) {
				t.Fatalf("failed lookup changed unadmitted order to %d", orderState)
			}
		})
	}
}
