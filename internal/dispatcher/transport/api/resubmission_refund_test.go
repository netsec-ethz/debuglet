// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// A submission refused because some of its orders already carry runs keeps
// the payment. Those runs may be executing or credited to their executor, so
// refunding the transaction would pay for the same work twice. TEST orders
// cannot be refunded at all, so the refund is observed as its attempt.
func TestSubmissionOfAPartlyAdmittedBatchKeepsThePayment(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	f := newMaintenanceFixtureLogged(t, zap.New(core), LocalDevelopment(true))
	const transactionID, authKey = "partly-admitted", "auth-key"
	wasm := base64.StdEncoding.EncodeToString([]byte("\x00asm\x01\x00\x00\x00"))
	policy := DebugletPolicyRequest{FloorBW: 1000, CeilBW: 1000, TimeoutMS: 1000, Addresses: []string{"127.0.0.1"}}
	batch := []DebugletRequest{
		{OrderID: 1, ExecutorID: "no-such-executor", Wasm: wasm, Policy: policy},
		{OrderID: 2, ExecutorID: "no-such-executor", Wasm: wasm, Policy: policy},
	}
	f.seedOrder(transactionID, authKey, batch, models.Paid)
	ctx := context.Background()
	queries := database.New(f.db)
	if _, err := queries.CreateDebugletOrder(ctx, database.CreateDebugletOrderParams{
		TransactionID: transactionID, OrderID: 2, ExecutorID: "no-such-executor", Price: 1000,
		Currency: "TEST", RefundAddress: "", State: int64(models.Outstanding),
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	run, err := queries.CreateDebuglet(ctx, database.CreateDebugletParams{
		Uuid: uuid.New(), StartTime: models.NewUTCTime(now), EndTime: models.NewUTCTime(now.Add(time.Second)),
		Usage: 1000, CeilBw: 1000, ExecutorID: "no-such-executor",
		State: models.RunStateStarted, TransactionID: transactionID, OrderID: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := queries.ClaimDebugletOrder(ctx, database.ClaimDebugletOrderParams{
		DebugletID: sql.NullInt64{Int64: run.ID, Valid: true}, TransactionID: transactionID, OrderID: 1,
	}); err != nil || claimed != 1 {
		t.Fatalf("claim order 1 = (%d, %v)", claimed, err)
	}

	status, refusal := f.put("/debuglet", SubmitDebugletsRequest{TransactionId: transactionID, AuthKey: authKey, Debuglets: batch})
	if status < http.StatusBadRequest {
		t.Fatalf("status %d (%+v), want a refusal", status, refusal)
	}
	if attempts := logs.FilterMessage("Failed to refund transaction").Len(); attempts != 0 {
		t.Fatalf("the refusal attempted %d refunds of a partly admitted batch", attempts)
	}
	tx, err := queries.GetTransactionByID(ctx, transactionID)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != int64(models.Paid) {
		t.Fatalf("transaction status %d after the refusal, want Paid (%d)", tx.Status, models.Paid)
	}
	orders, err := queries.GetTransactionOrders(ctx, transactionID)
	if err != nil {
		t.Fatal(err)
	}
	for _, order := range orders {
		if order.State != int64(models.Outstanding) {
			t.Fatalf("order %d state %d after the refusal, want Outstanding", order.OrderID, order.State)
		}
	}
}
