// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"go.uber.org/zap"
)

// allowanceFixture is a real database with an allowance-enabled payment
// handler, an account and an operator account.
func allowanceFixture(t *testing.T) (*sql.DB, *PaymentHandler, uuid.UUID, uuid.UUID) {
	t.Helper()
	db := newRefundDatabase(t)
	h := allowanceHandler(t, db)
	account, operator := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{account, operator} {
		if _, err := database.New(db).CreateUser(t.Context(), database.CreateUserParams{Uuid: id, Name: id.String()}); err != nil {
			t.Fatal(err)
		}
	}
	return db, h, account, operator
}

func allowanceHandler(t *testing.T, db *sql.DB) *PaymentHandler {
	t.Helper()
	cfg := disabledConfig(t, false)
	cfg.Allowance.Enabled = true
	return NewPaymentHandler(db, cfg, zap.NewNop())
}

// reserveIntent creates an account's TEST intent of one order of price the
// way PUT /payment/intent does: the transaction, its order and its owner in
// one SQL transaction, which a refusal commits for the release it made.
func reserveIntent(t *testing.T, h *PaymentHandler, db *sql.DB, account uuid.UUID, txID string, price int64) error {
	t.Helper()
	ctx := t.Context()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := h.CreateAllowanceIntentIn(tx, account, txID, price, testHash, ctx); err != nil {
		var exceeded *AllowanceExceededError
		if errors.As(err, &exceeded) {
			if commitErr := tx.Commit(); commitErr != nil {
				return commitErr
			}
		}
		return err
	}
	q := database.New(tx)
	if _, err := q.CreateDebugletOrder(ctx, database.CreateDebugletOrderParams{
		TransactionID: txID, OrderID: testOrderID, ExecutorID: testExecutor, Price: price,
		Currency: "TEST", RefundAddress: testRefund, State: int64(models.Outstanding),
	}); err != nil {
		return err
	}
	if err := q.SetTransactionOwner(ctx, database.SetTransactionOwnerParams{TransactionID: txID, Uuid: account}); err != nil {
		return err
	}
	return tx.Commit()
}

func mustGrant(t *testing.T, h *PaymentHandler, account, operator uuid.UUID, amount int64, key string) {
	t.Helper()
	if _, err := h.GrantAllowance(t.Context(), account, operator, amount, "trial", key); err != nil {
		t.Fatalf("grant %d: %v", amount, err)
	}
}

func assertAllowance(t *testing.T, h *PaymentHandler, account uuid.UUID, want Allowance) {
	t.Helper()
	got, err := h.Allowance(t.Context(), account)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("allowance %+v, want %+v", got, want)
	}
}

func expireIntent(t *testing.T, db *sql.DB, txID string) {
	t.Helper()
	if _, err := db.Exec("UPDATE transactions SET expires_at = ? WHERE id = ?", models.NewUTCTime(time.Now().Add(-time.Hour)), txID); err != nil {
		t.Fatal(err)
	}
}

// An intent within the remaining allowance is reserved; one beyond it is
// refused with what remains and what it needs, and writes no transaction.
func TestAllowanceReservesWithinGrantsAndRefusesBeyond(t *testing.T) {
	db, h, account, operator := allowanceFixture(t)
	if err := reserveIntent(t, h, db, account, "tx-none", 1); !errors.As(err, new(*AllowanceExceededError)) {
		t.Fatalf("intent without a grant: %v", err)
	}
	mustGrant(t, h, account, operator, 10, "first")
	if err := reserveIntent(t, h, db, account, testTxID, testPrice); err != nil {
		t.Fatal(err)
	}
	assertAllowance(t, h, account, Allowance{Granted: 10, Reserved: testPrice})
	var exceeded *AllowanceExceededError
	if err := reserveIntent(t, h, db, account, "tx-2", testPrice); !errors.As(err, &exceeded) || exceeded.Remaining != 3 || exceeded.Required != testPrice {
		t.Fatalf("intent beyond the allowance: %v", err)
	}
	for _, id := range []string{"tx-none", "tx-2"} {
		if _, err := database.New(db).GetTransactionByID(t.Context(), id); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("refused intent %s left a transaction: %v", id, err)
		}
	}
	assertAllowance(t, h, account, Allowance{Granted: 10, Reserved: testPrice})
}

// A run with a known outcome consumes its order whichever way it settled: a
// credit and a refund both move the price from reserved to consumed, so a run
// cannot fail on purpose and spend its grant again.
func TestAllowanceConsumptionFollowsTheSettlement(t *testing.T) {
	for _, exit := range []int32{0, 1} {
		t.Run(fmt.Sprint("exit ", exit), func(t *testing.T) {
			db, h, account, operator := allowanceFixture(t)
			mustGrant(t, h, account, operator, 10, "first")
			if err := reserveIntent(t, h, db, account, testTxID, testPrice); err != nil {
				t.Fatal(err)
			}
			if claimed, err := claimRefundOrder(t.Context(), db); err != nil || !claimed {
				t.Fatalf("claim: %t, %v", claimed, err)
			}
			assertAllowance(t, h, account, Allowance{Granted: 10, Reserved: testPrice})
			if err := h.SettleTerminalOrder(t.Context(), testDebuglet(), exit); err != nil {
				t.Fatal(err)
			}
			want := models.Credited
			if exit != 0 {
				want = models.Refunded
			}
			if got := orderState(t, db); got != want {
				t.Fatalf("order %v, want %v", got, want)
			}
			assertAllowance(t, h, account, Allowance{Granted: 10, Consumed: testPrice})
			if err := reserveIntent(t, h, db, account, "tx-2", testPrice); !errors.As(err, new(*AllowanceExceededError)) {
				t.Fatalf("a settled order returned its price to the allowance: %v", err)
			}
		})
	}
}

// An admitted run whose outcome is not known stays reserved, also after a
// restart, and an expired intent with admitted work is never released.
func TestAllowanceUnknownOutcomeStaysReservedAcrossRestart(t *testing.T) {
	db, h, account, operator := allowanceFixture(t)
	mustGrant(t, h, account, operator, 10, "first")
	if err := reserveIntent(t, h, db, account, testTxID, testPrice); err != nil {
		t.Fatal(err)
	}
	if claimed, err := claimRefundOrder(t.Context(), db); err != nil || !claimed {
		t.Fatalf("claim: %t, %v", claimed, err)
	}
	expireIntent(t, db, testTxID)

	var seq int64
	var name, path string
	if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restarted := allowanceHandler(t, reopened)
	assertAllowance(t, restarted, account, Allowance{Granted: 10, Reserved: testPrice})
	if err := reserveIntent(t, restarted, reopened, account, "tx-2", testPrice); !errors.As(err, new(*AllowanceExceededError)) {
		t.Fatalf("an admitted run of unknown outcome was released: %v", err)
	}
	if got := transactionStatus(t, reopened); got != models.Paid {
		t.Fatalf("admitted intent is %v, want paid", got)
	}
	assertAllowance(t, restarted, account, Allowance{Granted: 10, Reserved: testPrice})
}

// An unadmitted intent past its expiry is released by the account's next
// intent: its reservation returns to the allowance and it can no longer be
// admitted.
func TestAllowanceReleasesAnExpiredUnadmittedIntent(t *testing.T) {
	db, h, account, operator := allowanceFixture(t)
	mustGrant(t, h, account, operator, 10, "first")
	if err := reserveIntent(t, h, db, account, testTxID, testPrice); err != nil {
		t.Fatal(err)
	}
	expireIntent(t, db, testTxID)
	if err := reserveIntent(t, h, db, account, "tx-2", testPrice); err != nil {
		t.Fatalf("intent after the release: %v", err)
	}
	if got := transactionStatus(t, db); got != models.Expired {
		t.Fatalf("expired intent is %v, want expired", got)
	}
	if claimed, err := claimRefundOrder(t.Context(), db); err != nil || claimed {
		t.Fatalf("released intent was admitted: %t, %v", claimed, err)
	}
	assertAllowance(t, h, account, Allowance{Granted: 10, Reserved: testPrice})
}

// The release and an admission racing on two handles have one winner: either
// the run is admitted and the intent stays reserved, or the intent is released
// and the run is refused. The allowance is never overdrawn.
func TestAllowanceReleaseRacesAdmissionOnTwoHandles(t *testing.T) {
	for attempt := range 4 {
		t.Run(fmt.Sprint(attempt), func(t *testing.T) {
			db, h, account, operator := allowanceFixture(t)
			mustGrant(t, h, account, operator, testPrice, "first")
			if err := reserveIntent(t, h, db, account, testTxID, testPrice); err != nil {
				t.Fatal(err)
			}
			expireIntent(t, db, testTxID)
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
				func() error { return reserveIntent(t, h, db, account, "tx-2", testPrice) },
			})
			if errs[0] != nil {
				t.Fatalf("claim: %v", errs[0])
			}
			released := errs[1] == nil
			if errs[1] != nil && !errors.As(errs[1], new(*AllowanceExceededError)) {
				t.Fatalf("intent: %v", errs[1])
			}
			if claimed == released {
				t.Fatalf("need one winner: claimed=%t released=%t", claimed, released)
			}
			status := transactionStatus(t, db)
			if claimed && status != models.Paid || released && status != models.Expired {
				t.Fatalf("claimed=%t released=%t but the intent is %v", claimed, released, status)
			}
			assertAllowance(t, h, account, Allowance{Granted: testPrice, Reserved: testPrice})
		})
	}
}

// A grant is recorded once per idempotency key; the same key with another
// body is a conflict, an unknown account is reported and grants are immutable.
func TestAllowanceGrantIsIdempotentAndImmutable(t *testing.T) {
	db, h, account, operator := allowanceFixture(t)
	first, err := h.GrantAllowance(t.Context(), account, operator, 10, "trial", "key")
	if err != nil || !first.Created || first.Grant.Amount != 10 || first.Grant.GrantedBy != operator || first.Grant.Currency != AllowanceCurrency {
		t.Fatalf("first grant %+v, %v", first, err)
	}
	again, err := h.GrantAllowance(t.Context(), account, operator, 10, "trial", "key")
	if err != nil || again.Created || again.Grant != first.Grant || again.Allowance.Granted != 10 {
		t.Fatalf("repeated grant %+v, %v", again, err)
	}
	for _, change := range []struct {
		amount int64
		reason string
	}{{11, "trial"}, {10, "other"}} {
		if _, err := h.GrantAllowance(t.Context(), account, operator, change.amount, change.reason, "key"); !errors.Is(err, ErrGrantConflict) {
			t.Fatalf("grant with a changed body under the same key: %v", err)
		}
	}
	if _, err := h.GrantAllowance(t.Context(), uuid.New(), operator, 10, "trial", "key"); !errors.Is(err, ErrUnknownAccount) {
		t.Fatalf("grant to an unknown account: %v", err)
	}
	second, err := h.GrantAllowance(t.Context(), account, operator, 5, "more", "second")
	if err != nil || !second.Created || second.Allowance.Granted != 15 {
		t.Fatalf("second grant %+v, %v", second, err)
	}
	var rows int
	if err := db.QueryRow("SELECT COUNT(*) FROM allowance_grants").Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("%d grant rows, %v; want 2", rows, err)
	}
	if _, err := db.Exec("UPDATE allowance_grants SET amount = 1000"); err == nil {
		t.Fatal("a grant was changed")
	}
	if _, err := db.Exec("DELETE FROM allowance_grants"); err == nil {
		t.Fatal("a grant was removed")
	}
	assertAllowance(t, h, account, Allowance{Granted: 15})
}
