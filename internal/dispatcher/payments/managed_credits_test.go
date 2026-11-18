// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"database/sql"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func managedCreditFixture(t *testing.T, cap int64) (*sql.DB, *PaymentHandler, uuid.UUID, uuid.UUID) {
	t.Helper()
	db, h, account, operator := policyFixture(t, false)
	h.cfg.Allowance.PublicTrial = 0
	h.cfg.Allowance.BalanceCap = cap
	// Daily credit does not require a researcher or hosting approval record.
	if _, err := db.Exec(`DELETE FROM allowance_eligibility WHERE user_id=(SELECT id FROM users WHERE uuid=?)`, account); err != nil {
		t.Fatal(err)
	}
	return db, h, account, operator
}

func TestManagedCreditsDailyRolloverCatchupAndRestart(t *testing.T) {
	db, h, account, _ := managedCreditFixture(t, 250)
	now := time.Now().UTC()
	for _, step := range []struct {
		days            int
		credited, total int64
	}{{0, 100, 100}, {1, 100, 200}, {4, 50, 250}, {5, 0, 250}} {
		policy := applyPolicyAt(t, h, account, now.AddDate(0, 0, step.days))
		a, err := readAllowance(t.Context(), database.New(db), account)
		if err != nil || policy.Kind != "credits" || policy.Credited != step.credited || a.Granted != step.total {
			t.Fatalf("day %d: policy=%+v balance=%+v error=%v", step.days, policy, a, err)
		}
		if policy.DailyGrant != 100 || policy.BalanceCap != 250 || policy.Researcher || policy.NextReset == nil {
			t.Fatalf("policy=%+v", policy)
		}
	}
	consumePolicyCredit(t, db, h, account)
	restarted := allowanceHandler(t, db)
	restarted.cfg.Allowance = h.cfg.Allowance
	if got := applyPolicyAt(t, restarted, account, now.AddDate(0, 0, 5)); got.Credited != 0 {
		t.Fatalf("spending reopened the capped decision: %+v", got)
	}
	if got := applyPolicyAt(t, restarted, account, now.AddDate(0, 0, 6)); got.Credited != testPrice {
		t.Fatalf("next daily grant=%d, want %d", got.Credited, testPrice)
	}
}

func TestManagedCreditsReservationsRemainUnderCap(t *testing.T) {
	db, h, account, operator := managedCreditFixture(t, 200)
	mustGrant(t, h, account, operator, 190, "existing")
	now := time.Now().UTC()
	if p := applyPolicyAt(t, h, account, now); p.Credited != 10 {
		t.Fatalf("partial grant: %+v", p)
	}
	if err := reserveIntent(t, h, db, account, testTxID, 60); err != nil {
		t.Fatal(err)
	}
	if p := applyPolicyAt(t, h, account, now.AddDate(0, 0, 1)); p.Credited != 0 {
		t.Fatalf("reserved balance did not count toward cap: %+v", p)
	}
	expireIntent(t, db, testTxID)
	if err := reserveIntent(t, h, db, account, "after-release", 1); err != nil {
		t.Fatal(err)
	}
	a, err := readAllowance(t.Context(), database.New(db), account)
	if err != nil || a.Granted != 200 || a.Reserved != 1 {
		t.Fatalf("release changed total credit: %+v %v", a, err)
	}
}

func TestManagedCreditsConcurrentGrantAndAdmission(t *testing.T) {
	db, h, account, _ := managedCreditFixture(t, 150)
	var seq int64
	var name, path string
	if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	other, err := sqlitedb.Open(path, sqlitedb.BusyTimeout(5000))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	h2 := allowanceHandler(t, other)
	h2.cfg.Allowance = h.cfg.Allowance
	for _, err := range raceCalls([]func() error{
		func() error { _, err := h.Allowance(t.Context(), account); return err },
		func() error { return reserveIntent(t, h2, other, account, "credit-race", 60) },
	}) {
		if err != nil {
			t.Fatal(err)
		}
	}
	a, err := h.Allowance(t.Context(), account)
	if err != nil || a.Granted != 100 || a.Reserved != 60 {
		t.Fatalf("balance=%+v %v", a, err)
	}
	var periods int
	if err := db.QueryRow(`SELECT count(*) FROM allowance_periods WHERE period LIKE 'credits:%'`).Scan(&periods); err != nil || periods != 1 {
		t.Fatalf("daily decisions=%d %v", periods, err)
	}
}

func TestManagedCreditsNoRetroactiveOrOverflowingGrants(t *testing.T) {
	_, h, account, _ := managedCreditFixture(t, 200)
	now := time.Now().UTC()
	if p := applyPolicyAt(t, h, account, now); p.Credited != 100 {
		t.Fatalf("first grant backfilled account history: %+v", p)
	}
	h.cfg.Allowance.DailyBase = math.MaxInt64
	if p := applyPolicyAt(t, h, account, now.AddDate(100, 0, 0)); p.Credited != 100 {
		t.Fatalf("large catchup did not saturate at cap: %+v", p)
	}
	// A backwards clock cannot produce another day's grant.
	if p := applyPolicyAt(t, h, account, now.AddDate(0, 0, -1)); p.Credited != 0 {
		t.Fatalf("backwards clock grant: %+v", p)
	}
}
