// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func policyFixture(t *testing.T, researcher bool) (*sql.DB, *PaymentHandler, uuid.UUID, uuid.UUID) {
	t.Helper()
	db, h, account, operator := allowanceFixture(t)
	if _, err := db.Exec(`UPDATE users SET role='operator' WHERE uuid=?`, operator); err != nil {
		t.Fatal(err)
	}
	h.cfg.Allowance.PolicyIssuer = operator.String()
	h.cfg.Allowance.DailyBase = 100
	h.cfg.Allowance.PublicTrial = 10
	if err := h.SetAllowanceEligibility(t.Context(), account, operator, researcher, nil); err != nil {
		t.Fatal(err)
	}
	return db, h, account, operator
}
func applyPolicyAt(t *testing.T, h *PaymentHandler, account uuid.UUID, now time.Time) *AllowancePolicy {
	t.Helper()
	tx, err := h.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	p, err := h.applyAllowancePolicyIn(t.Context(), tx, account, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return p
}
func consumePolicyCredit(t *testing.T, db *sql.DB, h *PaymentHandler, account uuid.UUID) {
	t.Helper()
	if err := reserveIntent(t, h, db, account, testTxID, testPrice); err != nil {
		t.Fatal(err)
	}
	if ok, err := claimRefundOrder(t.Context(), db); err != nil || !ok {
		t.Fatalf("claim: %v, %v", ok, err)
	}
	if err := h.SettleTerminalOrder(t.Context(), testDebuglet(), 0); err != nil {
		t.Fatal(err)
	}
}
func TestAllowancePolicyZeroDecisionAndUTCDayBoundary(t *testing.T) {
	db, h, account, operator := policyFixture(t, true)
	mustGrant(t, h, account, operator, 100, "manual")
	today := time.Now().UTC()
	before := time.Date(today.Year(), today.Month(), today.Day(), 23, 59, 59, 0, time.UTC)
	first := applyPolicyAt(t, h, account, before)
	if first.Credited != 0 || first.NextReset == nil || !first.NextReset.Equal(before.Add(time.Second)) {
		t.Fatalf("first: %+v", first)
	}
	consumePolicyCredit(t, db, h, account)
	if got := applyPolicyAt(t, h, account, before); got.Credited != 0 {
		t.Fatalf("second refill on same day: %+v", got)
	}
	after := applyPolicyAt(t, h, account, before.Add(time.Second))
	if after.Credited != testPrice {
		t.Fatalf("new day's refill=%d, want %d", after.Credited, testPrice)
	}
	// Restart and repeated requests preserve the recorded decision.
	restarted := allowanceHandler(t, db)
	restarted.cfg.Allowance = h.cfg.Allowance
	applyPolicyAt(t, restarted, account, before.Add(time.Hour))
	a, err := readAllowance(t.Context(), database.New(db), account)
	if err != nil || a.Granted != 100+testPrice {
		t.Fatalf("balance=%+v, %v", a, err)
	}
}
func TestAllowancePolicyPublicTrialDoesNotReset(t *testing.T) {
	db, h, account, _ := policyFixture(t, false)
	now := time.Now()
	first := applyPolicyAt(t, h, account, now)
	if first.Kind != "trial" || first.NextReset != nil || first.Credited != 10 {
		t.Fatalf("trial: %+v", first)
	}
	consumePolicyCredit(t, db, h, account)
	applyPolicyAt(t, h, account, now.Add(72*time.Hour))
	a, err := h.Allowance(t.Context(), account)
	if err != nil || a.Granted != 10 {
		t.Fatalf("trial repeated: %+v, %v", a, err)
	}
}
func TestAllowancePolicyReservationsCountTowardRefill(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unadmitted", true: "uncertain"}[admitted], func(t *testing.T) {
			db, h, account, _ := policyFixture(t, true)
			now := time.Now()
			applyPolicyAt(t, h, account, now)
			if err := reserveIntent(t, h, db, account, testTxID, testPrice); err != nil {
				t.Fatal(err)
			}
			if admitted {
				if ok, err := claimRefundOrder(t.Context(), db); err != nil || !ok {
					t.Fatalf("claim: %v %v", ok, err)
				}
			}
			expireIntent(t, db, testTxID)
			if p := applyPolicyAt(t, h, account, now.Add(24*time.Hour)); p.Credited != 0 {
				t.Fatalf("refilled reserved credit: %+v", p)
			}
			if err := reserveIntent(t, h, db, account, "new", 1); err != nil {
				t.Fatal(err)
			}
			a, err := h.Allowance(t.Context(), account)
			if err != nil {
				t.Fatal(err)
			}
			wantReserved := int64(1)
			if admitted {
				wantReserved += testPrice
			}
			if a.Granted != 100 || a.Reserved != wantReserved {
				t.Fatalf("reservation changed: %+v", a)
			}
		})
	}
}
func TestAllowancePolicyConcurrentRefillAndAdmissionAcrossConnections(t *testing.T) {
	db, h, account, _ := policyFixture(t, true)
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
	for _, err := range raceCalls([]func() error{func() error { _, err := h.Allowance(t.Context(), account); return err }, func() error { return reserveIntent(t, h2, other, account, "raced-admission", 60) }}) {
		if err != nil {
			t.Fatal(err)
		}
	}
	a, err := h.Allowance(t.Context(), account)
	if err != nil || a.Granted != 100 || a.Reserved != 60 {
		t.Fatalf("concurrent refill: %+v %v", a, err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM allowance_periods`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("decisions=%d %v", count, err)
	}
}
func TestAllowancePolicyHostingApprovalAndCap(t *testing.T) {
	db, h, account, operator := policyFixture(t, true)
	now := time.Now().UTC()
	ids := make([]uuid.UUID, 5)
	for i := range ids {
		ids[i] = uuid.New()
		if _, err := db.Exec(`INSERT INTO owned_executors(executor_id,user_id,name,created_at) SELECT ?,id,'node',CURRENT_TIMESTAMP FROM users WHERE uuid=?`, ids[i].String(), account); err != nil {
			t.Fatal(err)
		}
		heartbeat := now.Unix()
		if i == 3 {
			heartbeat -= 121
		}
		if i == 4 {
			heartbeat++
		}
		if _, err := db.Exec(`INSERT INTO probe_status VALUES(?,?,?,?,?,?,1,'','test')`, ids[i].String(), now.Unix()-1000, heartbeat, 1, now.Unix()-1000, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.SetAllowanceEligibility(t.Context(), account, operator, true, ids[:4]); err != nil {
		t.Fatal(err)
	}
	eligible, err := EligibleHostingExecutors(t.Context(), db, account, now)
	if err != nil || len(eligible) != 3 {
		t.Fatalf("eligible=%v %v", eligible, err)
	}
	h.cfg.Allowance.DailyPerNode = 10
	h.cfg.Allowance.DailyNodeCap = 2
	if p := applyPolicyAt(t, h, account, now); p.EligibleNodes != 2 || p.HostingBonus != 20 || p.Ceiling != 120 {
		t.Fatalf("cap: %+v", p)
	}
	// A failed approval update is atomic, and approval does not follow ownership.
	if err := h.SetAllowanceEligibility(t.Context(), account, operator, false, []uuid.UUID{uuid.New()}); !errors.Is(err, ErrInvalidHostingApproval) {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE owned_executors SET user_id=(SELECT id FROM users WHERE uuid=?) WHERE executor_id=?`, operator, ids[0].String()); err != nil {
		t.Fatal(err)
	}
	eligible, err = EligibleHostingExecutors(t.Context(), db, operator, now)
	if err != nil || len(eligible) != 0 {
		t.Fatalf("approval followed ownership: %v %v", eligible, err)
	}
	if _, err := db.Exec(`UPDATE probe_status SET connected=0`); err != nil {
		t.Fatal(err)
	}
	if p := applyPolicyAt(t, h, account, now.Add(24*time.Hour)); p.Ceiling != 100 || p.HostingBonus != 0 || !p.Researcher {
		t.Fatalf("offline/failed update: %+v", p)
	}
}
