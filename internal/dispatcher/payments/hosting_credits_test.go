// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/enrollment"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func hostingCreditFixture(t *testing.T) (*sql.DB, *PaymentHandler, uuid.UUID, uuid.UUID, HostingObservation) {
	t.Helper()
	db, h, account, operator := policyFixture(t, false)
	h.cfg.Allowance.BalanceCap = 100000
	h.cfg.Allowance.HostingHourlyRate = 3600
	h.cfg.Allowance.PublicTrial = 0
	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO owned_executors(executor_id,user_id,name,created_at) SELECT ?,id,'hosting',CURRENT_TIMESTAMP FROM users WHERE uuid=?`, id.String(), account); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO executor_enrollments(executor_id,fingerprint,enrolled_at) VALUES(?,'credential',CURRENT_TIMESTAMP)`, id.String()); err != nil {
		t.Fatal(err)
	}
	if err := h.SetAllowanceEligibility(t.Context(), account, operator, false, []uuid.UUID{id}); err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC()
	observation := HostingObservation{ExecutorID: id.String(), Fingerprint: "credential", Seen: time.Date(today.Year(), today.Month(), today.Day(), 12, 0, 0, 0, time.UTC),
		Binding: controlsession.Binding{Incarnation: uuid.NewString(), SessionID: uuid.NewString()}}
	return db, h, account, operator, observation
}

func observeHosting(t *testing.T, h *PaymentHandler, now time.Time, observations ...HostingObservation) {
	t.Helper()
	if err := h.ApplyHostingObservations(t.Context(), now, observations); err != nil {
		t.Fatal(err)
	}
}

func hostingTotals(t *testing.T, db *sql.DB, account uuid.UUID) (seconds, earned int64) {
	t.Helper()
	if err := db.QueryRow(`SELECT COALESCE(SUM(observed_seconds),0),COALESCE(SUM(credited),0) FROM allowance_hosting WHERE user_id=(SELECT id FROM users WHERE uuid=?)`, account).Scan(&seconds, &earned); err != nil {
		t.Fatal(err)
	}
	return
}

func TestHostingCreditsFractionalHoursAndReplay(t *testing.T) {
	db, h, account, _, observation := hostingCreditFixture(t)
	h.cfg.Allowance.HostingHourlyRate = 7
	start := observation.Seen
	for minute := 0; minute <= 60; minute++ {
		observation.Seen = start.Add(time.Duration(minute) * time.Minute)
		// Duplicate observations in a pass and repeated passes are both harmless.
		observeHosting(t, h, observation.Seen, observation, observation)
		observeHosting(t, h, observation.Seen, observation)
		if minute == 30 {
			older := observation
			older.Seen = older.Seen.Add(-time.Minute)
			observeHosting(t, h, observation.Seen, older)
		}
	}
	seconds, earned := hostingTotals(t, db, account)
	if seconds != 3600 || earned != 7 {
		t.Fatalf("hosting=%ds/%d credits, want3600/7", seconds, earned)
	}
	a, err := readAllowance(t.Context(), database.New(db), account)
	if err != nil || a.Granted != 107 {
		t.Fatalf("allowance=%+v, %v", a, err)
	}
}

func TestHostingCreditsContinuityBoundaries(t *testing.T) {
	for _, test := range []string{"session", "dispatcher", "gap", "missing", "stale", "future", "approval", "revocation", "credential", "owner"} {
		t.Run(test, func(t *testing.T) {
			db, h, account, operator, observation := hostingCreditFixture(t)
			start := observation.Seen
			observeHosting(t, h, start, observation)
			observation.Seen = start.Add(time.Minute)
			observeHosting(t, h, observation.Seen, observation)
			if seconds, earned := hostingTotals(t, db, account); seconds != 60 || earned != 60 {
				t.Fatalf("initial=%d/%d", seconds, earned)
			}
			at := start.Add(2 * time.Minute)
			switch test {
			case "session":
				observation.Binding.SessionID = uuid.NewString()
			case "dispatcher":
				observation.Binding.Incarnation = uuid.NewString()
			case "gap":
				at = start.Add(4 * time.Minute)
			case "missing":
				observeHosting(t, h, at)
				at = at.Add(time.Minute)
			case "stale":
				observeHosting(t, h, start.Add(5*time.Minute), observation)
				at = start.Add(6 * time.Minute)
			case "future":
				future := observation
				future.Seen = start.Add(time.Hour)
				observeHosting(t, h, at, future)
				at = at.Add(time.Minute)
			case "approval":
				if err := h.SetAllowanceEligibility(t.Context(), account, operator, false, nil); err != nil {
					t.Fatal(err)
				}
				if err := h.SetAllowanceEligibility(t.Context(), account, operator, false, []uuid.UUID{uuid.MustParse(observation.ExecutorID)}); err != nil {
					t.Fatal(err)
				}
			case "revocation":
				if _, err := enrollment.NewStore(db).Revoke(t.Context(), observation.ExecutorID); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`INSERT INTO executor_enrollments(executor_id,fingerprint,enrolled_at) VALUES(?,'credential',CURRENT_TIMESTAMP)`, observation.ExecutorID); err != nil {
					t.Fatal(err)
				}
			case "credential":
				if _, err := db.Exec(`UPDATE executor_enrollments SET fingerprint='different' WHERE executor_id=?`, observation.ExecutorID); err != nil {
					t.Fatal(err)
				}
				observeHosting(t, h, at, observation)
				if _, err := db.Exec(`UPDATE executor_enrollments SET fingerprint='credential' WHERE executor_id=?`, observation.ExecutorID); err != nil {
					t.Fatal(err)
				}
				at = at.Add(time.Minute)
			case "owner":
				if _, err := db.Exec(`UPDATE owned_executors SET user_id=(SELECT id FROM users WHERE uuid=?) WHERE executor_id=?`, operator, observation.ExecutorID); err != nil {
					t.Fatal(err)
				}
				observeHosting(t, h, at, observation)
				if _, err := db.Exec(`UPDATE owned_executors SET user_id=(SELECT id FROM users WHERE uuid=?) WHERE executor_id=?`, account, observation.ExecutorID); err != nil {
					t.Fatal(err)
				}
				at = at.Add(time.Minute)
			}
			observation.Seen = at
			observeHosting(t, h, at, observation)
			if seconds, earned := hostingTotals(t, db, account); seconds != 60 || earned != 60 {
				t.Fatalf("gap earned time: %d/%d", seconds, earned)
			}
			observation.Seen = at.Add(time.Minute)
			observeHosting(t, h, observation.Seen, observation)
			if seconds, earned := hostingTotals(t, db, account); seconds != 120 || earned != 120 {
				t.Fatalf("resume=%d/%d", seconds, earned)
			}
		})
	}
}

func TestHostingCreditsApprovalUpdateAndCap(t *testing.T) {
	db, h, account, operator, observation := hostingCreditFixture(t)
	h.cfg.Allowance.BalanceCap = 100
	h.cfg.Allowance.HostingHourlyRate = 7
	start := observation.Seen
	observeHosting(t, h, start, observation)
	// A reservation still occupies the cap. It cannot make room for issuance.
	if err := reserveIntent(t, h, db, account, "held", 50); err != nil {
		t.Fatal(err)
	}
	if err := h.SetAllowanceEligibility(t.Context(), account, operator, false, []uuid.UUID{uuid.MustParse(observation.ExecutorID)}); err != nil {
		t.Fatal(err)
	}
	observation.Seen = start.Add(time.Minute)
	observeHosting(t, h, observation.Seen, observation)
	if seconds, earned := hostingTotals(t, db, account); seconds != 60 || earned != 0 {
		t.Fatalf("capped=%d/%d", seconds, earned)
	}
	var remainder int64
	if err := db.QueryRow(`SELECT remainder FROM allowance_hosting WHERE executor_id=?`, observation.ExecutorID).Scan(&remainder); err != nil || remainder != 0 {
		t.Fatalf("cap retained fractional credit: %d/%v", remainder, err)
	}
	// Consuming seven existing credits creates exactly seven credits of room.
	consumePolicyCredit(t, db, h, account)
	h.cfg.Allowance.HostingHourlyRate = 3600
	observation.Seen = start.Add(2 * time.Minute)
	observeHosting(t, h, observation.Seen, observation)
	if seconds, earned := hostingTotals(t, db, account); seconds != 120 || earned != testPrice {
		t.Fatalf("after spend=%d/%d", seconds, earned)
	}
	a, err := readAllowance(t.Context(), database.New(db), account)
	if err != nil || a.Granted-a.Consumed != 100 {
		t.Fatalf("cap not preserved: %+v/%v", a, err)
	}
}

func TestHostingCreditsConcurrentObserversAndRollback(t *testing.T) {
	db, h, account, _, observation := hostingCreditFixture(t)
	observeHosting(t, h, observation.Seen, observation)
	var sequence int64
	var name, path string
	if err := db.QueryRow("PRAGMA database_list").Scan(&sequence, &name, &path); err != nil {
		t.Fatal(err)
	}
	other, err := sqlitedb.Open(path, sqlitedb.BusyTimeout(5000))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	h2 := allowanceHandler(t, other)
	h2.cfg.Allowance = h.cfg.Allowance
	observation.Seen = observation.Seen.Add(time.Minute)
	for _, err := range raceCalls([]func() error{
		func() error {
			return h.ApplyHostingObservations(t.Context(), observation.Seen, []HostingObservation{observation})
		},
		func() error {
			return h2.ApplyHostingObservations(t.Context(), observation.Seen, []HostingObservation{observation})
		},
	}) {
		if err != nil {
			t.Fatal(err)
		}
	}
	if seconds, earned := hostingTotals(t, db, account); seconds != 60 || earned != 60 {
		t.Fatalf("raced=%d/%d", seconds, earned)
	}
	// A grant failure must roll back its accounting cursor, so retry can recover.
	if _, err = db.Exec(`CREATE TRIGGER reject_hosting BEFORE INSERT ON allowance_grants WHEN NEW.reason='executor hosting' BEGIN SELECT RAISE(ABORT,'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	observation.Seen = observation.Seen.Add(time.Minute)
	if err = h.ApplyHostingObservations(t.Context(), observation.Seen, []HostingObservation{observation}); err == nil {
		t.Fatal("failed grant was accepted")
	}
	if seconds, earned := hostingTotals(t, db, account); seconds != 60 || earned != 60 {
		t.Fatalf("failed transaction advanced=%d/%d", seconds, earned)
	}
	if _, err = db.Exec(`DROP TRIGGER reject_hosting`); err != nil {
		t.Fatal(err)
	}
	observeHosting(t, h, observation.Seen, observation)
	if seconds, earned := hostingTotals(t, db, account); seconds != 120 || earned != 120 {
		t.Fatalf("retried=%d/%d", seconds, earned)
	}
}
