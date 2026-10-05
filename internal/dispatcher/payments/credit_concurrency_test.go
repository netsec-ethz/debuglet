// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"database/sql"
	"strings"
	"sync"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

// creditCallers is how many completions of one order race in each test.
const creditCallers = 8

// raceCalls runs every call at once behind a start gate and returns their
// errors in call order.
func raceCalls(calls []func() error) []error {
	errs := make([]error, len(calls))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, call := range calls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = call()
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

// assertCreditedOnce checks that the order ended Credited with the
// executor's income and balance raised by its price exactly once.
func assertCreditedOnce(t *testing.T, db *sql.DB) {
	t.Helper()
	if got := orderState(t, db); got != models.Credited {
		t.Fatalf("order state %v, want %v", got, models.Credited)
	}
	var income, balance int64
	if err := db.QueryRow("SELECT total_income, current_balance FROM earnings WHERE executor_id = ? AND currency = 'TEST'",
		testExecutor).Scan(&income, &balance); err != nil {
		t.Fatalf("TEST earnings: %v", err)
	}
	if income != testPrice || balance != testPrice {
		t.Fatalf("income %d and balance %d, want the order price %d once", income, balance, testPrice)
	}
}

// Completions of one order that run at the same time credit it once. The
// dispatcher's database handle holds a single connection, so each completion's
// SQL transaction waits for the connection rather than meeting a lock: every
// call returns nil, one of them credits, and the others find the order
// Credited and write nothing.
func TestConcurrentCompletionsCreditOnce(t *testing.T) {
	db := newRefundDatabase(t)
	h, rec := newDisabledHandler(t, db, true, true)
	seedTESTOrder(t, db, models.Outstanding)

	calls := make([]func() error, creditCallers)
	for i := range calls {
		calls[i] = func() error { return h.SetDebugletOrderComplete(testDebuglet(), t.Context()) }
	}
	for i, err := range raceCalls(calls) {
		if err != nil {
			t.Fatalf("completion %d: %v", i, err)
		}
	}
	assertCreditedOnce(t, db)
	assertSettledOnce(t, db, settlementCredit)
	if calls := rec.chain.Calls(); len(calls) != 0 {
		t.Fatalf("TEST completion reached the chain backend: %v", calls)
	}
}

// A failed-run refund of a TEST order racing its completion: exactly one of
// them settles the order, every call returns nil, and the order carries one
// settlement row that agrees with its state and the executor's income.
func TestConcurrentCompletionAndTESTRefundSettleOnce(t *testing.T) {
	db := newRefundDatabase(t)
	h, rec := newDisabledHandler(t, db, true, true)
	seedTESTOrder(t, db, models.Outstanding)

	var calls []func() error
	for range creditCallers / 2 {
		calls = append(calls,
			func() error { return h.SettleTerminalOrder(t.Context(), testDebuglet(), 0) },
			func() error { return h.SettleTerminalOrder(t.Context(), testDebuglet(), 1) },
		)
	}
	for i, err := range raceCalls(calls) {
		if err != nil {
			t.Fatalf("settlement %d: %v", i, err)
		}
	}
	n, row := settlementOf(t, db)
	if n != 1 {
		t.Fatalf("%d settlement rows, want 1", n)
	}
	assertSettledOnce(t, db, row.Kind)
	if calls := rec.chain.Calls(); len(calls) != 0 {
		t.Fatalf("TEST completion or refund reached the chain backend: %v", calls)
	}
}

// Two handles on one database file, as a second process would hold, meet
// SQLite's lock. The busy timeout usually lets a completion wait it out; one
// that still loses it fails with "database is locked" (SQLITE_BUSY) and rolls
// back. No other failure occurs, and the order is still credited once. A
// completion repeated afterwards finds it Credited.
func TestCompletionsOnTwoHandlesCreditOnce(t *testing.T) {
	db := newRefundDatabase(t)
	seedTESTOrder(t, db, models.Outstanding)
	var seq int64
	var name, file string
	if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &file); err != nil {
		t.Fatalf("locate the database file: %v", err)
	}
	other, err := sqlitedb.Open(file)
	if err != nil {
		t.Fatalf("open a second handle: %v", err)
	}
	t.Cleanup(func() { _ = other.Close() })
	first, _ := newDisabledHandler(t, db, true, true)
	second, _ := newDisabledHandler(t, other, true, true)

	calls := make([]func() error, creditCallers)
	for i := range calls {
		h := first
		if i%2 == 1 {
			h = second
		}
		calls[i] = func() error { return h.SetDebugletOrderComplete(testDebuglet(), t.Context()) }
	}
	var succeeded, busy int
	for i, err := range raceCalls(calls) {
		switch {
		case err == nil:
			succeeded++
		case strings.Contains(err.Error(), "database is locked"):
			busy++
			t.Logf("completion %d lost the lock: %v", i, err)
		default:
			t.Fatalf("completion %d failed with %v, want nil or a lost lock", i, err)
		}
	}
	if succeeded == 0 {
		t.Fatal("no completion succeeded")
	}
	t.Logf("%d completions returned nil, %d lost the lock", succeeded, busy)
	assertCreditedOnce(t, db)
	assertSettledOnce(t, db, settlementCredit)
	if err := second.SetDebugletOrderComplete(testDebuglet(), t.Context()); err != nil {
		t.Fatalf("completion after the race: %v", err)
	}
	assertCreditedOnce(t, other)
	assertSettledOnce(t, other, settlementCredit)
}
