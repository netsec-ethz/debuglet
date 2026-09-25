package payments

import (
	"context"
	"database/sql/driver"
	"errors"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"

	"github.com/DATA-DOG/go-sqlmock"
	"go.uber.org/zap"
)

var (
	getEarningsQuery = regexp.QuoteMeta(
		"SELECT executor_id, currency, total_income, current_balance, sui_wallet_address FROM earnings",
	) + `\s*$`
	settleEarningQuery = regexp.QuoteMeta(
		"UPDATE earnings \nSET current_balance = 0\nWHERE executor_id = ? AND currency = ?",
	)
)

// recordingHandler is a payout Handler that records every earning it is asked
// to pay and fails for the executors listed in failFor.
type recordingHandler struct {
	mu      sync.Mutex
	paid    []database.Earning
	failFor map[string]bool
}

func (r *recordingHandler) PayoutExecutor(e database.Earning, ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paid = append(r.paid, e)
	if r.failFor[e.ExecutorID] {
		return errScripted
	}
	return nil
}

func (r *recordingHandler) Paid() []database.Earning {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]database.Earning(nil), r.paid...)
}

// argRecorder is a sqlmock argument matcher that accepts any value and keeps
// what it saw, so a test can assert which rows a statement was run for even
// when the production code discards the statement's error.
type argRecorder struct {
	mu   sync.Mutex
	seen []driver.Value
}

func (r *argRecorder) Match(v driver.Value) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, v)
	return true
}

func (r *argRecorder) Seen() []driver.Value {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]driver.Value(nil), r.seen...)
}

func newTestTicker(t *testing.T, period time.Duration, handler Handler) (*PayoutTicker, sqlmock.Sqlmock) {
	t.Helper()
	db, mock := newMockDB(t)
	ticker := time.NewTicker(period)
	t.Cleanup(ticker.Stop)
	return &PayoutTicker{ticker: ticker, database: db, handler: handler, logger: zap.NewNop()}, mock
}

// TestStartPayoutLoopReturnsOnCancel runs the loop with a ticker that would
// fire in an hour, cancels the context and requires the loop to return within
// the bound with a nil error.
func TestStartPayoutLoopReturnsOnCancel(t *testing.T) {
	handler := &recordingHandler{}
	pt, mock := newTestTicker(t, time.Hour, handler)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- pt.StartPayoutLoop(ctx) }()

	select {
	case err := <-errCh:
		t.Fatalf("loop returned before cancellation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	cancel()
	if err := waitErr(t, errCh, "StartPayoutLoop after cancellation"); err != nil {
		t.Fatalf("StartPayoutLoop returned %v after cancellation, want nil", err)
	}
	if paid := handler.Paid(); len(paid) != 0 {
		t.Fatalf("cancelled loop paid executors: %v", paid)
	}
	assertMet(t, mock)
}

// TestStartPayoutLoopStopsTicker cancels the context before the first tick of
// a short-period ticker and requires that no tick is delivered after the loop
// has returned, proving the ticker was stopped.
func TestStartPayoutLoopStopsTicker(t *testing.T) {
	const period = 5 * time.Millisecond
	handler := &recordingHandler{}
	pt, mock := newTestTicker(t, period, handler)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- pt.StartPayoutLoop(ctx) }()
	if err := waitErr(t, errCh, "StartPayoutLoop with cancelled context"); err != nil {
		t.Fatalf("StartPayoutLoop returned %v, want nil", err)
	}

	select {
	case tick := <-pt.ticker.C:
		t.Fatalf("ticker delivered a tick at %v after the loop returned; ticker not stopped", tick)
	case <-time.After(10 * period):
	}
	if paid := handler.Paid(); len(paid) != 0 {
		t.Fatalf("loop paid executors: %v", paid)
	}
	assertMet(t, mock)
}

// TestPayExecutorsSettlesOnlySuccessfulPayouts drives PayExecutors directly:
// a successful payout settles the earning row, a failed one leaves it alone.
// The failing executor is listed first so a wrong settle would be recorded by
// the argument recorder before the expected one.
func TestPayExecutorsSettlesOnlySuccessfulPayouts(t *testing.T) {
	handler := &recordingHandler{failFor: map[string]bool{"exec-fail": true}}
	pt, mock := newTestTicker(t, time.Hour, handler)

	mock.ExpectQuery(getEarningsQuery).WillReturnRows(sqlmock.NewRows(earningsColumns).
		AddRow("exec-fail", "USDC", int64(10), int64(10), "0xfail").
		AddRow("exec-ok", "USDC", int64(20), int64(20), "0xok"))
	settled := &argRecorder{}
	mock.ExpectExec(settleEarningQuery).WithArgs(settled, "USDC").WillReturnResult(sqlmock.NewResult(0, 1))

	pt.PayExecutors(context.Background())

	paid := handler.Paid()
	if len(paid) != 2 || paid[0].ExecutorID != "exec-fail" || paid[1].ExecutorID != "exec-ok" {
		t.Fatalf("payout attempts %v", paid)
	}
	if paid[1].CurrentBalance != 20 || paid[1].SuiWalletAddress != "0xok" {
		t.Fatalf("earning forwarded to handler %+v", paid[1])
	}
	if seen := settled.Seen(); len(seen) != 1 || seen[0] != "exec-ok" {
		t.Fatalf("settled executors %v, want [exec-ok]", seen)
	}
	assertMet(t, mock)
}

func TestPayExecutorsQueryError(t *testing.T) {
	handler := &recordingHandler{}
	pt, mock := newTestTicker(t, time.Hour, handler)
	mock.ExpectQuery(getEarningsQuery).WillReturnError(errors.New("boom"))

	pt.PayExecutors(context.Background())

	if paid := handler.Paid(); len(paid) != 0 {
		t.Fatalf("payouts attempted after a failed earnings query: %v", paid)
	}
	assertMet(t, mock)
}
