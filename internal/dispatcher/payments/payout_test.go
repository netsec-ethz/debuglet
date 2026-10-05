package payments

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"

	"github.com/DATA-DOG/go-sqlmock"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

var (
	getEarningsQuery = regexp.QuoteMeta(
		"SELECT executor_id, currency, total_income, current_balance, sui_wallet_address FROM earnings",
	) + `\s*$`
)

// recordingHandler is a payout Handler that records every earning it is asked
// to pay and counts reconciliation passes.
type recordingHandler struct {
	mu         sync.Mutex
	paid       []database.Earning
	reconciled int
}

func (r *recordingHandler) PayoutExecutor(e database.Earning, ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paid = append(r.paid, e)
	return nil
}

func (r *recordingHandler) ReconcileTransfers(ctx context.Context, limit int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reconciled++
	return nil
}

func (r *recordingHandler) Paid() []database.Earning {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]database.Earning(nil), r.paid...)
}

func (r *recordingHandler) Reconciled() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reconciled
}

func newTestTicker(t *testing.T, period time.Duration, handler Handler) (*PayoutTicker, sqlmock.Sqlmock) {
	t.Helper()
	db, mock := newMockDB(t)
	ticker := time.NewTicker(period)
	t.Cleanup(ticker.Stop)
	reconcile := time.NewTicker(period)
	t.Cleanup(reconcile.Stop)
	return &PayoutTicker{ticker: ticker, reconcile: reconcile, database: db, handler: handler, logger: zap.NewNop()}, mock
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
	case tick := <-pt.reconcile.C:
		t.Fatalf("reconciliation ticker delivered a tick at %v after the loop returned; ticker not stopped", tick)
	case <-time.After(10 * period):
	}
	if paid := handler.Paid(); len(paid) != 0 {
		t.Fatalf("loop paid executors: %v", paid)
	}
	assertMet(t, mock)
}

// TestStartPayoutLoopReconciles runs the loop with a payout tick an hour away
// and a short reconciliation tick: reconciliation runs without a payout.
func TestStartPayoutLoopReconciles(t *testing.T) {
	handler := &recordingHandler{}
	pt, mock := newTestTicker(t, time.Hour, handler)
	pt.reconcile.Reset(time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- pt.StartPayoutLoop(ctx) }()
	deadline := time.Now().Add(waitBound)
	for handler.Reconciled() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := waitErr(t, errCh, "StartPayoutLoop after cancellation"); err != nil {
		t.Fatalf("StartPayoutLoop returned %v", err)
	}
	if n := handler.Reconciled(); n < 2 {
		t.Fatalf("%d reconciliation passes within %v", n, waitBound)
	}
	if paid := handler.Paid(); len(paid) != 0 {
		t.Fatalf("reconciliation paid executors: %v", paid)
	}
	assertMet(t, mock)
}

// TestPayExecutorsSettlesOnlySuccessfulPayouts drives PayExecutors over a
// real database: a successful payout leaves the balance reserved in a sent
// transfer, a failed one restores the balance and records the failure. A
// zero balance is skipped, and a balance without a wallet is not paid out and
// counted once.
func TestPayExecutorsSettlesOnlySuccessfulPayouts(t *testing.T) {
	db, h, chain := transferFixture(t)
	const failWallet, okWallet = "0xfa11", "0x0c"
	chain.executeFor = map[string]error{failWallet: fmt.Errorf("%w: refused", sui.ErrNotBroadcast)}
	seedEarning(t, db, "exec-fail", 10, failWallet)
	seedEarning(t, db, "exec-ok", 20, okWallet)
	seedEarning(t, db, "exec-empty", 0, "0x0e")
	seedEarning(t, db, "exec-nowallet", 30, "")
	if _, err := database.New(db).CreateEarnings(t.Context(), database.CreateEarningsParams{ExecutorID: "exec-test", Currency: "TEST"}); err != nil {
		t.Fatal(err)
	}
	if err := database.New(db).AddEarnings(t.Context(), database.AddEarningsParams{Amount: 40, ExecutorID: "exec-test", Currency: "TEST"}); err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zapcore.DebugLevel)
	pt := &PayoutTicker{database: db, handler: h, logger: zap.New(core)}

	pt.PayExecutors(context.Background())

	if n := count(chain.Calls(), "ExecuteTransfer"); n != 2 || count(chain.Calls(), "PrepareTransfer") != 2 {
		t.Fatalf("%d executions, want 2", n)
	}
	for executor, want := range map[string]int64{"exec-fail": 10, "exec-ok": 0, "exec-empty": 0, "exec-nowallet": 30} {
		if got := earningOf(t, db, executor).CurrentBalance; got != want {
			t.Fatalf("balance of %s %d, want %d", executor, got, want)
		}
	}
	states := map[string]string{}
	for _, row := range transferRows(t, db) {
		states[row.ExecutorID] = row.State
	}
	if fmt.Sprint(states) != fmt.Sprint(map[string]string{"exec-fail": transferFailed, "exec-ok": transferSent}) {
		t.Fatalf("transfer states %v", states)
	}
	test, err := database.New(db).GetEarningsIn(t.Context(), database.GetEarningsInParams{ExecutorID: "exec-test", Currency: "TEST"})
	if err != nil || test.CurrentBalance != 40 {
		t.Fatalf("TEST earning %+v, %v; want it untouched", test, err)
	}
	if n := logs.FilterField(zap.String("execID", "exec-test")).Len(); n != 0 {
		t.Fatalf("TEST earning logged %d times", n)
	}
	warned := logs.FilterMessage("Earnings without a payout wallet were not paid out").All()
	if len(warned) != 1 || warned[0].ContextMap()["balances"] != int64(1) {
		t.Fatalf("wallet warnings %v", warned)
	}
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
