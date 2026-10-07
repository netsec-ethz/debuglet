// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"

	"github.com/block-vision/sui-go-sdk/utils"
)

const (
	testWallet  = "0x00000000000000000000000000000000000000000000000000000000000000aa"
	testBalance = int64(100)
)

var errLostResponse = errors.New("connection reset while waiting for the response")

// lookupResult is one scripted LookupTransfer answer.
type lookupResult struct {
	outcome  sui.TransferOutcome
	verified bool
	err      error
}

// transferChain scripts the transfer methods of fakeChain. A prepared
// transfer carries signed bytes with their real digest, so it can be stored
// and restored; ExecuteTransfer and LookupTransfer answer from per-call
// scripts. onPrepare and onExecute run during the chain call.
type transferChain struct {
	*fakeChain

	smu         sync.Mutex
	prepares    int
	receiverOf  map[string]string // digest -> receiver
	executeErrs []error           // consumed per call; nil once exhausted
	executeFor  map[string]error  // by receiver, before executeErrs
	executed    [][]byte
	lookups     []lookupResult // consumed per call
	expected    []sui.TransferExpectation
	onPrepare   func()
	onExecute   func()
	// blockExecute makes ExecuteTransfer wait until its context ends;
	// executeDeadline records that context's deadline.
	blockExecute    bool
	executeDeadline time.Time
}

func (c *transferChain) PrepareTransfer(ctx context.Context, amount uint64, coinType string, receiver string) (*sui.PreparedTransfer, error) {
	c.record("PrepareTransfer")
	if c.onPrepare != nil {
		c.onPrepare()
	}
	c.fakeChain.mu.Lock()
	c.transferAmount, c.transferCoinType, c.transferAddress = amount, coinType, receiver
	c.fakeChain.mu.Unlock()
	c.smu.Lock()
	defer c.smu.Unlock()
	c.prepares++
	if c.transferErr != nil {
		return nil, c.transferErr
	}
	txBytes := []byte(fmt.Sprintf("transfer %d: %d %s to %s", c.prepares, amount, coinType, receiver))
	digest, err := utils.GetTxDigestFromBytes(txBytes)
	if err != nil {
		return nil, err
	}
	if c.receiverOf == nil {
		c.receiverOf = map[string]string{}
	}
	c.receiverOf[digest] = receiver
	return sui.RestorePreparedTransfer(digest, txBytes, fmt.Sprintf("signature %d", c.prepares))
}

func (c *transferChain) ExecuteTransfer(ctx context.Context, prepared *sui.PreparedTransfer) error {
	c.record("ExecuteTransfer")
	if c.onExecute != nil {
		c.onExecute()
	}
	c.smu.Lock()
	defer c.smu.Unlock()
	c.executeDeadline, _ = ctx.Deadline()
	if c.blockExecute {
		c.smu.Unlock()
		<-ctx.Done()
		c.smu.Lock()
		return fmt.Errorf("execute transfer %s: %w", prepared.Digest, ctx.Err())
	}
	c.executed = append(c.executed, bytes.Clone(prepared.Bytes()))
	if err, ok := c.executeFor[c.receiverOf[prepared.Digest]]; ok {
		return err
	}
	if len(c.executeErrs) == 0 {
		return nil
	}
	err := c.executeErrs[0]
	c.executeErrs = c.executeErrs[1:]
	return err
}

func (c *transferChain) LookupTransfer(ctx context.Context, digest string, expect *sui.TransferExpectation) (sui.TransferOutcome, bool, error) {
	c.record("LookupTransfer")
	c.smu.Lock()
	defer c.smu.Unlock()
	c.expected = append(c.expected, *expect)
	if len(c.lookups) == 0 {
		return "", false, errors.New("no scripted lookup")
	}
	r := c.lookups[0]
	c.lookups = c.lookups[1:]
	return r.outcome, r.verified, r.err
}

func (c *transferChain) Executed() [][]byte {
	c.smu.Lock()
	defer c.smu.Unlock()
	return append([][]byte(nil), c.executed...)
}

// transferFixture is an enabled handler on a real dispatcher database with a
// scripted chain.
func transferFixture(t *testing.T) (*sql.DB, *PaymentHandler, *transferChain) {
	t.Helper()
	db := newRefundDatabase(t)
	h, rec := newEnabledHandler(t, db, enabledConfig(t))
	chain := &transferChain{fakeChain: rec.chain}
	h.sui = chain
	return db, h, chain
}

// seedEarning credits executor with amount USDC and sets its payout wallet.
func seedEarning(t *testing.T, db *sql.DB, executor string, amount int64, wallet string) database.Earning {
	t.Helper()
	q := database.New(db)
	if _, err := q.CreateEarnings(t.Context(), database.CreateEarningsParams{ExecutorID: executor, Currency: "USDC", SuiWalletAddress: wallet}); err != nil {
		t.Fatal(err)
	}
	creditEarning(t, db, executor, amount)
	return earningOf(t, db, executor)
}

func creditEarning(t *testing.T, db *sql.DB, executor string, amount int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitBound)
	defer cancel()
	if err := database.New(db).AddEarnings(ctx, database.AddEarningsParams{Amount: amount, ExecutorID: executor, Currency: "USDC"}); err != nil {
		t.Errorf("credit during the chain call (is a SQL transaction held across it?): %v", err)
	}
}

func earningOf(t *testing.T, db *sql.DB, executor string) database.Earning {
	t.Helper()
	e, err := database.New(db).GetEarningsIn(t.Context(), database.GetEarningsInParams{ExecutorID: executor, Currency: "USDC"})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// transferRows returns every chain_transfers row in insertion order.
func transferRows(t *testing.T, db *sql.DB) []database.ChainTransfer {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT id, kind, executor_id, transaction_id, order_id, amount, currency, receiver,
state, digest, signed_transaction, signature, detail FROM chain_transfers ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []database.ChainTransfer
	for rows.Next() {
		var r database.ChainTransfer
		if err := rows.Scan(&r.ID, &r.Kind, &r.ExecutorID, &r.TransactionID, &r.OrderID, &r.Amount, &r.Currency, &r.Receiver,
			&r.State, &r.Digest, &r.SignedTransaction, &r.Signature, &r.Detail); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// onlyTransfer requires exactly one transfer row and returns it.
func onlyTransfer(t *testing.T, db *sql.DB) database.ChainTransfer {
	t.Helper()
	rows := transferRows(t, db)
	if len(rows) != 1 {
		t.Fatalf("%d transfer rows, want 1: %+v", len(rows), rows)
	}
	return rows[0]
}

func count(calls []string, name string) int {
	n := 0
	for _, c := range calls {
		if c == name {
			n++
		}
	}
	return n
}

// ---- payouts ----

// The payout reserves the balance it read. Earnings credited while the chain
// is called, which needs the database to be free, stay in the balance.
func TestPayoutReservesTheBalanceReadAndKeepsLaterEarnings(t *testing.T) {
	db, h, chain := transferFixture(t)
	earning := seedEarning(t, db, testExecutor, testBalance, testWallet)
	chain.onPrepare = func() { creditEarning(t, db, testExecutor, 30) }
	chain.onExecute = func() { creditEarning(t, db, testExecutor, 5) }

	if err := h.PayoutExecutor(earning, t.Context()); err != nil {
		t.Fatalf("PayoutExecutor: %v", err)
	}
	if got := earningOf(t, db, testExecutor); got.CurrentBalance != 35 || got.TotalIncome != testBalance+35 {
		t.Fatalf("earning after the payout %+v, want balance 35 of income %d", got, testBalance+35)
	}
	row := onlyTransfer(t, db)
	if row.Kind != transferPayout || row.State != transferSent || row.Amount != testBalance || row.Receiver != testWallet ||
		row.ExecutorID != testExecutor || row.Currency != "USDC" || row.Digest == "" || row.Signature == "" {
		t.Fatalf("payout row %+v", row)
	}
	if executed := chain.Executed(); len(executed) != 1 || !bytes.Equal(executed[0], row.SignedTransaction) {
		t.Fatalf("the submitted transaction is not the stored one")
	}
	if chain.transferAmount != uint64(testBalance) || chain.transferCoinType != sui.GetCoinType("USDC", "testnet") || chain.transferAddress != testWallet {
		t.Fatalf("prepared %d %s to %s", chain.transferAmount, chain.transferCoinType, chain.transferAddress)
	}
}

// An open payout blocks the next one for the same executor and currency.
func TestSecondPayoutIsRefusedWhileOneIsOpen(t *testing.T) {
	db, h, chain := transferFixture(t)
	earning := seedEarning(t, db, testExecutor, testBalance, testWallet)
	chain.executeErrs = []error{errLostResponse}
	if err := h.PayoutExecutor(earning, t.Context()); err != nil {
		t.Fatalf("PayoutExecutor: %v", err)
	}
	if row := onlyTransfer(t, db); row.State != transferUnknown || !strings.Contains(row.Detail, errLostResponse.Error()) {
		t.Fatalf("payout with a lost response: %+v", row)
	}

	creditEarning(t, db, testExecutor, 20)
	if err := h.PayoutExecutor(earningOf(t, db, testExecutor), t.Context()); !errors.Is(err, errPayoutNotReserved) {
		t.Fatalf("second payout = %v, want %v", err, errPayoutNotReserved)
	}
	if got := earningOf(t, db, testExecutor).CurrentBalance; got != 20 {
		t.Fatalf("balance %d after the refused payout, want 20", got)
	}
	if n := count(chain.Calls(), "ExecuteTransfer"); n != 1 || len(transferRows(t, db)) != 1 {
		t.Fatalf("%d executions, %d rows after the refused payout", n, len(transferRows(t, db)))
	}
}

// A transfer that was not broadcast, or executed with failure status, moved
// nothing: the row is failed and the balance is restored.
func TestFailedPayoutRestoresTheBalance(t *testing.T) {
	for name, executeErr := range map[string]error{
		"not broadcast":  fmt.Errorf("%w: gas coins changed", sui.ErrNotBroadcast),
		"failure status": fmt.Errorf("%w: InsufficientCoinBalance", sui.ErrTransferFailed),
	} {
		t.Run(name, func(t *testing.T) {
			db, h, chain := transferFixture(t)
			earning := seedEarning(t, db, testExecutor, testBalance, testWallet)
			chain.executeErrs = []error{executeErr}
			if err := h.PayoutExecutor(earning, t.Context()); err != nil {
				t.Fatalf("PayoutExecutor: %v", err)
			}
			if row := onlyTransfer(t, db); row.State != transferFailed || row.Detail != executeErr.Error() {
				t.Fatalf("failed payout row %+v", row)
			}
			if got := earningOf(t, db, testExecutor).CurrentBalance; got != testBalance {
				t.Fatalf("balance %d after a failed payout, want %d", got, testBalance)
			}
			// A failed payout does not block the next one.
			chain.executeErrs = nil
			if err := h.PayoutExecutor(earningOf(t, db, testExecutor), t.Context()); err != nil {
				t.Fatalf("payout after a failed one: %v", err)
			}
			if rows := transferRows(t, db); len(rows) != 2 || rows[1].State != transferSent {
				t.Fatalf("rows after the second payout %+v", rows)
			}
		})
	}
}

// A submission is bounded by executeTimeout; one that does not answer before
// its context ends is recorded as unknown, and the amount stays reserved.
func TestUnansweredSubmissionIsUnknown(t *testing.T) {
	db, h, chain := transferFixture(t)
	earning := seedEarning(t, db, testExecutor, testBalance, testWallet)
	chain.blockExecute = true
	ctx, cancel := context.WithTimeout(t.Context(), waitBound/2)
	defer cancel()
	start := time.Now()
	if err := h.PayoutExecutor(earning, ctx); err != nil {
		t.Fatalf("PayoutExecutor: %v", err)
	}
	if chain.executeDeadline.IsZero() || chain.executeDeadline.After(start.Add(executeTimeout)) {
		t.Fatalf("submission deadline %v, want one within %v of %v", chain.executeDeadline, executeTimeout, start)
	}
	if row := onlyTransfer(t, db); row.State != transferUnknown || !strings.Contains(row.Detail, context.DeadlineExceeded.Error()) {
		t.Fatalf("unanswered submission recorded as %+v", row)
	}
	if got := earningOf(t, db, testExecutor).CurrentBalance; got != 0 {
		t.Fatalf("balance %d while the payout is unknown, want 0", got)
	}
}

// The outcome a decided refund returns, and the one later read from its
// transfer row, follow the recorded state; a TEST refund has no row.
func TestRefundOutcomeFollowsTheRecordedTransfer(t *testing.T) {
	for name, tc := range map[string]struct {
		executeErr error
		want       RefundOutcome
	}{
		"sent":    {nil, RefundSent},
		"unknown": {errLostResponse, RefundPending},
		"failed":  {fmt.Errorf("%w: refused", sui.ErrNotBroadcast), RefundFailed},
	} {
		t.Run(name, func(t *testing.T) {
			db, h, chain := transferFixture(t)
			seedUSDCTransaction(t, db, 7)
			chain.executeErrs = []error{tc.executeErr}
			if outcome, err := h.RefundUnadmittedTransaction(testTxID, t.Context()); outcome != tc.want || err != nil {
				t.Fatalf("RefundUnadmittedTransaction = (%v, %v), want (%v, nil)", outcome, err, tc.want)
			}
			if outcome, err := h.RefundOutcomeOf(t.Context(), testTxID); outcome != tc.want || err != nil {
				t.Fatalf("RefundOutcomeOf = (%v, %v), want (%v, nil)", outcome, err, tc.want)
			}
		})
	}
	_, h, _ := transferFixture(t)
	if outcome, err := h.RefundOutcomeOf(t.Context(), "no-transfer"); outcome != RefundLocal || err != nil {
		t.Fatalf("RefundOutcomeOf without a transfer = (%v, %v)", outcome, err)
	}
}

// hangingLookup answers LookupTransfer for the digest hang only when its
// context ends, and confirms every other digest.
type hangingLookup struct {
	*transferChain
	hang string
}

func (c hangingLookup) LookupTransfer(ctx context.Context, digest string, expect *sui.TransferExpectation) (sui.TransferOutcome, bool, error) {
	c.record("LookupTransfer")
	if digest == c.hang {
		<-ctx.Done()
		return "", false, ctx.Err()
	}
	return sui.TransferConfirmed, true, nil
}

// A lookup that never answers is cut off at chainReadTimeout: its transfer is
// recorded unknown with the reservation kept, and later transfers are still
// reconciled in the same pass.
func TestHungLookupDoesNotStopReconciliation(t *testing.T) {
	const bound = 200 * time.Millisecond
	saved := chainReadTimeout
	chainReadTimeout = bound
	t.Cleanup(func() { chainReadTimeout = saved })

	db, h, chain := transferFixture(t)
	chain.executeErrs = []error{errLostResponse, errLostResponse}
	for _, executor := range []string{"exec-a", "exec-b"} {
		if err := h.PayoutExecutor(seedEarning(t, db, executor, testBalance, testWallet), t.Context()); err != nil {
			t.Fatalf("PayoutExecutor(%s): %v", executor, err)
		}
	}
	rows := transferRows(t, db)
	if len(rows) != 2 || rows[0].State != transferUnknown || rows[1].State != transferUnknown {
		t.Fatalf("payouts with lost responses: %+v", rows)
	}
	h.sui = hangingLookup{transferChain: chain, hang: rows[0].Digest}

	start := time.Now()
	reconcile(t, h)
	if elapsed := time.Since(start); elapsed < bound || elapsed > bound+waitBound {
		t.Fatalf("pass took %v with a lookup bound of %v", elapsed, bound)
	}
	byExecutor := map[string]database.ChainTransfer{}
	for _, row := range transferRows(t, db) {
		byExecutor[row.ExecutorID] = row
	}
	if row := byExecutor["exec-a"]; row.State != transferUnknown || row.Detail != "last check: lookup timed out" {
		t.Fatalf("hung lookup recorded %+v", row)
	}
	if row := byExecutor["exec-b"]; row.State != transferConfirmed {
		t.Fatalf("later transfer recorded %+v", row)
	}
	if got := earningOf(t, db, "exec-a").CurrentBalance; got != 0 {
		t.Fatalf("balance %d after a timed-out lookup, want the reservation kept", got)
	}
}

// A preparation failure reserves nothing.
func TestUnpreparedPayoutReservesNothing(t *testing.T) {
	db, h, chain := transferFixture(t)
	earning := seedEarning(t, db, testExecutor, testBalance, testWallet)
	chain.transferErr = fmt.Errorf("%w: insufficient USDC balance", sui.ErrNotBroadcast)
	if err := h.PayoutExecutor(earning, t.Context()); !errors.Is(err, sui.ErrNotBroadcast) {
		t.Fatalf("PayoutExecutor = %v", err)
	}
	if rows := transferRows(t, db); len(rows) != 0 || earningOf(t, db, testExecutor).CurrentBalance != testBalance {
		t.Fatalf("an unprepared payout changed state: %+v", rows)
	}
}

// ---- reconciliation ----

// unknownPayout leaves one payout in state unknown.
func unknownPayout(t *testing.T) (*sql.DB, *PaymentHandler, *transferChain) {
	t.Helper()
	db, h, chain := transferFixture(t)
	chain.executeErrs = []error{errLostResponse}
	if err := h.PayoutExecutor(seedEarning(t, db, testExecutor, testBalance, testWallet), t.Context()); err != nil {
		t.Fatalf("PayoutExecutor: %v", err)
	}
	if row := onlyTransfer(t, db); row.State != transferUnknown {
		t.Fatalf("payout with a lost response: %+v", row)
	}
	return db, h, chain
}

func reconcile(t *testing.T, h *PaymentHandler) {
	t.Helper()
	if err := h.ReconcileTransfers(t.Context(), 10); err != nil {
		t.Fatalf("ReconcileTransfers: %v", err)
	}
}

// A lost response resolved as confirmed by lookup completes the transfer
// without sending it again; the lookup checks the intended credit.
func TestUnknownTransferConfirmedByLookupIsNotSentAgain(t *testing.T) {
	db, h, chain := unknownPayout(t)
	digest := onlyTransfer(t, db).Digest
	chain.lookups = []lookupResult{{outcome: sui.TransferConfirmed, verified: true}}
	reconcile(t, h)

	if row := onlyTransfer(t, db); row.State != transferConfirmed || row.Digest != digest {
		t.Fatalf("reconciled row %+v", row)
	}
	if n := count(chain.Calls(), "ExecuteTransfer"); n != 1 {
		t.Fatalf("%d executions, want the original one only", n)
	}
	want := sui.TransferExpectation{Receiver: testWallet, Amount: uint64(testBalance), CoinType: sui.GetCoinType("USDC", "testnet")}
	if len(chain.expected) != 1 || chain.expected[0] != want {
		t.Fatalf("lookup expectation %+v, want %+v", chain.expected, want)
	}
	if got := earningOf(t, db, testExecutor).CurrentBalance; got != 0 {
		t.Fatalf("balance %d after a confirmed payout", got)
	}
	// A confirmed transfer is not looked up again.
	reconcile(t, h)
	if n := count(chain.Calls(), "LookupTransfer"); n != 1 {
		t.Fatalf("%d lookups, want 1", n)
	}
}

// Inconclusive lookups keep the transfer unknown with the last check noted
// and the amount still reserved.
func TestInconclusiveLookupKeepsTheTransferUnknown(t *testing.T) {
	for name, tc := range map[string]struct {
		result lookupResult
		detail string
	}{
		"lookup error": {lookupResult{err: errors.New("node unavailable")}, "lookup inconclusive: node unavailable"},
		"unverified":   {lookupResult{outcome: sui.TransferConfirmed}, "credit could not be verified"},
	} {
		t.Run(name, func(t *testing.T) {
			db, h, chain := unknownPayout(t)
			chain.lookups = []lookupResult{tc.result}
			reconcile(t, h)
			if row := onlyTransfer(t, db); row.State != transferUnknown || !strings.Contains(row.Detail, tc.detail) {
				t.Fatalf("row after an inconclusive lookup %+v, want detail %q", row, tc.detail)
			}
			if n := count(chain.Calls(), "ExecuteTransfer"); n != 1 {
				t.Fatalf("%d executions after an inconclusive lookup", n)
			}
			if got := earningOf(t, db, testExecutor).CurrentBalance; got != 0 {
				t.Fatalf("balance %d while the payout is unknown, want 0", got)
			}
		})
	}
}

// A transfer the chain executed with failure status releases the payout.
func TestLookupFailedReleasesThePayout(t *testing.T) {
	db, h, chain := unknownPayout(t)
	chain.lookups = []lookupResult{{outcome: sui.TransferFailed}}
	reconcile(t, h)
	if row := onlyTransfer(t, db); row.State != transferFailed {
		t.Fatalf("row %+v", row)
	}
	if got := earningOf(t, db, testExecutor).CurrentBalance; got != testBalance {
		t.Fatalf("balance %d, want %d", got, testBalance)
	}
}

// A transfer the chain does not know is submitted again with the stored
// bytes, once, and the outcome is recorded as for the first submission.
func TestNotFoundResubmitsTheStoredTransactionOnce(t *testing.T) {
	db, h, chain := unknownPayout(t)
	stored := onlyTransfer(t, db)
	chain.lookups = []lookupResult{{outcome: sui.TransferNotFound}, {outcome: sui.TransferConfirmed, verified: true}}
	reconcile(t, h)

	executed := chain.Executed()
	if len(executed) != 2 || !bytes.Equal(executed[1], stored.SignedTransaction) || !bytes.Equal(executed[0], executed[1]) {
		t.Fatalf("resubmission did not send the stored transaction once: %d executions", len(executed))
	}
	if row := onlyTransfer(t, db); row.State != transferSent || row.Digest != stored.Digest {
		t.Fatalf("row after the resubmission %+v", row)
	}
	reconcile(t, h)
	if row := onlyTransfer(t, db); row.State != transferConfirmed {
		t.Fatalf("row after the second check %+v", row)
	}
	if n := len(chain.Executed()); n != 2 || chain.prepares != 1 {
		t.Fatalf("%d executions and %d preparations, want 2 and 1", n, chain.prepares)
	}
}

// The recovery window is measured from reservation, not the last lookup, and
// survives repeated not-found answers. Stopping resubmission never releases
// uncertain money; lookups can still confirm a late chain result.
func TestNotFoundTransferStopsResubmittingAfterRecoveryWindow(t *testing.T) {
	for _, initialState := range []string{transferReserved, transferUnknown} {
		t.Run(initialState, func(t *testing.T) {
			db, h, chain := unknownPayout(t)
			stored := onlyTransfer(t, db)
			if _, err := db.Exec(`UPDATE chain_transfers SET state = ?, updated_at = ?`, initialState,
				models.NewUTCTime(time.Now().Add(-2*staleReservation))); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				chain.lookups = []lookupResult{{outcome: sui.TransferNotFound}}
				chain.executeErrs = []error{errLostResponse}
				reconcile(t, h)
			}
			if len(chain.Executed()) != 4 {
				t.Fatalf("%d executions before window elapsed, want 4", len(chain.Executed()))
			}
			for _, sent := range chain.Executed() {
				if !bytes.Equal(sent, stored.SignedTransaction) {
					t.Fatal("resubmission changed the signed transaction")
				}
			}
			if _, err := db.Exec(`UPDATE chain_transfers SET created_at = ?`,
				models.NewUTCTime(time.Now().Add(-automaticResubmissionWindow-time.Second))); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				chain.lookups = []lookupResult{{outcome: sui.TransferNotFound}}
				reconcile(t, h)
				row := onlyTransfer(t, db)
				if row.State != transferUnknown || row.Digest != stored.Digest ||
					!bytes.Equal(row.SignedTransaction, stored.SignedTransaction) || row.Signature != stored.Signature ||
					!strings.Contains(row.Detail, "automatic resubmission stopped") || !strings.Contains(row.Detail, "later payouts") {
					t.Fatalf("expired recovery row %+v", row)
				}
			}
			if len(chain.Executed()) != 4 || chain.prepares != 1 || earningOf(t, db, testExecutor).CurrentBalance != 0 {
				t.Fatalf("expired transfer executed/rebuilt/released: calls %v, earning %+v", chain.Calls(), earningOf(t, db, testExecutor))
			}
			creditEarning(t, db, testExecutor, 7)
			if err := h.PayoutExecutor(earningOf(t, db, testExecutor), t.Context()); !errors.Is(err, errPayoutNotReserved) {
				t.Fatalf("later payout error %v, want unresolved reservation", err)
			}
			if len(transferRows(t, db)) != 1 || earningOf(t, db, testExecutor).CurrentBalance != 7 {
				t.Fatal("later payout bypassed the unresolved reservation")
			}
			chain.lookups = []lookupResult{{err: errors.New("node unavailable")}}
			reconcile(t, h)
			if !strings.Contains(onlyTransfer(t, db).Detail, "automatic resubmission stopped") {
				t.Fatal("an inconclusive lookup hid the abandonment detail")
			}
			chain.lookups = []lookupResult{{outcome: sui.TransferConfirmed, verified: true}}
			reconcile(t, h)
			if row := onlyTransfer(t, db); row.State != transferConfirmed || row.Digest != stored.Digest {
				t.Fatalf("late confirmed row %+v", row)
			}
			if len(chain.Executed()) != 4 || earningOf(t, db, testExecutor).CurrentBalance != 7 {
				t.Fatal("late confirmation sent or released money")
			}
		})
	}
}

func TestResubmissionNotBroadcastKeepsEarlierOutcomeUnknown(t *testing.T) {
	db, h, chain := unknownPayout(t)
	stored := onlyTransfer(t, db)
	chain.lookups = []lookupResult{{outcome: sui.TransferNotFound}}
	chain.executeErrs = []error{fmt.Errorf("%w: local submission refused", sui.ErrNotBroadcast)}
	reconcile(t, h)
	if row := onlyTransfer(t, db); row.State != transferUnknown || row.Digest != stored.Digest ||
		!strings.Contains(row.Detail, "earlier outcome remains unknown") {
		t.Fatalf("not-broadcast resubmission %+v", row)
	}
	if earningOf(t, db, testExecutor).CurrentBalance != 0 || chain.prepares != 1 {
		t.Fatal("refused resubmission released or rebuilt uncertain money")
	}
}

// A stop between the reservation and the chain call leaves the transfer
// reserved. Reconciliation leaves a fresh reservation alone, and resolves an
// old one by its digest.
func TestReservedTransferLeftByAStopIsReconciled(t *testing.T) {
	db, h, chain := transferFixture(t)
	earning := seedEarning(t, db, testExecutor, testBalance, testWallet)
	reserved, err := h.prepareAndReserve(t.Context(), database.ChainTransfer{
		Kind: transferPayout, ExecutorID: testExecutor, Amount: earning.CurrentBalance, Currency: "USDC", Receiver: testWallet,
	}, func(q *database.Queries) error {
		_, err := q.ReservePayout(t.Context(), database.ReservePayoutParams{Amount: earning.CurrentBalance, ExecutorID: testExecutor, Currency: "USDC"})
		return err
	})
	if err != nil || reserved == nil {
		t.Fatalf("prepareAndReserve: %v", err)
	}
	if row := onlyTransfer(t, db); row.State != transferReserved || earningOf(t, db, testExecutor).CurrentBalance != 0 {
		t.Fatalf("reserved row %+v", row)
	}

	reconcile(t, h)
	if n := count(chain.Calls(), "LookupTransfer"); n != 0 {
		t.Fatalf("a fresh reservation was looked up %d times", n)
	}

	old := models.NewUTCTime(time.Now().Add(-2 * staleReservation))
	if _, err := db.ExecContext(t.Context(), "UPDATE chain_transfers SET updated_at = ?", old); err != nil {
		t.Fatal(err)
	}
	chain.lookups = []lookupResult{{outcome: sui.TransferNotFound}}
	reconcile(t, h)
	row := onlyTransfer(t, db)
	if row.State != transferSent || row.Digest != reserved.prepared.Digest {
		t.Fatalf("row after reconciliation %+v", row)
	}
	if executed := chain.Executed(); len(executed) != 1 || !bytes.Equal(executed[0], row.SignedTransaction) {
		t.Fatalf("the stored transaction was not submitted once")
	}
}

func TestReconcileTransfersDisabled(t *testing.T) {
	h, rec := newDisabledHandler(t, newRefundDatabase(t), true, true)
	if err := h.ReconcileTransfers(t.Context(), 10); !errors.Is(err, ErrPaymentsDisabled) {
		t.Fatalf("ReconcileTransfers = %v, want %v", err, ErrPaymentsDisabled)
	}
	if calls := rec.chain.Calls(); len(calls) != 0 {
		t.Fatalf("disabled reconciliation reached the chain: %v", calls)
	}
}

// ---- refunds ----

// seedUSDCTransaction stores a paid USDC transaction with one Outstanding
// order per price.
func seedUSDCTransaction(t *testing.T, db *sql.DB, prices ...int64) {
	t.Helper()
	q := database.New(db)
	var total int64
	for _, p := range prices {
		total += p
	}
	if _, err := q.CreateTransaction(t.Context(), database.CreateTransactionParams{
		ID: testTxID, AuthKey: "key", Price: total, Currency: "USDC", Method: "SUI",
		ExpiresAt: models.NewUTCTime(time.Now().Add(time.Hour)), Status: int64(models.Paid), Hash: testHash,
	}); err != nil {
		t.Fatal(err)
	}
	for i, p := range prices {
		if _, err := q.CreateDebugletOrder(t.Context(), database.CreateDebugletOrderParams{
			TransactionID: testTxID, OrderID: int64(i + 1), ExecutorID: testExecutor, Price: p,
			Currency: "USDC", RefundAddress: testWallet, State: int64(models.Outstanding),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// refundState returns the transaction status, the order states and the
// number of refund settlement rows.
func refundState(t *testing.T, db *sql.DB) (models.TransactionState, []models.TransactionState, int) {
	t.Helper()
	q := database.New(db)
	tr, err := q.GetTransactionByID(t.Context(), testTxID)
	if err != nil {
		t.Fatal(err)
	}
	orders, err := q.GetTransactionOrders(t.Context(), testTxID)
	if err != nil {
		t.Fatal(err)
	}
	var states []models.TransactionState
	for _, o := range orders {
		states = append(states, models.TransactionState(o.State))
	}
	var settlements int
	if err := db.QueryRow("SELECT COUNT(*) FROM order_settlements WHERE kind = 'refund'").Scan(&settlements); err != nil {
		t.Fatal(err)
	}
	return models.TransactionState(tr.Status), states, settlements
}

// A transaction refund is one transfer of the total and one refund
// settlement per order.
func TestRefundTransactionIsOneTransferWithOneSettlementPerOrder(t *testing.T) {
	db, h, chain := transferFixture(t)
	seedUSDCTransaction(t, db, 7, 8)
	if err := h.RefundTransaction(testTxID, t.Context()); err != nil {
		t.Fatalf("RefundTransaction: %v", err)
	}
	status, orders, settlements := refundState(t, db)
	if status != models.Refunded || fmt.Sprint(orders) != fmt.Sprint([]models.TransactionState{models.Refunded, models.Refunded}) || settlements != 2 {
		t.Fatalf("after the refund: transaction %v, orders %v, %d settlements", status, orders, settlements)
	}
	row := onlyTransfer(t, db)
	if row.Kind != transferRefund || row.Amount != 15 || row.Receiver != testWallet || row.TransactionID != testTxID ||
		row.OrderID.Valid || row.State != transferSent {
		t.Fatalf("refund row %+v", row)
	}
	if n := count(chain.Calls(), "ExecuteTransfer"); n != 1 {
		t.Fatalf("%d executions", n)
	}
}

// A refund whose transfer fails stays decided: the orders are Refunded and
// the owed amount is visible as a failed transfer, and the caller is told so.
func TestFailedRefundTransferKeepsTheDecision(t *testing.T) {
	db, h, chain := transferFixture(t)
	seedUSDCTransaction(t, db, 7, 8)
	chain.executeErrs = []error{fmt.Errorf("%w: refused", sui.ErrTransferFailed)}
	if outcome, err := h.RefundUnadmittedTransaction(testTxID, t.Context()); outcome != RefundFailed || err != nil {
		t.Fatalf("RefundUnadmittedTransaction = (%v, %v), want (%v, nil)", outcome, err, RefundFailed)
	}
	if outcome, err := h.RefundOutcomeOf(t.Context(), testTxID); outcome != RefundFailed || err != nil {
		t.Fatalf("RefundOutcomeOf = (%v, %v), want (%v, nil)", outcome, err, RefundFailed)
	}
	status, orders, settlements := refundState(t, db)
	if status != models.Refunded || orders[0] != models.Refunded || orders[1] != models.Refunded || settlements != 2 {
		t.Fatalf("after a failed transfer: transaction %v, orders %v, %d settlements", status, orders, settlements)
	}
	if row := onlyTransfer(t, db); row.State != transferFailed || row.Amount != 15 {
		t.Fatalf("refund row %+v", row)
	}
}

// A repeated refund request finds the transaction refunded and sends nothing.
func TestDuplicateRefundRequestSendsNothing(t *testing.T) {
	db, h, chain := transferFixture(t)
	seedUSDCTransaction(t, db, 7)
	if err := h.RefundTransaction(testTxID, t.Context()); err != nil {
		t.Fatalf("RefundTransaction: %v", err)
	}
	unadmitted := func(id string, ctx context.Context) error {
		_, err := h.RefundUnadmittedTransaction(id, ctx)
		return err
	}
	for _, refund := range []func(string, context.Context) error{h.RefundTransaction, unadmitted} {
		if err := refund(testTxID, t.Context()); err == nil || !strings.Contains(err.Error(), "has not been payed") {
			t.Fatalf("repeated refund = %v", err)
		}
	}
	if n := count(chain.Calls(), "ExecuteTransfer"); n != 1 || len(transferRows(t, db)) != 1 {
		t.Fatalf("%d executions after repeated requests", n)
	}
}

// Only Outstanding orders are refunded: a credited order was paid with work.
func TestRefundTransactionSkipsSettledOrders(t *testing.T) {
	db, h, _ := transferFixture(t)
	seedUSDCTransaction(t, db, 7, 8)
	if err := h.SetDebugletOrderComplete(&database.Debuglet{TransactionID: testTxID, OrderID: 2, ExecutorID: testExecutor}, t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.RefundTransaction(testTxID, t.Context()); err != nil {
		t.Fatalf("RefundTransaction: %v", err)
	}
	if _, orders, settlements := refundState(t, db); orders[0] != models.Refunded || orders[1] != models.Credited || settlements != 1 {
		t.Fatalf("orders %v, %d refund settlements", orders, settlements)
	}
	if row := onlyTransfer(t, db); row.Amount != 7 || !row.OrderID.Valid || row.OrderID.Int64 != 1 {
		t.Fatalf("refund row %+v", row)
	}
}

// A failed USDC run is refunded through the same lifecycle.
func TestSettleTerminalOrderRefundsAFailedUSDCRun(t *testing.T) {
	db, h, chain := transferFixture(t)
	seedUSDCTransaction(t, db, 7)
	run := &database.Debuglet{TransactionID: testTxID, OrderID: testOrderID, ExecutorID: testExecutor}
	for range 2 {
		if err := h.SettleTerminalOrder(t.Context(), run, 1); err != nil {
			t.Fatalf("SettleTerminalOrder: %v", err)
		}
	}
	if _, orders, settlements := refundState(t, db); orders[0] != models.Refunded || settlements != 1 {
		t.Fatalf("orders %v, %d settlements", orders, settlements)
	}
	if row := onlyTransfer(t, db); row.Amount != 7 || row.Kind != transferRefund || row.State != transferSent {
		t.Fatalf("refund row %+v", row)
	}
	if n := count(chain.Calls(), "ExecuteTransfer"); n != 1 {
		t.Fatalf("%d executions", n)
	}
}

// RefundDebugletOrder refunds one USDC order to its refund address through
// the same lifecycle; the order's transfer row names the order.
func TestRefundDebugletOrderUSDC(t *testing.T) {
	db, h, chain := transferFixture(t)
	seedUSDCTransaction(t, db, 7)
	if err := h.RefundDebugletOrder(&database.Debuglet{TransactionID: testTxID, OrderID: testOrderID, ExecutorID: testExecutor}, testWallet, t.Context()); err != nil {
		t.Fatalf("RefundDebugletOrder: %v", err)
	}
	status, orders, settlements := refundState(t, db)
	if status != models.Paid || orders[0] != models.Refunded || settlements != 1 {
		t.Fatalf("transaction %v, orders %v, %d settlements", status, orders, settlements)
	}
	if row := onlyTransfer(t, db); row.Amount != 7 || row.Receiver != testWallet || row.OrderID.Int64 != testOrderID || row.State != transferSent {
		t.Fatalf("refund row %+v", row)
	}
	if chain.transferCoinType != sui.GetCoinType("USDC", "testnet") || count(chain.Calls(), "ExecuteTransfer") != 1 {
		t.Fatalf("prepared %s, calls %v", chain.transferCoinType, chain.Calls())
	}
}

// A reservation that cannot be written leaves the decision untaken and
// submits nothing.
func TestRefusedReservationLeavesStateUntouched(t *testing.T) {
	refuse := func(t *testing.T, db *sql.DB) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), `CREATE TRIGGER refuse_transfer BEFORE INSERT ON chain_transfers
BEGIN SELECT RAISE(ABORT, 'transfer refused'); END;`); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("payout", func(t *testing.T) {
		db, h, chain := transferFixture(t)
		earning := seedEarning(t, db, testExecutor, testBalance, testWallet)
		refuse(t, db)
		if err := h.PayoutExecutor(earning, t.Context()); err == nil || !strings.Contains(err.Error(), "transfer refused") {
			t.Fatalf("PayoutExecutor = %v", err)
		}
		if got := earningOf(t, db, testExecutor).CurrentBalance; got != testBalance {
			t.Fatalf("balance %d after a refused reservation", got)
		}
		if n := count(chain.Calls(), "ExecuteTransfer"); n != 0 {
			t.Fatalf("%d executions after a refused reservation", n)
		}
	})
	t.Run("refund", func(t *testing.T) {
		db, h, chain := transferFixture(t)
		seedUSDCTransaction(t, db, 7, 8)
		refuse(t, db)
		if err := h.RefundTransaction(testTxID, t.Context()); err == nil || !strings.Contains(err.Error(), "transfer refused") {
			t.Fatalf("RefundTransaction = %v", err)
		}
		status, orders, settlements := refundState(t, db)
		if status != models.Paid || orders[0] != models.Outstanding || orders[1] != models.Outstanding || settlements != 0 {
			t.Fatalf("after a refused reservation: transaction %v, orders %v, %d settlements", status, orders, settlements)
		}
		if n := count(chain.Calls(), "ExecuteTransfer"); n != 0 {
			t.Fatalf("%d executions after a refused reservation", n)
		}
	})
}

// ---- settlement passes ----

// A failed USDC run whose inline refund lost its response is decided: the
// order is Refunded and the transfer unknown with its signed transaction
// kept. A settlement pass then selects nothing for the order and reaches the
// chain backend zero times; reconciliation resolves the transfer.
func TestSettlementPassLeavesAnUnknownRefundToReconciliation(t *testing.T) {
	for _, tc := range []struct {
		name             string
		block, cancelled bool
	}{
		{"no answer", true, false}, {"lost response", false, false},
		{"cancelled no answer", true, true}, {"cancelled lost response", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRehearsal(t, false, false)
			db, h, chain := r.db, r.h, r.chain.transferChain
			seed := seedFailedUSDCRun
			if tc.cancelled {
				seed = seedCancelledUSDCRun
			}
			run := seed(t, db)
			ctx := t.Context()
			if tc.block {
				chain.blockExecute = true
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, waitBound/2)
				defer cancel()
			} else {
				chain.executeErrs = []error{errLostResponse}
			}
			if err := h.SettleTerminalOrder(ctx, &run, 3); err != nil {
				t.Fatalf("SettleTerminalOrder: %v", err)
			}
			if got := orderState(t, db); got != models.Refunded {
				t.Fatalf("order state %v after the refund was reserved, want %v", got, models.Refunded)
			}
			if row := onlyTransfer(t, db); row.State != transferUnknown || len(row.SignedTransaction) == 0 || row.Signature == "" {
				t.Fatalf("refund row %+v", row)
			}
			original := onlyTransfer(t, db)
			r.restart()
			db, h = r.db, r.h
			calls := len(chain.Calls())
			for range 2 {
				settled, failed, deferred, next, err := h.SettlePendingOrders(t.Context(), 0, 32)
				if settled != 0 || failed != 0 || deferred != 0 || next != 0 || err != nil {
					t.Fatalf("pass: settled %d, failed %d, deferred %d, next %d, error %v", settled, failed, deferred, next, err)
				}
			}
			if got := chain.Calls()[calls:]; len(got) != 0 {
				t.Fatalf("settlement passes reached the chain backend: %v", got)
			}
			if row := onlyTransfer(t, db); row.Digest != original.Digest || row.Signature != original.Signature || !bytes.Equal(row.SignedTransaction, original.SignedTransaction) {
				t.Fatal("settlement retry replaced the uncertain transfer")
			}
			chain.lookups = []lookupResult{{outcome: sui.TransferConfirmed, verified: true}}
			reconcile(t, h)
			if row := onlyTransfer(t, db); row.State != transferConfirmed {
				t.Fatalf("reconciled refund row %+v", row)
			}
			if n, _ := settlementOf(t, db); n != 1 || count(chain.Calls(), "ExecuteTransfer") != 1 {
				t.Fatalf("%d settlement rows, calls %v", n, chain.Calls())
			}
		})
	}
}

// A refund owed but never attempted (the process stopped before the inline
// attempt reserved anything) is sent by a settlement pass exactly once, with
// the signed transaction reserved before it is submitted.
func TestSettlementPassSendsAnOwedRefundOnce(t *testing.T) {
	db, h, chain := transferFixture(t)
	seedFailedUSDCRun(t, db)
	chain.onExecute = func() {
		rows := transferRows(t, db)
		if len(rows) != 1 || rows[0].State != transferReserved || len(rows[0].SignedTransaction) == 0 || orderState(t, db) != models.Refunded {
			t.Errorf("submitted before the refund was reserved: %+v", rows)
		}
	}
	if settled, failed, deferred, _, err := h.SettlePendingOrders(t.Context(), 0, 32); settled != 1 || failed != 0 || deferred != 0 || err != nil {
		t.Fatalf("first pass: settled %d, failed %d, deferred %d, error %v", settled, failed, deferred, err)
	}
	if settled, failed, deferred, _, err := h.SettlePendingOrders(t.Context(), 0, 32); settled != 0 || failed != 0 || deferred != 0 || err != nil {
		t.Fatalf("second pass: settled %d, failed %d, deferred %d, error %v", settled, failed, deferred, err)
	}
	if row := onlyTransfer(t, db); row.State != transferSent || row.Amount != testPrice || row.Receiver != testRefund {
		t.Fatalf("refund row %+v", row)
	}
	if n := count(chain.Calls(), "ExecuteTransfer"); n != 1 {
		t.Fatalf("%d executions, want 1", n)
	}
	if n, row := settlementOf(t, db); n != 1 || row.Kind != settlementRefund {
		t.Fatalf("%d settlement rows, first %+v", n, row)
	}
}

func TestInvalidStoredRefundAddressRecordsFailedRefundOnce(t *testing.T) {
	for _, mode := range []string{"terminal run", "unadmitted transaction"} {
		t.Run(mode, func(t *testing.T) {
			db, h, chain := transferFixture(t)
			if mode == "terminal run" {
				seedFailedUSDCRun(t, db)
			} else {
				seedUSDCTransaction(t, db, testPrice)
			}
			if _, err := db.Exec(`UPDATE debuglet_order SET refund_address = 'unusable-address'`); err != nil {
				t.Fatal(err)
			}
			if mode == "terminal run" {
				if settled, failed, _, _, err := h.SettlePendingOrders(t.Context(), 0, 32); settled != 1 || failed != 0 || err != nil {
					t.Fatalf("settlement pass: settled %d failed %d error %v", settled, failed, err)
				}
			} else if outcome, err := h.RefundUnadmittedTransaction(testTxID, t.Context()); outcome != RefundFailed || err != nil {
				t.Fatalf("refund outcome %v, error %v", outcome, err)
			}
			row := onlyTransfer(t, db)
			if row.State != transferFailed || row.Amount != testPrice || row.Receiver != "unusable-address" ||
				row.Digest != "" || len(row.SignedTransaction) != 0 || row.Signature != "" ||
				!strings.Contains(row.Detail, "invalid refund address") || !strings.Contains(row.Detail, "amount remains owed") {
				t.Fatalf("failed refund row %+v", row)
			}
			if orderState(t, db) != models.Refunded {
				t.Fatal("invalid refund remains eligible for settlement")
			}
			if outcome, err := h.RefundOutcomeOf(t.Context(), testTxID); outcome != RefundFailed || err != nil {
				t.Fatalf("visible refund outcome %v, error %v", outcome, err)
			}
			for range 2 {
				if settled, failed, _, _, err := h.SettlePendingOrders(t.Context(), 0, 32); settled != 0 || failed != 0 || err != nil {
					t.Fatalf("repeat pass: settled %d failed %d error %v", settled, failed, err)
				}
				reconcile(t, h)
			}
			if n, settlement := settlementOf(t, db); n != 1 || settlement.Kind != settlementRefund || settlement.Amount != testPrice {
				t.Fatalf("%d settlement records: %+v", n, settlement)
			}
			if len(transferRows(t, db)) != 1 || len(chain.Calls()) != 0 {
				t.Fatalf("invalid refund retried or called chain: %v", chain.Calls())
			}
		})
	}
}
