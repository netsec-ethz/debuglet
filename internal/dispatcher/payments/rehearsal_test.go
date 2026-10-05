// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"

	"go.uber.org/zap"
)

// The settlement rehearsal runs the complete chain payment lifecycle on a
// real dispatcher database file through the real PaymentHandler in enabled
// mode, with the scripted transferChain in place of the Sui network: intent,
// receipt, admission, terminal outcome, credit or refund, payout and
// reconciliation, including lost responses and stops between the steps.
// Each drill ends by comparing every row of the payment tables with the
// expected table and by counting the chain calls.

// rehearsalBuyer is the buyer's refund address of every rehearsal order.
const rehearsalBuyer = "0x00000000000000000000000000000000000000000000000000000000000000bb"

// rehearsalChain is transferChain with intent creation as the Sui adapter
// does it: the transaction row is stored outstanding, with method SUI, through
// the caller's database handle.
type rehearsalChain struct {
	*transferChain
}

func (c *rehearsalChain) CreatePaymentIntent(db database.DBTX, transactionId string, price int64, currency string, hash string, ctx context.Context) (sui.SuiPaymentIntent, error) {
	c.record("CreatePaymentIntent")
	expiresAt := time.Now().Add(5 * time.Minute)
	if _, err := database.New(db).CreateTransaction(ctx, database.CreateTransactionParams{
		ID: transactionId, AuthKey: "auth-" + transactionId, Price: price, Currency: currency, Method: "SUI",
		ExpiresAt: models.NewUTCTime(expiresAt), Hash: hash, Status: int64(models.Outstanding),
	}); err != nil {
		return sui.SuiPaymentIntent{}, fmt.Errorf("failed to store transaction: %w", err)
	}
	return sui.SuiPaymentIntent{TransactionId: transactionId, Price: price, CoinType: sui.GetCoinType(currency, "testnet"), ExpiresAt: expiresAt}, nil
}

// rehearsal is one dispatcher database file with the handler serving it. The
// scripted chain outlives restarts, as the network outlives the dispatcher.
type rehearsal struct {
	t        *testing.T
	path     string
	cfg      *config.DispatcherConfig
	disabled bool
	// restartEachStep closes and reopens the database file after every
	// step and requires every row to read back identically.
	restartEachStep bool
	restarts        int

	db    *sql.DB
	h     *PaymentHandler
	chain *rehearsalChain
}

func newRehearsal(t *testing.T, disabled bool, restartEachStep bool) *rehearsal {
	t.Helper()
	r := &rehearsal{
		t:               t,
		path:            filepath.Join(t.TempDir(), "dispatcher.sqlite"),
		disabled:        disabled,
		restartEachStep: restartEachStep,
		chain:           &rehearsalChain{transferChain: &transferChain{fakeChain: newFakeChain()}},
	}
	if !disabled {
		r.cfg = enabledConfig(t)
	}
	r.open(true)
	t.Cleanup(func() { _ = r.db.Close() })
	return r
}

// open opens the database file, creating and migrating it the first time,
// and builds the handler as the daemon does at startup.
func (r *rehearsal) open(create bool) {
	t := r.t
	t.Helper()
	opts := []sqlitedb.Option{}
	if create {
		opts = append(opts, sqlitedb.Create())
	}
	db, err := sqlitedb.Open(r.path, opts...)
	if err != nil {
		t.Fatalf("open %s: %v", r.path, err)
	}
	if create {
		if _, err := sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), sqlitedb.Latest); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	r.db = db
	if r.disabled {
		// The chain is attached after construction so that a guard that
		// wrongly reaches it is a recorded call, not a nil dereference.
		r.h, _ = newDisabledHandler(t, db, true, false)
	} else {
		r.h, _ = newEnabledHandler(t, db, r.cfg)
	}
	r.h.sui = r.chain
}

// restart stops the dispatcher and starts it again on the same file. Every
// row of the file must read back exactly as it was written.
func (r *rehearsal) restart() {
	t := r.t
	t.Helper()
	before := dumpAll(t, r.db)
	if err := r.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	r.open(false)
	if after := dumpAll(t, r.db); after != before {
		t.Fatalf("state read back after a restart differs\nbefore:\n%s\nafter:\n%s", before, after)
	}
	r.restarts++
}

// step runs one lifecycle step and, in the recovery drill, restarts after it.
func (r *rehearsal) step(name string, fn func()) {
	r.t.Helper()
	fn()
	if r.t.Failed() {
		r.t.Fatalf("step %q failed", name)
	}
	if r.restartEachStep {
		r.restart()
	}
}

func (r *rehearsal) ctx() context.Context { return r.t.Context() }

// register creates the executor's USDC earnings with its payout wallet, as
// executor registration does.
func (r *rehearsal) register() {
	r.t.Helper()
	if err := r.h.CreateEarningsIfNotExists(testExecutor, "USDC", testWallet, database.New(r.db), r.ctx()); err != nil {
		r.t.Fatalf("register executor: %v", err)
	}
}

// intent stores a payment intent of method with one order per price in one
// SQL transaction, as the intent request does.
func (r *rehearsal) intent(txID string, method string, prices ...int64) error {
	r.t.Helper()
	var total int64
	for _, p := range prices {
		total += p
	}
	tx, err := r.db.BeginTx(r.ctx(), nil)
	if err != nil {
		r.t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := r.h.CreatePaymentIntentIn(tx, txID, total, method, testHash, r.ctx()); err != nil {
		return err
	}
	currency := method
	for i, p := range prices {
		if _, err := database.New(tx).CreateDebugletOrder(r.ctx(), database.CreateDebugletOrderParams{
			TransactionID: txID, OrderID: int64(i + 1), ExecutorID: testExecutor, Price: p,
			Currency: currency, RefundAddress: rehearsalBuyer, State: int64(models.Outstanding),
		}); err != nil {
			r.t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		r.t.Fatal(err)
	}
	return nil
}

// receipt is a chain payment receipt paying amount to this dispatcher.
func (r *rehearsal) receipt(digest string, txID string, amount uint64, checkpoint uint64) sui.PaymentReceipt {
	return sui.PaymentReceipt{
		Digest: digest, Nonce: txID, Amount: amount, CoinType: sui.GetCoinType("USDC", "testnet"),
		Receiver: r.cfg.Sui.Address, Timestamp: time.Now(), Checkpoint: checkpoint,
	}
}

func (r *rehearsal) applyReceipt(rc sui.PaymentReceipt, want sui.ReceiptDisposition) {
	r.t.Helper()
	got, err := r.h.ApplyPaymentReceipt(r.ctx(), rc)
	if err != nil || got != want {
		r.t.Fatalf("receipt %s event %d = (%q, %v), want %q", rc.Digest, rc.EventSeq, got, err, want)
	}
}

// admit creates the run of an order and claims the order for it in one SQL
// transaction, as admission does. A refused claim stores nothing.
func (r *rehearsal) admit(txID string, orderID int64) (database.Debuglet, bool) {
	r.t.Helper()
	tx, err := r.db.BeginTx(r.ctx(), nil)
	if err != nil {
		r.t.Fatal(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	run, err := q.CreateDebuglet(r.ctx(), database.CreateDebugletParams{
		Uuid: uuid.New(), StartTime: models.NewUTCTime(time.Now()), EndTime: models.NewUTCTime(time.Now().Add(time.Minute)),
		ExecutorID: testExecutor, State: models.RunStateStarted, TransactionID: txID, OrderID: orderID,
		DispatcherIncarnation: "incarnation", SessionID: "session",
	})
	if err != nil {
		r.t.Fatal(err)
	}
	claimed, err := q.ClaimDebugletOrder(r.ctx(), database.ClaimDebugletOrderParams{
		DebugletID: sql.NullInt64{Int64: run.ID, Valid: true}, TransactionID: txID, OrderID: orderID,
		OutstandingState: int64(models.Outstanding), PaidStatus: int64(models.Paid),
	})
	if err != nil {
		r.t.Fatal(err)
	}
	if claimed != 1 {
		return database.Debuglet{}, false
	}
	if err := tx.Commit(); err != nil {
		r.t.Fatal(err)
	}
	return run, true
}

func (r *rehearsal) mustAdmit(txID string, orderID int64) database.Debuglet {
	r.t.Helper()
	run, ok := r.admit(txID, orderID)
	if !ok {
		r.t.Fatalf("order %s#%d was not admitted", txID, orderID)
	}
	return run
}

// terminate records the run's terminal state and exit code in one SQL
// transaction, as the terminal path does.
func (r *rehearsal) terminate(run database.Debuglet, exitCode int64) {
	r.t.Helper()
	tx, err := r.db.BeginTx(r.ctx(), nil)
	if err != nil {
		r.t.Fatal(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	if _, err := q.CompleteDebuglet(r.ctx(), database.CompleteDebugletParams{
		ExitedState: models.RunStateExited, Uuid: run.Uuid, ExecutorID: run.ExecutorID,
		DispatcherIncarnation: run.DispatcherIncarnation, SessionID: run.SessionID,
	}); err != nil {
		r.t.Fatalf("complete run: %v", err)
	}
	if err := q.RecordMeasurementTerminal(r.ctx(), database.RecordMeasurementTerminalParams{
		DebugletID: run.ID, TerminalObservedNs: sql.NullInt64{Int64: 1, Valid: true}, ExitCode: sql.NullInt64{Int64: exitCode, Valid: true},
	}); err != nil {
		r.t.Fatalf("record terminal: %v", err)
	}
	if err := tx.Commit(); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rehearsal) settle(run database.Debuglet, exitCode int32) {
	r.t.Helper()
	if err := r.h.SettleTerminalOrder(r.ctx(), &run, exitCode); err != nil {
		r.t.Fatalf("SettleTerminalOrder(%s#%d, %d): %v", run.TransactionID, run.OrderID, exitCode, err)
	}
}

func (r *rehearsal) pass(wantSettled int) {
	r.t.Helper()
	settled, failed, deferred, _, err := r.h.SettlePendingOrders(r.ctx(), 0, 32)
	if settled != wantSettled || failed != 0 || deferred != 0 || err != nil {
		r.t.Fatalf("settlement pass: settled %d, failed %d, deferred %d, error %v; want %d settled", settled, failed, deferred, err, wantSettled)
	}
}

// payout runs one payout tick over every balance.
func (r *rehearsal) payout() {
	(&PayoutTicker{database: r.db, handler: r.h, logger: zap.NewNop()}).PayExecutors(r.ctx())
}

func (r *rehearsal) reconcile(lookups ...lookupResult) {
	r.t.Helper()
	r.chain.smu.Lock()
	r.chain.lookups = append(r.chain.lookups, lookups...)
	r.chain.smu.Unlock()
	if err := r.h.ReconcileTransfers(r.ctx(), 10); err != nil {
		r.t.Fatalf("ReconcileTransfers: %v", err)
	}
	r.chain.smu.Lock()
	defer r.chain.smu.Unlock()
	if len(r.chain.lookups) != 0 {
		r.t.Fatalf("%d scripted lookups were not used", len(r.chain.lookups))
	}
}

// ageReservations moves every reserved transfer past staleReservation, as
// the clock does while a stopped dispatcher is down.
func (r *rehearsal) ageReservations() {
	r.t.Helper()
	old := models.NewUTCTime(time.Now().Add(-2 * staleReservation))
	if _, err := r.db.ExecContext(r.ctx(), "UPDATE chain_transfers SET updated_at = ? WHERE state = 'reserved'", old); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rehearsal) exec(statement string) {
	r.t.Helper()
	if _, err := r.db.ExecContext(r.ctx(), statement); err != nil {
		r.t.Fatalf("%s: %v", statement, err)
	}
}

// expectCalls compares the chain call counts with want; a call not named in
// want must not have happened.
func (r *rehearsal) expectCalls(want map[string]int) {
	r.t.Helper()
	got := map[string]int{}
	for _, c := range r.chain.Calls() {
		got[c]++
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		r.t.Fatalf("chain calls %v, want %v", got, want)
	}
	r.t.Logf("chain calls: %v", got)
}

// expectTables compares the payment tables with want, line by line.
func (r *rehearsal) expectTables(want string) {
	r.t.Helper()
	got := paymentTables(r.t, r.db)
	want = strings.TrimSpace(want)
	if got != want {
		r.t.Fatalf("payment tables:\n%s\n\nwant:\n%s", got, want)
	}
	r.t.Logf("final payment tables after %d restarts:\n%s", r.restarts, got)
}

// paymentTables renders every row of the six payment tables without the
// values that differ between runs (timestamps, random keys). Coin type,
// addresses and transfer digests are written as names; a transfer's stored
// signed transaction is "signed" only when its digest is the digest of the
// stored bytes and a signature is stored, so it can be submitted unchanged.
func paymentTables(t *testing.T, db *sql.DB) string {
	t.Helper()
	ctx := t.Context()
	var b strings.Builder
	query := func(statement string, scan func(*sql.Rows) string) {
		rows, err := db.QueryContext(ctx, statement)
		if err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
		defer rows.Close()
		for rows.Next() {
			b.WriteString("  " + scan(rows) + "\n")
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}
	scanInto := func(rows *sql.Rows, dest ...any) {
		if err := rows.Scan(dest...); err != nil {
			t.Fatal(err)
		}
	}
	nullable := func(v sql.NullInt64) string {
		if !v.Valid {
			return "-"
		}
		return fmt.Sprint(v.Int64)
	}

	b.WriteString("transactions\n")
	query("SELECT id, price, currency, method, status, pricing_rule FROM transactions ORDER BY id", func(rows *sql.Rows) string {
		var id, currency, method, rule string
		var price, status int64
		scanInto(rows, &id, &price, &currency, &method, &status, &rule)
		return fmt.Sprintf("%s %d %s/%s %v rule=%q", id, price, currency, method, models.TransactionState(status), rule)
	})
	b.WriteString("debuglet_order\n")
	query("SELECT transaction_id, order_id, executor_id, price, currency, state, refund_address, debuglet_id FROM debuglet_order ORDER BY transaction_id, order_id", func(rows *sql.Rows) string {
		var o database.DebugletOrder
		scanInto(rows, &o.TransactionID, &o.OrderID, &o.ExecutorID, &o.Price, &o.Currency, &o.State, &o.RefundAddress, &o.DebugletID)
		return fmt.Sprintf("%s#%d %s %d %s %v refund=%s run=%s", o.TransactionID, o.OrderID, o.ExecutorID, o.Price, o.Currency,
			models.TransactionState(o.State), o.RefundAddress, nullable(o.DebugletID))
	})
	b.WriteString("order_settlements\n")
	query("SELECT transaction_id, order_id, kind, amount, currency, executor_id, debuglet_id FROM order_settlements ORDER BY transaction_id, order_id", func(rows *sql.Rows) string {
		var s database.OrderSettlement
		scanInto(rows, &s.TransactionID, &s.OrderID, &s.Kind, &s.Amount, &s.Currency, &s.ExecutorID, &s.DebugletID)
		return fmt.Sprintf("%s#%d %s %d %s %s run=%s", s.TransactionID, s.OrderID, s.Kind, s.Amount, s.Currency, s.ExecutorID, nullable(s.DebugletID))
	})
	b.WriteString("earnings\n")
	query("SELECT executor_id, currency, total_income, current_balance, sui_wallet_address FROM earnings ORDER BY executor_id, currency", func(rows *sql.Rows) string {
		var e database.Earning
		scanInto(rows, &e.ExecutorID, &e.Currency, &e.TotalIncome, &e.CurrentBalance, &e.SuiWalletAddress)
		return fmt.Sprintf("%s %s income=%d balance=%d wallet=%s", e.ExecutorID, e.Currency, e.TotalIncome, e.CurrentBalance, e.SuiWalletAddress)
	})
	b.WriteString("chain_transfers\n")
	var digests []string
	query("SELECT id, kind, executor_id, transaction_id, order_id, amount, currency, receiver, state, digest, signed_transaction, signature, detail FROM chain_transfers ORDER BY id", func(rows *sql.Rows) string {
		var c database.ChainTransfer
		scanInto(rows, &c.ID, &c.Kind, &c.ExecutorID, &c.TransactionID, &c.OrderID, &c.Amount, &c.Currency, &c.Receiver,
			&c.State, &c.Digest, &c.SignedTransaction, &c.Signature, &c.Detail)
		signed := "unsigned"
		if _, err := sui.RestorePreparedTransfer(c.Digest, c.SignedTransaction, c.Signature); err == nil {
			signed = "signed"
		}
		digests = append(digests, c.Digest)
		return fmt.Sprintf("%d %s executor=%s tx=%s order=%s %d %s to=%s %s %s %s detail=%q", c.ID, c.Kind, c.ExecutorID, c.TransactionID,
			nullable(c.OrderID), c.Amount, c.Currency, c.Receiver, c.State, c.Digest, signed, c.Detail)
	})
	b.WriteString("payment_receipts\n")
	query("SELECT tx_digest, event_seq, nonce, disposition, amount, coin_type, receiver, checkpoint, detail FROM payment_receipts ORDER BY tx_digest, event_seq", func(rows *sql.Rows) string {
		var p database.PaymentReceipt
		scanInto(rows, &p.TxDigest, &p.EventSeq, &p.Nonce, &p.Disposition, &p.Amount, &p.CoinType, &p.Receiver, &p.Checkpoint, &p.Detail)
		return fmt.Sprintf("%s#%d nonce=%s %s %s %s to=%s checkpoint=%s detail=%q", p.TxDigest, p.EventSeq, p.Nonce, p.Disposition,
			p.Amount, p.CoinType, p.Receiver, nullable(p.Checkpoint), p.Detail)
	})

	names := []string{sui.GetCoinType("USDC", "testnet"), "USDC-COIN", testWallet, "WALLET", rehearsalBuyer, "BUYER"}
	for i, d := range digests {
		if d != "" {
			names = append(names, d, fmt.Sprintf("D%d", i+1))
		}
	}
	return strings.TrimSpace(strings.NewReplacer(names...).Replace(b.String()))
}

// dumpAll renders every column of every row of the tables the payment
// lifecycle writes, timestamps and stored bytes included.
func dumpAll(t *testing.T, db *sql.DB) string {
	t.Helper()
	var b strings.Builder
	for _, table := range []string{"transactions", "debuglet_order", "order_settlements", "earnings", "chain_transfers",
		"payment_receipts", "debuglets", "measurement_execution", "transaction_states"} {
		rows, err := db.QueryContext(t.Context(), "SELECT * FROM "+table+" ORDER BY rowid")
		if err != nil {
			t.Fatalf("dump %s: %v", table, err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%s %v\n", table, columns)
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			for i, v := range values {
				if raw, ok := v.([]byte); ok {
					values[i] = hex.EncodeToString(raw)
				}
			}
			fmt.Fprintf(&b, "  %v\n", values)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
	return b.String()
}

// ---- drills ----

// Drill 1: a USDC intent is paid by its receipt, its orders are admitted and
// complete, each is credited once, and the executor's balance is paid out
// and confirmed. A replayed receipt is a duplicate and a second payment of
// the same intent is recorded as a mismatch; earnings credited while the
// payout is on its way stay in the balance.
func drillPaidRunIsCreditedAndPaidOut(r *rehearsal) {
	t := r.t
	r.step("registration", r.register)
	r.step("intent", func() {
		if err := r.intent(testTxID, "USDC", 7, 8); err != nil {
			t.Fatalf("intent: %v", err)
		}
		if _, ok := r.admit(testTxID, 1); ok {
			t.Fatal("an unpaid order was admitted")
		}
	})
	r.step("receipt", func() { r.applyReceipt(r.receipt("receipt-1", testTxID, 15, 12), sui.ReceiptApplied) })
	r.step("replayed and second receipts", func() {
		r.applyReceipt(r.receipt("receipt-1", testTxID, 15, 12), sui.ReceiptDuplicate)
		r.applyReceipt(r.receipt("receipt-2", testTxID, 15, 13), sui.ReceiptMismatch)
	})
	var runs []database.Debuglet
	r.step("admission", func() { runs = []database.Debuglet{r.mustAdmit(testTxID, 1), r.mustAdmit(testTxID, 2)} })
	r.step("terminal", func() { r.terminate(runs[0], 0) })
	r.step("credit", func() {
		r.settle(runs[0], 0)
		r.settle(runs[0], 0)
		r.pass(0)
	})
	r.step("payout", func() {
		// The second run completes and is credited while the payout is
		// with the chain.
		r.chain.onExecute = func() {
			r.terminate(runs[1], 0)
			r.settle(runs[1], 0)
		}
		r.payout()
		r.chain.onExecute = nil
	})
	r.step("reconciliation", func() { r.reconcile(lookupResult{outcome: sui.TransferConfirmed, verified: true}) })
	r.step("later passes", func() {
		r.pass(0)
		r.reconcile()
	})

	r.expectTables(`
transactions
  tx-1 15 USDC/SUI TransactionPaid rule=""
debuglet_order
  tx-1#1 exec-1 7 USDC TransactionCredited refund=BUYER run=1
  tx-1#2 exec-1 8 USDC TransactionCredited refund=BUYER run=2
order_settlements
  tx-1#1 credit 7 USDC exec-1 run=1
  tx-1#2 credit 8 USDC exec-1 run=2
earnings
  exec-1 USDC income=15 balance=8 wallet=WALLET
chain_transfers
  1 payout executor=exec-1 tx= order=- 7 USDC to=WALLET confirmed D1 signed detail=""
payment_receipts
  receipt-1#0 nonce=tx-1 applied 15 USDC-COIN to=0xdead checkpoint=12 detail=""
  receipt-2#0 nonce=tx-1 mismatch 15 USDC-COIN to=0xdead checkpoint=13 detail="already paid by receipt-1 event 0"`)
	r.expectCalls(map[string]int{"CreatePaymentIntent": 1, "PrepareTransfer": 1, "ExecuteTransfer": 1, "LookupTransfer": 1})
}

// creditedBalance brings the fixture to one paid, completed and credited
// order of testPrice, so the executor holds a balance to pay out.
func creditedBalance(r *rehearsal) {
	t := r.t
	r.step("registration", r.register)
	r.step("intent", func() {
		if err := r.intent(testTxID, "USDC", testPrice); err != nil {
			t.Fatalf("intent: %v", err)
		}
	})
	r.step("receipt", func() { r.applyReceipt(r.receipt("receipt-1", testTxID, uint64(testPrice), 12), sui.ReceiptApplied) })
	var run database.Debuglet
	r.step("admission", func() { run = r.mustAdmit(testTxID, 1) })
	r.step("terminal", func() { r.terminate(run, 0) })
	r.step("credit", func() { r.settle(run, 0) })
}

const creditedTables = `
transactions
  tx-1 7 USDC/SUI TransactionPaid rule=""
debuglet_order
  tx-1#1 exec-1 7 USDC TransactionCredited refund=BUYER run=1
order_settlements
  tx-1#1 credit 7 USDC exec-1 run=1
earnings
  exec-1 USDC income=7 balance=0 wallet=WALLET
chain_transfers
  1 payout executor=exec-1 tx= order=- 7 USDC to=WALLET confirmed D1 signed detail=""
payment_receipts
  receipt-1#0 nonce=tx-1 applied 7 USDC-COIN to=0xdead checkpoint=12 detail=""`

// Drill 2: the payout's chain call loses its response. The transfer is
// unknown with the amount still reserved; a lookup that confirms execution
// without verifying the receiver's credit leaves it unknown, a verified one
// confirms it. Nothing is submitted a second time.
func drillLostResponseIsResolvedByLookup(r *rehearsal) {
	t := r.t
	creditedBalance(r)
	r.step("payout with a lost response", func() {
		r.chain.smu.Lock()
		r.chain.executeErrs = []error{errLostResponse}
		r.chain.smu.Unlock()
		r.payout()
		if row := onlyTransfer(t, r.db); row.State != transferUnknown || row.Detail != errLostResponse.Error() {
			t.Fatalf("payout with a lost response %+v", row)
		}
		if got := earningOf(t, r.db, testExecutor).CurrentBalance; got != 0 {
			t.Fatalf("balance %d while the payout is unknown", got)
		}
	})
	r.step("unverified lookup", func() {
		r.reconcile(lookupResult{outcome: sui.TransferConfirmed, verified: false})
		if row := onlyTransfer(t, r.db); row.State != transferUnknown || !strings.Contains(row.Detail, "could not be verified") {
			t.Fatalf("payout after an unverified lookup %+v", row)
		}
	})
	r.step("verified lookup", func() { r.reconcile(lookupResult{outcome: sui.TransferConfirmed, verified: true}) })
	r.step("later passes", func() { r.reconcile() })

	r.expectTables(creditedTables)
	r.expectCalls(map[string]int{"CreatePaymentIntent": 1, "PrepareTransfer": 1, "ExecuteTransfer": 1, "LookupTransfer": 2})
}

// reservePayoutAndStop is a payout that stops after its reservation (SQL
// transaction A) is committed, before the chain is called: the payout's own
// decision, reserving exactly the balance read, and nothing after it.
func reservePayoutAndStop(r *rehearsal) *reservedTransfer {
	t := r.t
	earning := earningOf(t, r.db, testExecutor)
	reserved, err := r.h.prepareAndReserve(r.ctx(), database.ChainTransfer{
		Kind: transferPayout, ExecutorID: testExecutor, Amount: earning.CurrentBalance, Currency: "USDC", Receiver: earning.SuiWalletAddress,
	}, func(q *database.Queries) error {
		n, err := q.ReservePayout(r.ctx(), database.ReservePayoutParams{Amount: earning.CurrentBalance, ExecutorID: testExecutor, Currency: "USDC"})
		if err == nil && n != 1 {
			err = errPayoutNotReserved
		}
		return err
	})
	if err != nil || reserved == nil {
		t.Fatalf("reserve payout: %v", err)
	}
	return reserved
}

// Drill 3: the dispatcher stops after the payout is reserved with its signed
// transaction and before the chain is called. After the restart, a fresh
// reservation is left alone; once it is stale the lookup finds nothing and
// the stored transaction is submitted unchanged, once, with the reserved
// digest; the next reconciliation confirms it.
func drillStopBeforeSubmission(r *rehearsal) {
	t := r.t
	creditedBalance(r)
	var reserved *reservedTransfer
	r.step("reservation", func() { reserved = reservePayoutAndStop(r) })
	r.restart()
	r.step("fresh reservation", func() {
		r.reconcile()
		if row := onlyTransfer(t, r.db); row.State != transferReserved {
			t.Fatalf("a fresh reservation was resolved: %+v", row)
		}
	})
	r.step("stale reservation", r.ageReservations)
	r.step("resubmission", func() {
		r.reconcile(lookupResult{outcome: sui.TransferNotFound})
		row := onlyTransfer(t, r.db)
		executed := r.chain.Executed()
		if row.State != transferSent || row.Digest != reserved.prepared.Digest || len(executed) != 1 || string(executed[0]) != string(row.SignedTransaction) {
			t.Fatalf("resubmission: row %+v, %d submissions", row, len(executed))
		}
	})
	r.step("confirmation", func() { r.reconcile(lookupResult{outcome: sui.TransferConfirmed, verified: true}) })
	r.step("later passes", func() { r.reconcile() })

	r.expectTables(creditedTables)
	r.expectCalls(map[string]int{"CreatePaymentIntent": 1, "PrepareTransfer": 1, "ExecuteTransfer": 1, "LookupTransfer": 2})
	if r.chain.prepares != 1 {
		t.Fatalf("%d preparations, want 1", r.chain.prepares)
	}
}

// Drill 4: the chain executes the payout but the dispatcher stops before the
// outcome (SQL transaction B) is recorded, simulated by refusing the update.
// After the restart, the stale reservation is resolved by lookup; there is
// one chain transfer in total.
func drillStopAfterSubmission(r *rehearsal) {
	t := r.t
	creditedBalance(r)
	r.step("payout without its outcome", func() {
		r.exec(`CREATE TRIGGER stop_before_outcome BEFORE UPDATE ON chain_transfers
BEGIN SELECT RAISE(ABORT, 'stopped before the outcome was recorded'); END;`)
		r.payout()
		if row := onlyTransfer(t, r.db); row.State != transferReserved || len(r.chain.Executed()) != 1 {
			t.Fatalf("payout whose outcome was not recorded: %+v, %d submissions", row, len(r.chain.Executed()))
		}
	})
	r.restart()
	r.step("restarted", func() {
		r.exec("DROP TRIGGER stop_before_outcome")
		r.reconcile()
	})
	r.step("stale reservation", r.ageReservations)
	r.step("lookup", func() { r.reconcile(lookupResult{outcome: sui.TransferConfirmed, verified: true}) })
	r.step("later passes", func() { r.reconcile() })

	r.expectTables(creditedTables)
	r.expectCalls(map[string]int{"CreatePaymentIntent": 1, "PrepareTransfer": 1, "ExecuteTransfer": 1, "LookupTransfer": 1})
}

// Drill 5: a failed USDC run is refunded and the refund transfer fails
// before broadcast. The order stays Refunded with its settlement row
// unchanged, and the failed transfer is the record of what is owed: neither
// a settlement pass nor reconciliation sends it again. A second failed run
// whose refund was never attempted is refunded by the settlement pass
// exactly once, reserved before it is submitted.
func drillFailedRefund(r *rehearsal) {
	t := r.t
	r.step("registration", r.register)
	r.step("intent", func() {
		if err := r.intent(testTxID, "USDC", 7, 8); err != nil {
			t.Fatalf("intent: %v", err)
		}
	})
	r.step("receipt", func() { r.applyReceipt(r.receipt("receipt-1", testTxID, 15, 12), sui.ReceiptApplied) })
	var runs []database.Debuglet
	r.step("admission", func() { runs = []database.Debuglet{r.mustAdmit(testTxID, 1), r.mustAdmit(testTxID, 2)} })
	r.step("terminal", func() { r.terminate(runs[0], 3) })
	var decided database.OrderSettlement
	r.step("refund not broadcast", func() {
		r.chain.smu.Lock()
		r.chain.executeErrs = []error{fmt.Errorf("%w: gas coins changed", sui.ErrNotBroadcast)}
		r.chain.smu.Unlock()
		r.settle(runs[0], 3)
		var err error
		if decided, err = database.New(r.db).GetOrderSettlement(r.ctx(), database.GetOrderSettlementParams{TransactionID: testTxID, OrderID: 1}); err != nil {
			t.Fatal(err)
		}
	})
	r.step("passes and reconciliation", func() {
		r.pass(0)
		r.reconcile()
		r.settle(runs[0], 3)
		r.settle(runs[0], 0)
		if n := count(r.chain.Calls(), "ExecuteTransfer"); n != 1 {
			t.Fatalf("%d submissions of the failed refund, want 1", n)
		}
	})
	r.step("second failed run", func() { r.terminate(runs[1], 3) })
	r.step("owed refund", func() {
		r.chain.onExecute = func() {
			rows := transferRows(t, r.db)
			order, err := database.New(r.db).GetDebugletOrder(r.ctx(), database.GetDebugletOrderParams{TransactionID: testTxID, OrderID: 2})
			if err != nil || len(rows) != 2 || rows[1].State != transferReserved || len(rows[1].SignedTransaction) == 0 || order.State != int64(models.Refunded) {
				t.Errorf("submitted before the refund was reserved: %+v, order %+v (%v)", rows, order, err)
			}
		}
		r.pass(1)
		r.chain.onExecute = nil
		r.pass(0)
	})
	r.step("reconciliation", func() { r.reconcile(lookupResult{outcome: sui.TransferConfirmed, verified: true}) })
	r.step("later passes", func() {
		r.pass(0)
		r.reconcile()
	})

	after, err := database.New(r.db).GetOrderSettlement(r.ctx(), database.GetOrderSettlementParams{TransactionID: testTxID, OrderID: 1})
	if err != nil || after != decided {
		t.Fatalf("the settlement of the failed refund changed: %+v, was %+v (%v)", after, decided, err)
	}
	r.expectTables(`
transactions
  tx-1 15 USDC/SUI TransactionPaid rule=""
debuglet_order
  tx-1#1 exec-1 7 USDC TransactionRefunded refund=BUYER run=1
  tx-1#2 exec-1 8 USDC TransactionRefunded refund=BUYER run=2
order_settlements
  tx-1#1 refund 7 USDC exec-1 run=1
  tx-1#2 refund 8 USDC exec-1 run=2
earnings
  exec-1 USDC income=0 balance=0 wallet=WALLET
chain_transfers
  1 refund executor= tx=tx-1 order=1 7 USDC to=BUYER failed D1 signed detail="transfer not broadcast: gas coins changed"
  2 refund executor= tx=tx-1 order=2 8 USDC to=BUYER confirmed D2 signed detail=""
payment_receipts
  receipt-1#0 nonce=tx-1 applied 15 USDC-COIN to=0xdead checkpoint=12 detail=""`)
	r.expectCalls(map[string]int{"CreatePaymentIntent": 1, "PrepareTransfer": 2, "ExecuteTransfer": 2, "LookupTransfer": 1})
}

// Drill 6: the inline credit after the terminal report fails; the order
// stays Outstanding and the settlement pass credits it once. A later
// duplicate terminal report, with the same or another exit code, changes
// nothing.
func drillSweepDeliversAFailedCredit(r *rehearsal) {
	t := r.t
	r.step("registration", r.register)
	r.step("intent", func() {
		if err := r.intent(testTxID, "USDC", testPrice); err != nil {
			t.Fatalf("intent: %v", err)
		}
	})
	r.step("receipt", func() { r.applyReceipt(r.receipt("receipt-1", testTxID, uint64(testPrice), 12), sui.ReceiptApplied) })
	var run database.Debuglet
	r.step("admission", func() { run = r.mustAdmit(testTxID, 1) })
	r.step("terminal", func() { r.terminate(run, 0) })
	r.step("inline credit fails", func() {
		r.exec(`CREATE TRIGGER refuse_settlement BEFORE INSERT ON order_settlements
BEGIN SELECT RAISE(ABORT, 'settlement refused'); END;`)
		if err := r.h.SettleTerminalOrder(r.ctx(), &run, 0); err == nil || !strings.Contains(err.Error(), "settlement refused") {
			t.Fatalf("inline credit = %v, want the refused settlement", err)
		}
		if got := earningOf(t, r.db, testExecutor); got.TotalIncome != 0 || got.CurrentBalance != 0 {
			t.Fatalf("earnings after a failed credit %+v", got)
		}
	})
	r.step("sweep", func() {
		r.exec("DROP TRIGGER refuse_settlement")
		r.pass(1)
		r.pass(0)
	})
	r.step("duplicate terminal reports", func() {
		if err := database.New(r.db).RecordMeasurementTerminal(r.ctx(), database.RecordMeasurementTerminalParams{
			DebugletID: run.ID, ExitCode: sql.NullInt64{Int64: 3, Valid: true},
		}); err != nil {
			t.Fatal(err)
		}
		r.settle(run, 0)
		r.settle(run, 3)
		r.pass(0)
	})

	r.expectTables(`
transactions
  tx-1 7 USDC/SUI TransactionPaid rule=""
debuglet_order
  tx-1#1 exec-1 7 USDC TransactionCredited refund=BUYER run=1
order_settlements
  tx-1#1 credit 7 USDC exec-1 run=1
earnings
  exec-1 USDC income=7 balance=7 wallet=WALLET
chain_transfers
payment_receipts
  receipt-1#0 nonce=tx-1 applied 7 USDC-COIN to=0xdead checkpoint=12 detail=""`)
	r.expectCalls(map[string]int{"CreatePaymentIntent": 1})
}

// Drill 8: with chain payments disabled every chain action is refused with
// ErrPaymentsDisabled and reaches neither the chain nor the transfer and
// receipt tables, also for chain orders an earlier enabled deployment left
// behind; TEST intents are paid, credited and refunded as before.
func drillDisabled(r *rehearsal) {
	t := r.t
	disabled := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrPaymentsDisabled) {
			t.Fatalf("%s = %v, want %v", what, err, ErrPaymentsDisabled)
		}
	}
	r.step("chain intent and receipt", func() {
		disabled("CheckPaymentMethod(USDC)", r.h.CheckPaymentMethod("USDC"))
		disabled("CheckPaymentMethod(SUI)", r.h.CheckPaymentMethod("SUI"))
		if err := r.h.CheckPaymentMethod("TEST"); err != nil {
			t.Fatalf("CheckPaymentMethod(TEST) = %v", err)
		}
		disabled("USDC intent", r.intent("tx-usdc", "USDC", testPrice))
		_, err := r.h.ApplyPaymentReceipt(r.ctx(), sui.PaymentReceipt{Digest: "receipt-1", Nonce: testTxID, Amount: 15,
			CoinType: sui.GetCoinType("USDC", "testnet"), Receiver: "0xdead", Timestamp: time.Now()})
		disabled("ApplyPaymentReceipt", err)
		// Start returns at once and starts nothing.
		if err := r.h.Start(r.ctx()); err != nil {
			t.Fatalf("Start = %v", err)
		}
	})
	// Chain orders recorded by an earlier enabled deployment: paid, admitted
	// and completed, with a balance to pay out.
	var runs []database.Debuglet
	r.step("earlier chain orders", func() {
		seedUSDCTransaction(t, r.db, 7, 8)
		runs = []database.Debuglet{r.mustAdmit(testTxID, 1), r.mustAdmit(testTxID, 2)}
		r.terminate(runs[0], 0)
		r.terminate(runs[1], 3)
		seedEarning(t, r.db, testExecutor, testBalance, testWallet)
	})
	r.step("chain settlement and transfers", func() {
		disabled("credit", r.h.SettleTerminalOrder(r.ctx(), &runs[0], 0))
		disabled("refund", r.h.SettleTerminalOrder(r.ctx(), &runs[1], 3))
		disabled("RefundDebugletOrder", r.h.RefundDebugletOrder(&runs[1], rehearsalBuyer, r.ctx()))
		disabled("RefundTransaction", r.h.RefundTransaction(testTxID, r.ctx()))
		disabled("RefundUnadmittedTransaction", r.h.RefundUnadmittedTransaction(testTxID, r.ctx()))
		disabled("PayoutExecutor", r.h.PayoutExecutor(earningOf(t, r.db, testExecutor), r.ctx()))
		disabled("TransferUSDC", r.h.TransferUSDC(1, testWallet, r.ctx()))
		disabled("ReconcileTransfers", r.h.ReconcileTransfers(r.ctx(), 10))
		if settled, failed, deferred, _, err := r.h.SettlePendingOrders(r.ctx(), 0, 32); settled != 0 || failed != 0 || deferred != 2 || err != nil {
			t.Fatalf("pass: settled %d, failed %d, deferred %d, error %v", settled, failed, deferred, err)
		}
	})
	r.step("TEST intent", func() {
		if err := r.intent("tx-test", "TEST", 5, 6); err != nil {
			t.Fatalf("TEST intent: %v", err)
		}
	})
	var testRuns []database.Debuglet
	r.step("TEST admission", func() { testRuns = []database.Debuglet{r.mustAdmit("tx-test", 1), r.mustAdmit("tx-test", 2)} })
	r.step("TEST terminal", func() {
		r.terminate(testRuns[0], 0)
		r.terminate(testRuns[1], 3)
	})
	r.step("TEST settlement", func() {
		r.settle(testRuns[0], 0)
		if settled, failed, deferred, _, err := r.h.SettlePendingOrders(r.ctx(), 0, 32); settled != 1 || failed != 0 || deferred != 2 || err != nil {
			t.Fatalf("pass: settled %d, failed %d, deferred %d, error %v", settled, failed, deferred, err)
		}
	})

	r.expectTables(`
transactions
  tx-1 15 USDC/SUI TransactionPaid rule=""
  tx-test 11 TEST/TEST TransactionPaid rule=""
debuglet_order
  tx-1#1 exec-1 7 USDC TransactionOutstanding refund=WALLET run=1
  tx-1#2 exec-1 8 USDC TransactionOutstanding refund=WALLET run=2
  tx-test#1 exec-1 5 TEST TransactionCredited refund=BUYER run=3
  tx-test#2 exec-1 6 TEST TransactionRefunded refund=BUYER run=4
order_settlements
  tx-test#1 credit 5 TEST exec-1 run=3
  tx-test#2 refund 6 TEST exec-1 run=4
earnings
  exec-1 TEST income=5 balance=5 wallet=
  exec-1 USDC income=100 balance=100 wallet=WALLET
chain_transfers
payment_receipts`)
	r.expectCalls(map[string]int{})
}

func TestRehearsalPaidRunIsCreditedAndPaidOut(t *testing.T) {
	drillPaidRunIsCreditedAndPaidOut(newRehearsal(t, false, false))
}

func TestRehearsalLostResponseIsResolvedByLookup(t *testing.T) {
	drillLostResponseIsResolvedByLookup(newRehearsal(t, false, false))
}

func TestRehearsalStopBeforeSubmission(t *testing.T) {
	drillStopBeforeSubmission(newRehearsal(t, false, false))
}

func TestRehearsalStopAfterSubmission(t *testing.T) {
	drillStopAfterSubmission(newRehearsal(t, false, false))
}

func TestRehearsalFailedRefund(t *testing.T) {
	drillFailedRefund(newRehearsal(t, false, false))
}

func TestRehearsalSweepDeliversAFailedCredit(t *testing.T) {
	drillSweepDeliversAFailedCredit(newRehearsal(t, false, false))
}

// Drill 7: every drill again, with the dispatcher stopped and its database
// file reopened after every step. Every row reads back identically and every
// drill ends in the same rows with the same chain calls.
func TestRehearsalRecovery(t *testing.T) {
	for name, drill := range map[string]func(*rehearsal){
		"paid run":           drillPaidRunIsCreditedAndPaidOut,
		"lost response":      drillLostResponseIsResolvedByLookup,
		"stop before submit": drillStopBeforeSubmission,
		"stop after submit":  drillStopAfterSubmission,
		"failed refund":      drillFailedRefund,
		"sweep":              drillSweepDeliversAFailedCredit,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRehearsal(t, false, true)
			drill(r)
			if r.restarts < 5 {
				t.Fatalf("%d restarts", r.restarts)
			}
		})
	}
	t.Run("disabled", func(t *testing.T) { drillDisabled(newRehearsal(t, true, true)) })
}

func TestRehearsalDisabledMode(t *testing.T) {
	drillDisabled(newRehearsal(t, true, false))
}
