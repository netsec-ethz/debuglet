package payments

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"

	"github.com/DATA-DOG/go-sqlmock"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	_ "modernc.org/sqlite"
)

// waitBound is the upper bound for every join in this package's tests. A
// join that needs longer than this is a hang, not slowness.
const waitBound = 2 * time.Second

// Exact SQL of the generated queries (internal/dispatcher/database/
// transactions.sql.go). sqlmock matches these as regular expressions against
// the full statement, so the multi-line statements keep their newlines and
// the GetTransactionOrders pattern is anchored to avoid matching the longer
// GetDebugletOrder statement.
var (
	transactionColumns = []string{"id", "auth_key", "price", "method", "expires_at", "hash", "currency", "status"}
	orderColumns       = []string{"transaction_id", "order_id", "executor_id", "price", "currency", "state", "refund_address", "debuglet_id"}
	earningsColumns    = []string{"executor_id", "currency", "total_income", "current_balance", "sui_wallet_address"}

	createTransactionQuery = regexp.QuoteMeta(
		"INSERT INTO transactions (id, auth_key, price, currency, method, expires_at, status, hash)\nVALUES (?, ?, ?, ?, ?, ?, ?, ?)\nRETURNING id, auth_key, price, method, expires_at, hash, currency, status",
	)
	getTransactionByIDQuery = regexp.QuoteMeta(
		"SELECT id, auth_key, price, method, expires_at, hash, currency, status FROM transactions\nWHERE id = ?",
	)
	updateTransactionStatusQuery = regexp.QuoteMeta(
		"UPDATE transactions\nSET status = ?\nWHERE id = ?",
	)
	getDebugletOrderQuery = regexp.QuoteMeta(
		"SELECT transaction_id, order_id, executor_id, price, currency, state, refund_address, debuglet_id FROM debuglet_order\nWHERE transaction_id = ? AND order_id = ?",
	)
	getTransactionOrdersQuery = regexp.QuoteMeta(
		"SELECT transaction_id, order_id, executor_id, price, currency, state, refund_address, debuglet_id FROM debuglet_order\nWHERE transaction_id = ?",
	) + `\s*$`
	updateDebugletOrderStateQuery = regexp.QuoteMeta(
		"UPDATE debuglet_order\nSET state = ? \nWHERE transaction_id = ? AND order_id = ?\nRETURNING transaction_id, order_id, executor_id, price, currency, state, refund_address, debuglet_id",
	)
	getEarningsInQuery = regexp.QuoteMeta(
		"SELECT executor_id, currency, total_income, current_balance, sui_wallet_address FROM earnings\nWHERE executor_id = ? AND currency = ?",
	)
	createEarningsQuery = regexp.QuoteMeta(
		"INSERT INTO earnings (executor_id, currency, sui_wallet_address, total_income, current_balance)\nVALUES (?,?,?,0,0)\nRETURNING executor_id, currency, total_income, current_balance, sui_wallet_address",
	)
	addEarningsQuery = regexp.QuoteMeta(
		"UPDATE earnings\nSET total_income = total_income + ?1,\n    current_balance = current_balance + ?1\nWHERE executor_id = ?2 AND currency = ?3",
	)
)

const (
	testTxID     = "tx-1"
	testOrderID  = int64(1)
	testExecutor = "exec-1"
	testHash     = "hash-1"
	testRefund   = "0xrefund"
	testPrice    = int64(7)
)

var errScripted = errors.New("scripted failure")

// ---- scripted dependencies ----

// fakeChain is a scripted chainBackend. Start blocks until the context is
// cancelled or a failure is injected through fail; every other method records
// its arguments.
type fakeChain struct {
	mu        sync.Mutex
	startOnce sync.Once
	doneOnce  sync.Once
	started   chan struct{}
	done      chan struct{}
	fail      chan error
	calls     []string

	intent    sui.SuiPaymentIntent
	intentErr error
	intentTx  string
	intentPx  int64
	intentCcy string
	intentHsh string

	refundOrder   *database.DebugletOrder
	refundAddress string
	refundErr     error

	transferAmount   uint64
	transferCoinType string
	transferAddress  string
	transferErr      error
}

func newFakeChain() *fakeChain {
	return &fakeChain{
		started: make(chan struct{}),
		done:    make(chan struct{}),
		fail:    make(chan error, 1),
	}
}

func (f *fakeChain) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
}

func (f *fakeChain) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeChain) Start(ctx context.Context) error {
	f.record("Start")
	f.startOnce.Do(func() { close(f.started) })
	defer f.doneOnce.Do(func() { close(f.done) })
	select {
	case <-ctx.Done():
		return nil
	case err := <-f.fail:
		return err
	}
}

func (f *fakeChain) CreatePaymentIntent(_ database.DBTX, transactionId string, price int64, currency string, hash string, ctx context.Context) (sui.SuiPaymentIntent, error) {
	f.record("CreatePaymentIntent")
	f.mu.Lock()
	f.intentTx, f.intentPx, f.intentCcy, f.intentHsh = transactionId, price, currency, hash
	f.mu.Unlock()
	return f.intent, f.intentErr
}

func (f *fakeChain) RefundDebuglet(debugletOrder *database.DebugletOrder, refundAddress string, ctx context.Context) error {
	f.record("RefundDebuglet")
	f.mu.Lock()
	f.refundOrder, f.refundAddress = debugletOrder, refundAddress
	f.mu.Unlock()
	return f.refundErr
}

func (f *fakeChain) TransferCoins(amount uint64, cointype string, refundAddress string, ctx context.Context) error {
	f.record("TransferCoins")
	f.mu.Lock()
	f.transferAmount, f.transferCoinType, f.transferAddress = amount, cointype, refundAddress
	f.mu.Unlock()
	return f.transferErr
}

// fakePayout is a scripted payoutLoop that blocks until its context ends.
type fakePayout struct {
	startOnce sync.Once
	doneOnce  sync.Once
	started   chan struct{}
	done      chan struct{}
}

func newFakePayout() *fakePayout {
	return &fakePayout{started: make(chan struct{}), done: make(chan struct{})}
}

func (f *fakePayout) StartPayoutLoop(ctx context.Context) error {
	f.startOnce.Do(func() { close(f.started) })
	defer f.doneOnce.Do(func() { close(f.done) })
	<-ctx.Done()
	return nil
}

// depRecorder counts factory invocations and records their arguments.
type depRecorder struct {
	chain  *fakeChain
	payout *fakePayout

	chainCalls  int
	payoutCalls int
	gotCfg      *config.DispatcherConfig
	gotDB       *sql.DB
	gotLogger   *zap.Logger
	gotTF       sui.TransactionFulfiller
	gotHandler  Handler
}

func newDepRecorder() *depRecorder {
	return &depRecorder{chain: newFakeChain(), payout: newFakePayout()}
}

func (r *depRecorder) deps() paymentDeps {
	return paymentDeps{
		newChain: func(cfg *config.DispatcherConfig, db *sql.DB, logger *zap.Logger, tf sui.TransactionFulfiller) chainBackend {
			r.chainCalls++
			r.gotCfg, r.gotDB, r.gotLogger, r.gotTF = cfg, db, logger, tf
			return r.chain
		},
		newPayout: func(db *sql.DB, h Handler, logger *zap.Logger) payoutLoop {
			r.payoutCalls++
			r.gotHandler = h
			return r.payout
		},
	}
}

// ---- fixtures ----

// staleSui returns deliberately unusable, nonempty chain fields. The keystore
// path does not exist; nothing may try to read it.
func staleSui(t *testing.T) config.SuiConfig {
	t.Helper()
	return config.SuiConfig{
		Network:           "testnet",
		GRPCEndpoint:      "fullnode.invalid:443",
		GraphQLURL:        "https://graphql.invalid/graphql",
		Address:           "0xdead",
		PaymentRegistryId: "0xregistry",
		PaymentKitPackage: "0xpackage",
		KeystorePath:      filepath.Join(t.TempDir(), "missing", "sui.keystore"),
	}
}

func disabledConfig(t *testing.T, stale bool) *config.DispatcherConfig {
	t.Helper()
	cfg := &config.DispatcherConfig{}
	if stale {
		cfg.Sui = staleSui(t)
	}
	cfg.Sui.Disabled = true
	return cfg
}

func enabledConfig(t *testing.T) *config.DispatcherConfig {
	t.Helper()
	cfg := &config.DispatcherConfig{Sui: staleSui(t)}
	cfg.Sui.Disabled = false
	return cfg
}

func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() {
		mock.ExpectClose()
		if err := db.Close(); err != nil {
			t.Errorf("close mock db: %v", err)
		}
	})
	return db, mock
}

// newDisabledHandler builds a disabled handler through the guarded helper and
// proves that neither factory ran. When inject is set, scripted services are
// attached afterwards so that a guard that wrongly reaches the backend is
// observed as a recorded call rather than a nil-pointer panic.
func newDisabledHandler(t *testing.T, db *sql.DB, stale bool, inject bool) (*PaymentHandler, *depRecorder) {
	t.Helper()
	rec := newDepRecorder()
	h := newPaymentHandler(db, disabledConfig(t, stale), zap.NewNop(), rec.deps())
	if rec.chainCalls != 0 || rec.payoutCalls != 0 {
		t.Fatalf("disabled construction invoked factories: chain=%d payout=%d", rec.chainCalls, rec.payoutCalls)
	}
	if h.sui != nil || h.pt != nil {
		t.Fatalf("disabled handler holds services: sui=%v pt=%v", h.sui, h.pt)
	}
	if inject {
		h.sui = rec.chain
		h.pt = rec.payout
	}
	return h, rec
}

func newEnabledHandler(t *testing.T, db *sql.DB, cfg *config.DispatcherConfig) (*PaymentHandler, *depRecorder) {
	t.Helper()
	rec := newDepRecorder()
	h := newPaymentHandler(db, cfg, zap.NewNop(), rec.deps())
	if rec.chainCalls != 1 || rec.payoutCalls != 1 {
		t.Fatalf("enabled construction factory counts: chain=%d payout=%d, want 1/1", rec.chainCalls, rec.payoutCalls)
	}
	return h, rec
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(waitBound):
		t.Fatalf("%s did not happen within %v", what, waitBound)
	}
}

func waitErr(t *testing.T, ch <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(waitBound):
		t.Fatalf("%s did not return within %v", what, waitBound)
		return nil
	}
}

func transactionRow(method string, status models.TransactionState) *sqlmock.Rows {
	return sqlmock.NewRows(transactionColumns).AddRow(
		testTxID, "", testPrice, method, time.Now().Add(5*time.Minute), testHash, method, int64(status),
	)
}

func orderRow(currency string, state models.TransactionState) *sqlmock.Rows {
	return sqlmock.NewRows(orderColumns).AddRow(
		testTxID, testOrderID, testExecutor, testPrice, currency, int64(state), testRefund, nil,
	)
}

func testDebuglet() *database.Debuglet {
	return &database.Debuglet{TransactionID: testTxID, OrderID: testOrderID, ExecutorID: testExecutor}
}

func expectOrderRead(mock sqlmock.Sqlmock, currency string, state models.TransactionState) {
	mock.ExpectQuery(getDebugletOrderQuery).WithArgs(testTxID, testOrderID).WillReturnRows(orderRow(currency, state))
}

func expectTransactionRead(mock sqlmock.Sqlmock, method string, status models.TransactionState) {
	mock.ExpectQuery(getTransactionByIDQuery).WithArgs(testTxID).WillReturnRows(transactionRow(method, status))
}

func expectTransactionOrdersRead(mock sqlmock.Sqlmock, currency string, n int) {
	rows := sqlmock.NewRows(orderColumns)
	for i := 1; i <= n; i++ {
		rows.AddRow(testTxID, int64(i), testExecutor, testPrice, currency, int64(models.Paid), testRefund, nil)
	}
	mock.ExpectQuery(getTransactionOrdersQuery).WithArgs(testTxID).WillReturnRows(rows)
}

// expiresWithin matches a time.Time argument that lies in [now+d-slack, now+d+slack].
type expiresWithin struct {
	d     time.Duration
	slack time.Duration
}

func (e expiresWithin) Match(v driver.Value) bool {
	ts, ok := v.(time.Time)
	if !ok {
		return false
	}
	want := time.Now().Add(e.d)
	return ts.After(want.Add(-e.slack)) && ts.Before(want.Add(e.slack))
}

func assertMet(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// ---- construction and lifetime ----

func TestDisabledConstructionInvokesNoFactory(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprintf("stale=%v", stale), func(t *testing.T) {
			db, mock := newMockDB(t)
			h, rec := newDisabledHandler(t, db, stale, false)

			// Disabled Start must be synchronous and immediate; a Start that
			// blocked here would trip the package test timeout, and a Start
			// that spawned work would raise the goroutine count.
			before := runtime.NumGoroutine()
			for i := 0; i < 2; i++ {
				if err := h.Start(context.Background()); err != nil {
					t.Fatalf("disabled Start #%d returned %v", i+1, err)
				}
			}
			if after := runtime.NumGoroutine(); after > before {
				t.Fatalf("disabled Start left goroutines behind: %d -> %d", before, after)
			}
			if rec.chainCalls != 0 || rec.payoutCalls != 0 {
				t.Fatalf("Start invoked factories: chain=%d payout=%d", rec.chainCalls, rec.payoutCalls)
			}
			select {
			case <-rec.chain.started:
				t.Fatalf("scripted chain backend was started in disabled mode")
			case <-rec.payout.started:
				t.Fatalf("scripted payout loop was started in disabled mode")
			default:
			}
			assertMet(t, mock)
		})
	}
}

// TestPublicConstructorDisabled proves the exported constructor uses the same
// gate: with disabled=true and unusable chain fields it neither panics nor
// constructs the chain/payout services.
func TestPublicConstructorDisabled(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprintf("stale=%v", stale), func(t *testing.T) {
			db, mock := newMockDB(t)
			h := NewPaymentHandler(db, disabledConfig(t, stale), zap.NewNop())
			if h.sui != nil || h.pt != nil {
				t.Fatalf("public constructor built services in disabled mode: sui=%v pt=%v", h.sui, h.pt)
			}
			if err := h.Start(context.Background()); err != nil {
				t.Fatalf("disabled Start: %v", err)
			}
			assertMet(t, mock)
		})
	}
}

func TestEnabledConstructionInvokesBothFactoriesOnce(t *testing.T) {
	cases := []struct {
		name string
		cfg  func(t *testing.T) *config.DispatcherConfig
	}{
		{"disabled false", enabledConfig},
		{"sui omitted", func(t *testing.T) *config.DispatcherConfig { return &config.DispatcherConfig{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := newMockDB(t)
			cfg := tc.cfg(t)
			logger := zap.NewNop()
			rec := newDepRecorder()
			h := newPaymentHandler(db, cfg, logger, rec.deps())

			if rec.chainCalls != 1 || rec.payoutCalls != 1 {
				t.Fatalf("factory counts chain=%d payout=%d, want 1/1", rec.chainCalls, rec.payoutCalls)
			}
			if rec.gotCfg != cfg || rec.gotDB != db || rec.gotLogger != logger {
				t.Fatalf("chain factory received wrong arguments")
			}
			if rec.gotTF != sui.TransactionFulfiller(h) {
				t.Fatalf("chain factory did not receive the handler as TransactionFulfiller")
			}
			if rec.gotHandler != Handler(h) {
				t.Fatalf("payout factory did not receive the handler as Handler")
			}
			if h.sui != chainBackend(rec.chain) || h.pt != payoutLoop(rec.payout) {
				t.Fatalf("handler does not hold the constructed services")
			}
			assertMet(t, mock)
		})
	}
}

func TestEnabledStartRunsBothAndJoinsOnCancel(t *testing.T) {
	db, mock := newMockDB(t)
	h, rec := newEnabledHandler(t, db, enabledConfig(t))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- h.Start(ctx) }()

	waitClosed(t, rec.chain.started, "chain listener start")
	waitClosed(t, rec.payout.started, "payout loop start")

	select {
	case err := <-errCh:
		t.Fatalf("Start returned before cancellation: %v", err)
	default:
	}

	cancel()
	if err := waitErr(t, errCh, "Start after cancellation"); err != nil {
		t.Fatalf("Start returned %v after cancellation, want nil", err)
	}
	waitClosed(t, rec.chain.done, "chain listener exit")
	waitClosed(t, rec.payout.done, "payout loop exit")
	assertMet(t, mock)
}

func TestEnabledStartPropagatesListenerError(t *testing.T) {
	db, mock := newMockDB(t)
	h, rec := newEnabledHandler(t, db, enabledConfig(t))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- h.Start(ctx) }()

	waitClosed(t, rec.chain.started, "chain listener start")
	waitClosed(t, rec.payout.started, "payout loop start")

	rec.chain.fail <- errScripted
	err := waitErr(t, errCh, "Start after listener failure")
	if !errors.Is(err, errScripted) {
		t.Fatalf("Start returned %v, want listener error %v", err, errScripted)
	}
	// The listener failure must have cancelled the payout loop as well.
	waitClosed(t, rec.payout.done, "payout loop exit after listener failure")
	if ctx.Err() != nil {
		t.Fatalf("caller context was cancelled by Start")
	}
	assertMet(t, mock)
}

// ---- preflight ----

func TestCheckPaymentMethod(t *testing.T) {
	cases := []struct {
		method   string
		disabled bool
		want     error // nil, ErrPaymentsDisabled or ErrUnsupportedPaymentMethod
	}{
		{"TEST", true, nil},
		{"TEST", false, nil},
		{"USDC", true, ErrPaymentsDisabled},
		{"USDC", false, nil},
		{"SUI", true, ErrPaymentsDisabled},
		{"SUI", false, nil},
		{"BTC", true, ErrUnsupportedPaymentMethod},
		{"BTC", false, ErrUnsupportedPaymentMethod},
		{"", true, ErrUnsupportedPaymentMethod},
		{"", false, ErrUnsupportedPaymentMethod},
		{"usdc", false, ErrUnsupportedPaymentMethod},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%q/disabled=%v", tc.method, tc.disabled), func(t *testing.T) {
			db, mock := newMockDB(t)
			var h *PaymentHandler
			if tc.disabled {
				h, _ = newDisabledHandler(t, db, true, false)
			} else {
				h, _ = newEnabledHandler(t, db, enabledConfig(t))
			}
			err := h.CheckPaymentMethod(tc.method)
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("CheckPaymentMethod(%q) = %v, want nil", tc.method, err)
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("CheckPaymentMethod(%q) = %v, want %v", tc.method, err, tc.want)
			}
			if errors.Is(tc.want, ErrPaymentsDisabled) && err.Error() != "blockchain payments are disabled" {
				t.Fatalf("disabled message %q", err.Error())
			}
			if errors.Is(tc.want, ErrUnsupportedPaymentMethod) && !strings.Contains(err.Error(), tc.method) {
				t.Fatalf("unsupported-method error %q does not name the method", err.Error())
			}
			if errors.Is(err, ErrPaymentsDisabled) && errors.Is(err, ErrUnsupportedPaymentMethod) {
				t.Fatalf("error matches both sentinels: %v", err)
			}
			assertMet(t, mock)
		})
	}
}

// ---- intents ----

func TestEnabledCreatePaymentIntentForwardsToBackend(t *testing.T) {
	for _, method := range []string{"USDC", "SUI"} {
		t.Run(method, func(t *testing.T) {
			db, mock := newMockDB(t)
			h, rec := newEnabledHandler(t, db, enabledConfig(t))
			want := sui.SuiPaymentIntent{
				TransactionId: testTxID, Price: testPrice, CoinType: "0x2::coin", AuthKey: "auth",
				RegistryAddress: "0xregistry", ReceiverAddress: "0xdead",
			}
			rec.chain.intent = want

			got, err := h.CreatePaymentIntent(testTxID, testPrice, method, testHash, context.Background())
			if err != nil {
				t.Fatalf("CreatePaymentIntent: %v", err)
			}
			if calls := rec.chain.Calls(); len(calls) != 1 || calls[0] != "CreatePaymentIntent" {
				t.Fatalf("backend calls %v", calls)
			}
			if rec.chain.intentTx != testTxID || rec.chain.intentPx != testPrice || rec.chain.intentCcy != method || rec.chain.intentHsh != testHash {
				t.Fatalf("forwarded (%q,%d,%q,%q)", rec.chain.intentTx, rec.chain.intentPx, rec.chain.intentCcy, rec.chain.intentHsh)
			}
			if got.method != method {
				t.Fatalf("intent method %q, want %q", got.method, method)
			}
			if gotIntent, ok := got.Intent.(sui.SuiPaymentIntent); !ok || gotIntent != want {
				t.Fatalf("intent payload %#v, want %#v", got.Intent, want)
			}
			assertMet(t, mock)
		})
	}

	t.Run("backend error is wrapped", func(t *testing.T) {
		db, mock := newMockDB(t)
		h, rec := newEnabledHandler(t, db, enabledConfig(t))
		rec.chain.intentErr = errScripted
		_, err := h.CreatePaymentIntent(testTxID, testPrice, "USDC", testHash, context.Background())
		if !errors.Is(err, errScripted) {
			t.Fatalf("CreatePaymentIntent = %v, want wrapped %v", err, errScripted)
		}
		if errors.Is(err, ErrPaymentsDisabled) {
			t.Fatalf("enabled failure reported as disabled: %v", err)
		}
		assertMet(t, mock)
	})
}

func expectDummyIntentInsert(mock sqlmock.Sqlmock) {
	// CreateDummyIntent stores Method "TEST", Status Paid, an empty auth key,
	// the locked price in the TEST currency, the request hash and a
	// five-minute expiry.
	mock.ExpectQuery(createTransactionQuery).
		WithArgs(testTxID, "", testPrice, "TEST", "TEST", expiresWithin{5 * time.Minute, 30 * time.Second}, int64(models.Paid), testHash).
		WillReturnRows(sqlmock.NewRows(transactionColumns).AddRow(
			testTxID, "", testPrice, "TEST", time.Now().Add(5*time.Minute), testHash, "TEST", int64(models.Paid),
		))
}

func TestCreatePaymentIntentTESTCreatesPaidTransaction(t *testing.T) {
	for _, disabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("disabled=%v", disabled), func(t *testing.T) {
			db, mock := newMockDB(t)
			var h *PaymentHandler
			var rec *depRecorder
			if disabled {
				h, rec = newDisabledHandler(t, db, true, true)
			} else {
				h, rec = newEnabledHandler(t, db, enabledConfig(t))
			}
			expectDummyIntentInsert(mock)

			got, err := h.CreatePaymentIntent(testTxID, testPrice, "TEST", testHash, context.Background())
			if err != nil {
				t.Fatalf("CreatePaymentIntent(TEST): %v", err)
			}
			if got.method != "TEST" {
				t.Fatalf("method %q", got.method)
			}
			if intent, ok := got.Intent.(DummyIntent); !ok || intent != (DummyIntent{TransactionId: testTxID, AuthKey: ""}) {
				t.Fatalf("intent payload %#v", got.Intent)
			}
			if calls := rec.chain.Calls(); len(calls) != 0 {
				t.Fatalf("TEST intent reached the chain backend: %v", calls)
			}
			assertMet(t, mock)
		})
	}
}

func TestCreatePaymentIntentUnknownMethod(t *testing.T) {
	db, mock := newMockDB(t)
	h, _ := newDisabledHandler(t, db, true, true)
	_, err := h.CreatePaymentIntent(testTxID, testPrice, "BTC", testHash, context.Background())
	if err == nil || errors.Is(err, ErrPaymentsDisabled) {
		t.Fatalf("unknown method returned %v", err)
	}
	assertMet(t, mock)
}

// ---- disabled guards ----

type guardCase struct {
	name   string
	expect func(mock sqlmock.Sqlmock)
	call   func(h *PaymentHandler, ctx context.Context) error
}

func chainGuardCases() []guardCase {
	var cases []guardCase
	for _, ccy := range []string{"USDC", "SUI"} {
		cases = append(cases,
			guardCase{
				name:   "CreatePaymentIntent " + ccy,
				expect: func(sqlmock.Sqlmock) {},
				call: func(h *PaymentHandler, ctx context.Context) error {
					_, err := h.CreatePaymentIntent(testTxID, testPrice, ccy, testHash, ctx)
					return err
				},
			},
			guardCase{
				name: "RefundDebugletOrder " + ccy + " order",
				expect: func(mock sqlmock.Sqlmock) {
					mock.ExpectBegin()
					expectOrderRead(mock, ccy, models.Paid)
					mock.ExpectRollback()
				},
				call: func(h *PaymentHandler, ctx context.Context) error {
					return h.RefundDebugletOrder(testDebuglet(), testRefund, ctx)
				},
			},
			guardCase{
				name: "RefundTransaction " + ccy,
				expect: func(mock sqlmock.Sqlmock) {
					mock.ExpectBegin()
					expectTransactionRead(mock, ccy, models.Paid)
					expectTransactionOrdersRead(mock, ccy, 2)
					mock.ExpectRollback()
				},
				call: func(h *PaymentHandler, ctx context.Context) error {
					return h.RefundTransaction(testTxID, ctx)
				},
			},
			guardCase{
				name:   "PayoutExecutor " + ccy,
				expect: func(sqlmock.Sqlmock) {},
				call: func(h *PaymentHandler, ctx context.Context) error {
					return h.PayoutExecutor(database.Earning{ExecutorID: testExecutor, Currency: ccy, CurrentBalance: 10, SuiWalletAddress: "0xwallet"}, ctx)
				},
			},
			guardCase{
				name: "SetDebugletOrderComplete " + ccy + " order",
				expect: func(mock sqlmock.Sqlmock) {
					mock.ExpectBegin()
					expectOrderRead(mock, ccy, models.Paid)
					mock.ExpectRollback()
				},
				call: func(h *PaymentHandler, ctx context.Context) error {
					return h.SetDebugletOrderComplete(testDebuglet(), ctx)
				},
			},
		)
	}
	cases = append(cases, guardCase{
		name:   "TransferUSDC",
		expect: func(sqlmock.Sqlmock) {},
		call: func(h *PaymentHandler, ctx context.Context) error {
			return h.TransferUSDC(10, "0xreceiver", ctx)
		},
	})
	return cases
}

// TestDisabledChainGuards runs every error-returning chain method in disabled
// mode. Each must return ErrPaymentsDisabled, make no backend call and issue
// only the permitted reads (sqlmock's strict ordering rejects any UPDATE or
// INSERT that is not expected). The table runs once with the natural nil
// services and once with injected scripted services so an unguarded backend
// call is reported as such rather than as a panic.
func TestDisabledChainGuards(t *testing.T) {
	for _, inject := range []bool{false, true} {
		for _, tc := range chainGuardCases() {
			t.Run(fmt.Sprintf("inject=%v/%s", inject, tc.name), func(t *testing.T) {
				db, mock := newMockDB(t)
				h, rec := newDisabledHandler(t, db, true, inject)
				tc.expect(mock)

				err := tc.call(h, context.Background())
				if !errors.Is(err, ErrPaymentsDisabled) {
					t.Fatalf("%s returned %v, want ErrPaymentsDisabled", tc.name, err)
				}
				if calls := rec.chain.Calls(); len(calls) != 0 {
					t.Fatalf("%s reached the chain backend: %v", tc.name, calls)
				}
				assertMet(t, mock)
			})
		}
	}
}

// TestDisabledTESTPaths checks the database-only TEST behaviour in disabled
// mode: completion credits the executor, refunds keep failing with the
// existing unsupported-currency errors and never commit.
func TestDisabledTESTPaths(t *testing.T) {
	t.Run("SetDebugletOrderComplete credits TEST order", func(t *testing.T) {
		db, mock := newMockDB(t)
		h, rec := newDisabledHandler(t, db, true, true)

		mock.ExpectBegin()
		expectOrderRead(mock, "TEST", models.Outstanding)
		mock.ExpectQuery(updateDebugletOrderStateQuery).
			WithArgs(int64(models.Credited), testTxID, testOrderID).
			WillReturnRows(orderRow("TEST", models.Credited))
		mock.ExpectQuery(getEarningsInQuery).WithArgs(testExecutor, "TEST").WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery(createEarningsQuery).WithArgs(testExecutor, "TEST", "").
			WillReturnRows(sqlmock.NewRows(earningsColumns).AddRow(testExecutor, "TEST", int64(0), int64(0), ""))
		mock.ExpectExec(addEarningsQuery).WithArgs(testPrice, testExecutor, "TEST").WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		if err := h.SetDebugletOrderComplete(testDebuglet(), context.Background()); err != nil {
			t.Fatalf("SetDebugletOrderComplete(TEST): %v", err)
		}
		if calls := rec.chain.Calls(); len(calls) != 0 {
			t.Fatalf("TEST completion reached the chain backend: %v", calls)
		}
		assertMet(t, mock)
	})

	t.Run("RefundDebugletOrder TEST order is unsupported", func(t *testing.T) {
		db, mock := newMockDB(t)
		h, rec := newDisabledHandler(t, db, true, true)

		// Existing behaviour: the state update happens inside the transaction
		// and is rolled back with the unsupported-currency error.
		mock.ExpectBegin()
		expectOrderRead(mock, "TEST", models.Paid)
		mock.ExpectQuery(updateDebugletOrderStateQuery).
			WithArgs(int64(models.Refunded), testTxID, testOrderID).
			WillReturnRows(orderRow("TEST", models.Refunded))
		mock.ExpectRollback()

		err := h.RefundDebugletOrder(testDebuglet(), testRefund, context.Background())
		if err == nil || err.Error() != "Refunds not supported for currency TEST" {
			t.Fatalf("RefundDebugletOrder(TEST) = %v", err)
		}
		if errors.Is(err, ErrPaymentsDisabled) {
			t.Fatalf("TEST refund reported as disabled: %v", err)
		}
		if calls := rec.chain.Calls(); len(calls) != 0 {
			t.Fatalf("TEST refund reached the chain backend: %v", calls)
		}
		assertMet(t, mock)
	})

	t.Run("RefundDebugletOrder already refunded order", func(t *testing.T) {
		db, mock := newMockDB(t)
		h, _ := newDisabledHandler(t, db, true, true)
		mock.ExpectBegin()
		expectOrderRead(mock, "USDC", models.Refunded)
		mock.ExpectRollback()

		err := h.RefundDebugletOrder(testDebuglet(), testRefund, context.Background())
		if err == nil || err.Error() != "Debuglet has already been refunded" {
			t.Fatalf("RefundDebugletOrder(refunded) = %v", err)
		}
		assertMet(t, mock)
	})

	t.Run("RefundTransaction TEST is unsupported", func(t *testing.T) {
		db, mock := newMockDB(t)
		h, rec := newDisabledHandler(t, db, true, true)

		mock.ExpectBegin()
		expectTransactionRead(mock, "TEST", models.Paid)
		expectTransactionOrdersRead(mock, "TEST", 1)
		mock.ExpectQuery(updateDebugletOrderStateQuery).
			WithArgs(int64(models.Refunded), testTxID, testOrderID).
			WillReturnRows(orderRow("TEST", models.Refunded))
		mock.ExpectExec(updateTransactionStatusQuery).
			WithArgs(int64(models.Refunded), testTxID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectRollback()

		err := h.RefundTransaction(testTxID, context.Background())
		if err == nil || !strings.Contains(err.Error(), "Refunds are not supported for currency TEST") {
			t.Fatalf("RefundTransaction(TEST) = %v", err)
		}
		if errors.Is(err, ErrPaymentsDisabled) {
			t.Fatalf("TEST refund reported as disabled: %v", err)
		}
		if calls := rec.chain.Calls(); len(calls) != 0 {
			t.Fatalf("TEST refund reached the chain backend: %v", calls)
		}
		assertMet(t, mock)
	})

	t.Run("RefundTransaction unpaid transaction", func(t *testing.T) {
		db, mock := newMockDB(t)
		h, _ := newDisabledHandler(t, db, true, true)
		mock.ExpectBegin()
		expectTransactionRead(mock, "USDC", models.Outstanding)
		mock.ExpectRollback()

		err := h.RefundTransaction(testTxID, context.Background())
		if err == nil || errors.Is(err, ErrPaymentsDisabled) {
			t.Fatalf("RefundTransaction(unpaid) = %v", err)
		}
		assertMet(t, mock)
	})

	t.Run("PayoutExecutor TEST is unsupported", func(t *testing.T) {
		db, mock := newMockDB(t)
		h, rec := newDisabledHandler(t, db, true, true)
		err := h.PayoutExecutor(database.Earning{ExecutorID: testExecutor, Currency: "TEST", CurrentBalance: 5}, context.Background())
		if err == nil || err.Error() != "Unknown/unallowed currency TEST" || errors.Is(err, ErrPaymentsDisabled) {
			t.Fatalf("PayoutExecutor(TEST) = %v", err)
		}
		if calls := rec.chain.Calls(); len(calls) != 0 {
			t.Fatalf("TEST payout reached the chain backend: %v", calls)
		}
		assertMet(t, mock)
	})
}

// TestUnrelatedReadErrorsArePreserved makes sure a failing lookup surfaces as
// that failure and not as the disabled sentinel, with no write attempted.
func TestUnrelatedReadErrorsArePreserved(t *testing.T) {
	cases := []guardCase{
		{
			name: "SetDebugletOrderComplete order lookup",
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(getDebugletOrderQuery).WithArgs(testTxID, testOrderID).WillReturnError(errScripted)
				mock.ExpectRollback()
			},
			call: func(h *PaymentHandler, ctx context.Context) error {
				return h.SetDebugletOrderComplete(testDebuglet(), ctx)
			},
		},
		{
			name: "RefundDebugletOrder order lookup",
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(getDebugletOrderQuery).WithArgs(testTxID, testOrderID).WillReturnError(errScripted)
				mock.ExpectRollback()
			},
			call: func(h *PaymentHandler, ctx context.Context) error {
				return h.RefundDebugletOrder(testDebuglet(), testRefund, ctx)
			},
		},
		{
			name: "RefundTransaction transaction lookup",
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectQuery(getTransactionByIDQuery).WithArgs(testTxID).WillReturnError(errScripted)
				mock.ExpectRollback()
			},
			call: func(h *PaymentHandler, ctx context.Context) error { return h.RefundTransaction(testTxID, ctx) },
		},
		{
			name: "RefundTransaction orders lookup",
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectTransactionRead(mock, "USDC", models.Paid)
				mock.ExpectQuery(getTransactionOrdersQuery).WithArgs(testTxID).WillReturnError(errScripted)
				mock.ExpectRollback()
			},
			call: func(h *PaymentHandler, ctx context.Context) error { return h.RefundTransaction(testTxID, ctx) },
		},
		{
			name: "SetDebugletOrderComplete begin",
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin().WillReturnError(errScripted)
			},
			call: func(h *PaymentHandler, ctx context.Context) error {
				return h.SetDebugletOrderComplete(testDebuglet(), ctx)
			},
		},
	}
	for _, disabled := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("disabled=%v/%s", disabled, tc.name), func(t *testing.T) {
				db, mock := newMockDB(t)
				var h *PaymentHandler
				var rec *depRecorder
				if disabled {
					h, rec = newDisabledHandler(t, db, true, true)
				} else {
					h, rec = newEnabledHandler(t, db, enabledConfig(t))
				}
				tc.expect(mock)
				err := tc.call(h, context.Background())
				if !errors.Is(err, errScripted) {
					t.Fatalf("%s returned %v, want wrapped %v", tc.name, err, errScripted)
				}
				if errors.Is(err, ErrPaymentsDisabled) {
					t.Fatalf("%s reported a read failure as disabled: %v", tc.name, err)
				}
				if calls := rec.chain.Calls(); len(calls) != 0 {
					t.Fatalf("%s reached the chain backend: %v", tc.name, calls)
				}
				assertMet(t, mock)
			})
		}
	}
}

// ---- enabled forwarding through the scripted backend ----

func TestEnabledChainMethodsForwardToBackend(t *testing.T) {
	t.Run("RefundDebugletOrder USDC", func(t *testing.T) {
		db, mock := newMockDB(t)
		h, rec := newEnabledHandler(t, db, enabledConfig(t))
		mock.ExpectBegin()
		expectOrderRead(mock, "USDC", models.Paid)
		mock.ExpectQuery(updateDebugletOrderStateQuery).
			WithArgs(int64(models.Refunded), testTxID, testOrderID).
			WillReturnRows(orderRow("USDC", models.Refunded))
		mock.ExpectCommit()

		if err := h.RefundDebugletOrder(testDebuglet(), testRefund, context.Background()); err != nil {
			t.Fatalf("RefundDebugletOrder: %v", err)
		}
		if calls := rec.chain.Calls(); len(calls) != 1 || calls[0] != "RefundDebuglet" {
			t.Fatalf("backend calls %v", calls)
		}
		if rec.chain.refundAddress != testRefund || rec.chain.refundOrder == nil || rec.chain.refundOrder.State != int64(models.Refunded) {
			t.Fatalf("forwarded refund (%v, %q)", rec.chain.refundOrder, rec.chain.refundAddress)
		}
		assertMet(t, mock)
	})

	t.Run("RefundTransaction USDC", func(t *testing.T) {
		db, mock := newMockDB(t)
		h, rec := newEnabledHandler(t, db, enabledConfig(t))
		mock.ExpectBegin()
		expectTransactionRead(mock, "USDC", models.Paid)
		expectTransactionOrdersRead(mock, "USDC", 2)
		for i := int64(1); i <= 2; i++ {
			mock.ExpectQuery(updateDebugletOrderStateQuery).
				WithArgs(int64(models.Refunded), testTxID, i).
				WillReturnRows(orderRow("USDC", models.Refunded))
		}
		mock.ExpectExec(updateTransactionStatusQuery).
			WithArgs(int64(models.Refunded), testTxID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		if err := h.RefundTransaction(testTxID, context.Background()); err != nil {
			t.Fatalf("RefundTransaction: %v", err)
		}
		if calls := rec.chain.Calls(); len(calls) != 1 || calls[0] != "TransferCoins" {
			t.Fatalf("backend calls %v", calls)
		}
		if rec.chain.transferAmount != uint64(2*testPrice) || rec.chain.transferAddress != testRefund ||
			rec.chain.transferCoinType != sui.GetCoinType("USDC", "testnet") {
			t.Fatalf("forwarded transfer (%d, %q, %q)", rec.chain.transferAmount, rec.chain.transferCoinType, rec.chain.transferAddress)
		}
		assertMet(t, mock)
	})

	t.Run("PayoutExecutor USDC", func(t *testing.T) {
		db, mock := newMockDB(t)
		h, rec := newEnabledHandler(t, db, enabledConfig(t))
		err := h.PayoutExecutor(database.Earning{ExecutorID: testExecutor, Currency: "USDC", CurrentBalance: 42, SuiWalletAddress: "0xwallet"}, context.Background())
		if err != nil {
			t.Fatalf("PayoutExecutor: %v", err)
		}
		if calls := rec.chain.Calls(); len(calls) != 1 || calls[0] != "TransferCoins" {
			t.Fatalf("backend calls %v", calls)
		}
		if rec.chain.transferAmount != 42 || rec.chain.transferAddress != "0xwallet" ||
			rec.chain.transferCoinType != sui.GetCoinType("USDC", "testnet") {
			t.Fatalf("forwarded transfer (%d, %q, %q)", rec.chain.transferAmount, rec.chain.transferCoinType, rec.chain.transferAddress)
		}
		assertMet(t, mock)
	})

	t.Run("TransferUSDC reaches the backend once", func(t *testing.T) {
		db, mock := newMockDB(t)
		h, rec := newEnabledHandler(t, db, enabledConfig(t))
		if err := h.TransferUSDC(9, "0xreceiver", context.Background()); err != nil {
			t.Fatalf("TransferUSDC: %v", err)
		}
		if calls := rec.chain.Calls(); len(calls) != 1 || calls[0] != "TransferCoins" {
			t.Fatalf("backend calls %v", calls)
		}
		if rec.chain.transferAmount != 9 {
			t.Fatalf("forwarded amount %d", rec.chain.transferAmount)
		}
		assertMet(t, mock)
	})
}

// ---- CompleteTransaction (void TransactionFulfiller callback) ----

// Log messages emitted by CompleteTransaction. The callback is void and
// swallows database errors into these lines, so the log is the only place an
// attempted write can be observed: sqlmock answers an unexpected UPDATE with an
// error, which surfaces as logFailedSettle rather than as a test failure.
const (
	logLookupFailed = "failed to look up transaction to settle"
	logNotSettling  = "not settling transaction"
	logSettling     = "settling transaction"
	logFailedSettle = "failed to settle transaction"
)

var allCompleteLogs = []string{logLookupFailed, logNotSettling, logSettling, logFailedSettle}

func TestCompleteTransaction(t *testing.T) {
	expectUpdate := func(mock sqlmock.Sqlmock) {
		mock.ExpectExec(updateTransactionStatusQuery).WithArgs(int64(models.Paid), testTxID).WillReturnResult(sqlmock.NewResult(0, 1))
	}
	cases := []struct {
		name     string
		disabled bool
		expect   func(mock sqlmock.Sqlmock)
		wantLogs []string // exactly these CompleteTransaction messages, in order
	}{
		{
			name: "disabled SUI: lookup only", disabled: true,
			expect:   func(mock sqlmock.Sqlmock) { expectTransactionRead(mock, "SUI", models.Outstanding) },
			wantLogs: []string{logNotSettling},
		},
		{
			name: "disabled USDC: lookup only", disabled: true,
			expect:   func(mock sqlmock.Sqlmock) { expectTransactionRead(mock, "USDC", models.Outstanding) },
			wantLogs: []string{logNotSettling},
		},
		{
			name: "disabled TEST: lookup then update", disabled: true,
			expect: func(mock sqlmock.Sqlmock) {
				expectTransactionRead(mock, "TEST", models.Outstanding)
				expectUpdate(mock)
			},
			wantLogs: []string{logSettling},
		},
		{
			name: "disabled lookup error: no update", disabled: true,
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(getTransactionByIDQuery).WithArgs(testTxID).WillReturnError(errScripted)
			},
			wantLogs: []string{logLookupFailed},
		},
		{
			name: "disabled unknown id: no update", disabled: true,
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(getTransactionByIDQuery).WithArgs(testTxID).WillReturnError(sql.ErrNoRows)
			},
			wantLogs: []string{logLookupFailed},
		},
		{
			name: "enabled SUI: lookup then update", disabled: false,
			expect: func(mock sqlmock.Sqlmock) {
				expectTransactionRead(mock, "SUI", models.Outstanding)
				expectUpdate(mock)
			},
			wantLogs: []string{logSettling},
		},
		{
			name: "enabled USDC: lookup then update", disabled: false,
			expect: func(mock sqlmock.Sqlmock) {
				expectTransactionRead(mock, "USDC", models.Outstanding)
				expectUpdate(mock)
			},
			wantLogs: []string{logSettling},
		},
		{
			name: "enabled TEST: lookup then update", disabled: false,
			expect: func(mock sqlmock.Sqlmock) {
				expectTransactionRead(mock, "TEST", models.Outstanding)
				expectUpdate(mock)
			},
			wantLogs: []string{logSettling},
		},
		{
			name: "enabled lookup error: no update", disabled: false,
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(getTransactionByIDQuery).WithArgs(testTxID).WillReturnError(errScripted)
			},
			wantLogs: []string{logLookupFailed},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := newMockDB(t)
			var h *PaymentHandler
			var rec *depRecorder
			if tc.disabled {
				h, rec = newDisabledHandler(t, db, true, true)
			} else {
				h, rec = newEnabledHandler(t, db, enabledConfig(t))
			}
			core, logs := observer.New(zapcore.DebugLevel)
			h.logger = zap.New(core)
			tc.expect(mock)

			var tf sui.TransactionFulfiller = h
			tf.CompleteTransaction(testTxID, context.Background())

			if calls := rec.chain.Calls(); len(calls) != 0 {
				t.Fatalf("CompleteTransaction reached the chain backend: %v", calls)
			}
			// ExpectationsWereMet proves the expected reads/updates happened; the
			// log proves nothing else was attempted (an unexpected UPDATE would
			// have been answered with an error and logged as logFailedSettle).
			assertMet(t, mock)
			var got []string
			for _, entry := range logs.All() {
				for _, known := range allCompleteLogs {
					if entry.Message == known {
						got = append(got, entry.Message)
					}
				}
			}
			if strings.Join(got, "|") != strings.Join(tc.wantLogs, "|") {
				t.Fatalf("CompleteTransaction log messages %q, want %q (all entries: %v)", got, tc.wantLogs, logs.All())
			}
			if tc.wantLogs[0] == logSettling {
				if n := logs.FilterMessage(logSettling).Len(); n != 1 {
					t.Fatalf("settling logged %d times", n)
				}
			}
		})
	}
}

// newRefundDatabase is a real dispatcher database: a refund writes several
// rows in one transaction, and what matters here is the state it leaves.
func newRefundDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "refund.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	testutil.ApplyMigrations(t, db, "../database/migrations")
	return db
}

// Refunding a transaction refunds the transaction, not only its order rows. A
// submission is admitted on the transaction's status, so a transaction left
// Paid after its money went back would admit the same batch again and have the
// work done a second time for a payment that no longer exists.
func TestRefundTransactionSpendsTheTransactionItself(t *testing.T) {
	db := newRefundDatabase(t)
	h, rec := newEnabledHandler(t, db, enabledConfig(t))
	ctx := context.Background()
	queries := database.New(db)
	const id = "paid-transaction"
	if _, err := queries.CreateTransaction(ctx, database.CreateTransactionParams{
		ID: id, AuthKey: "key", Price: 1000, Currency: "USDC", Method: "SUI",
		ExpiresAt: models.NewUTCTime(time.Now().Add(time.Hour)), Status: int64(models.Paid), Hash: "hash",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := queries.CreateDebugletOrder(ctx, database.CreateDebugletOrderParams{
		TransactionID: id, OrderID: 1, ExecutorID: "executor", Price: 1000,
		Currency: "USDC", RefundAddress: "0xrefund", State: int64(models.Outstanding),
	}); err != nil {
		t.Fatal(err)
	}

	if err := h.RefundTransaction(id, ctx); err != nil {
		t.Fatalf("refund: %v", err)
	}
	if !strings.Contains(strings.Join(rec.chain.Calls(), " "), "TransferCoins") {
		t.Fatalf("the money was not moved: %v", rec.chain.Calls())
	}
	refunded, err := queries.GetTransactionByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if refunded.Status != int64(models.Refunded) {
		t.Fatalf("the refunded transaction is still %v; the same batch can be submitted again", models.TransactionState(refunded.Status))
	}
	orders, err := queries.GetTransactionOrders(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(orders) != 1 || orders[0].State != int64(models.Refunded) {
		t.Fatalf("order rows after the refund: %+v", orders)
	}
	// Refunding it again finds nothing to refund: it is not Paid any more.
	if err := h.RefundTransaction(id, ctx); err == nil {
		t.Fatal("a refunded transaction was refunded a second time")
	}
}

// seedTESTOrder stores a TEST transaction with one order in the given state,
// as the wallet-free flow leaves it before completion.
func seedTESTOrder(t *testing.T, db *sql.DB, state models.TransactionState) {
	t.Helper()
	ctx := t.Context()
	queries := database.New(db)
	if _, err := queries.CreateTransaction(ctx, database.CreateTransactionParams{
		ID: testTxID, Price: testPrice, Currency: "TEST", Method: "TEST",
		ExpiresAt: models.NewUTCTime(time.Now().Add(time.Hour)), Status: int64(models.Paid), Hash: testHash,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := queries.CreateDebugletOrder(ctx, database.CreateDebugletOrderParams{
		TransactionID: testTxID, OrderID: testOrderID, ExecutorID: testExecutor, Price: testPrice,
		Currency: "TEST", RefundAddress: testRefund, State: int64(state),
	}); err != nil {
		t.Fatal(err)
	}
}

func orderState(t *testing.T, db *sql.DB) models.TransactionState {
	t.Helper()
	order, err := database.New(db).GetDebugletOrder(t.Context(), database.GetDebugletOrderParams{
		TransactionID: testTxID, OrderID: testOrderID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return models.TransactionState(order.State)
}

// totalIncome is the executor's recorded TEST income; a missing row counts as 0.
func totalIncome(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	earning, err := database.New(db).GetEarningsIn(t.Context(), database.GetEarningsInParams{
		ExecutorID: testExecutor, Currency: "TEST",
	})
	if errors.Is(err, sql.ErrNoRows) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return earning.TotalIncome
}

// Completing the same order twice credits the executor once: the second call
// finds the order already Credited and writes nothing.
func TestSetDebugletOrderCompleteCreditsOnce(t *testing.T) {
	db := newRefundDatabase(t)
	h, rec := newDisabledHandler(t, db, true, true)
	seedTESTOrder(t, db, models.Outstanding)

	for i := range 2 {
		if err := h.SetDebugletOrderComplete(testDebuglet(), t.Context()); err != nil {
			t.Fatalf("completion %d: %v", i+1, err)
		}
	}
	if got := orderState(t, db); got != models.Credited {
		t.Fatalf("order state %v, want %v", got, models.Credited)
	}
	if got := totalIncome(t, db); got != testPrice {
		t.Fatalf("total income %d after two completions, want the order price %d once", got, testPrice)
	}
	if calls := rec.chain.Calls(); len(calls) != 0 {
		t.Fatalf("TEST completion reached the chain backend: %v", calls)
	}
}

// A failed earnings write leaves the order Outstanding and reports the error:
// the credit and the earnings commit together or not at all.
func TestSetDebugletOrderCompleteRollsBackFailedEarnings(t *testing.T) {
	db := newRefundDatabase(t)
	h, _ := newDisabledHandler(t, db, true, true)
	seedTESTOrder(t, db, models.Outstanding)
	if _, err := db.ExecContext(t.Context(), `CREATE TRIGGER refuse_earnings BEFORE UPDATE ON earnings
BEGIN SELECT RAISE(ABORT, 'earnings update refused'); END;`); err != nil {
		t.Fatal(err)
	}

	err := h.SetDebugletOrderComplete(testDebuglet(), t.Context())
	if err == nil || !strings.Contains(err.Error(), "earnings update refused") {
		t.Fatalf("SetDebugletOrderComplete = %v, want the refused earnings write", err)
	}
	if got := orderState(t, db); got != models.Outstanding {
		t.Fatalf("order state %v after a failed earnings write, want %v", got, models.Outstanding)
	}
	if got := totalIncome(t, db); got != 0 {
		t.Fatalf("total income %d after a failed earnings write", got)
	}
}

// A refunded order is never credited.
func TestSetDebugletOrderCompleteLeavesRefundedOrder(t *testing.T) {
	db := newRefundDatabase(t)
	h, _ := newDisabledHandler(t, db, true, true)
	seedTESTOrder(t, db, models.Refunded)

	if err := h.SetDebugletOrderComplete(testDebuglet(), t.Context()); err != nil {
		t.Fatalf("SetDebugletOrderComplete(refunded): %v", err)
	}
	if got := orderState(t, db); got != models.Refunded {
		t.Fatalf("order state %v, want %v", got, models.Refunded)
	}
	if got := totalIncome(t, db); got != 0 {
		t.Fatalf("a refunded order earned %d", got)
	}
}

// A TEST intent records what was locked: its price and the TEST currency.
func TestCreatePaymentIntentTESTStoresPriceAndCurrency(t *testing.T) {
	db := newRefundDatabase(t)
	h, _ := newDisabledHandler(t, db, true, true)

	if _, err := h.CreatePaymentIntent(testTxID, testPrice, "TEST", testHash, t.Context()); err != nil {
		t.Fatalf("CreatePaymentIntent(TEST): %v", err)
	}
	stored, err := database.New(db).GetTransactionByID(t.Context(), testTxID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Price != testPrice || stored.Currency != "TEST" || stored.Method != "TEST" {
		t.Fatalf("stored TEST transaction price=%d currency=%q method=%q, want %d %q %q",
			stored.Price, stored.Currency, stored.Method, testPrice, "TEST", "TEST")
	}
}
