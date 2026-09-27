package api

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/protocol"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// Route-level regression tests for the wallet-free (Sui disabled) payment mode.
// Every fixture uses a PaymentHandler constructed with Sui.Disabled=true, a
// dispatcher with one registered executor and sqlmock as the only database, so
// that every query the handlers issue is recorded and any unexpected write
// fails the request. All helpers are prefixed with "mode" to stay clear of the
// wallet_free_test.go ("wf" prefix) in this package.

const (
	modeExecutorID = "mode-exec"
	// modeExecutorCurrency is the executor's announced pricing currency; it only
	// determines the earnings row created at registration.
	modeExecutorCurrency = "TEST"
	modeExecutorWallet   = ""
	modePricePerBwS      = int64(1)
	modeFloorBW          = int64(100)
	modeTimeoutMS        = int64(10_000)
	// modeOrderPrice is PricePerBwS * FloorBW * (TimeoutMS / 1000), as LockPrice
	// computes it.
	modeOrderPrice   = modePricePerBwS * modeFloorBW * (modeTimeoutMS / 1000)
	modeOrderID      = int64(1)
	modeRefundAddr   = "0xmoderefund"
	modeChainTxID    = "0123456789abcdef0123456789abcdef"
	modeChainAuthKey = "mode-chain-auth-key"
	modeDisabledBody = `{"code":"payments_disabled","message":"blockchain payments are disabled"}`
)

// Exact SQL of the generated queries in internal/dispatcher/database/*.sql.go.
// sqlmock collapses whitespace before matching, so the single-line forms match
// the multi-line constants; the "-- name:" comment prefix is matched as a
// substring.
var (
	modeGetEarningsInQuery = regexp.QuoteMeta(
		"SELECT executor_id, currency, total_income, current_balance, sui_wallet_address FROM earnings WHERE executor_id = ? AND currency = ?",
	)
	modeCreateEarningsQuery = regexp.QuoteMeta(
		"INSERT INTO earnings (executor_id, currency, sui_wallet_address, total_income, current_balance) VALUES (?,?,?,0,0) RETURNING executor_id, currency, total_income, current_balance, sui_wallet_address",
	)
	modeCreateOrderQuery = regexp.QuoteMeta(
		"INSERT INTO debuglet_order (transaction_id, order_id, executor_id, price, currency, refund_address, state ) VALUES (?,?,?,?,?,?,?) RETURNING transaction_id, order_id, executor_id, price, currency, state, refund_address, debuglet_id",
	)
	modeGetTransactionQuery = regexp.QuoteMeta(
		"SELECT id, auth_key, price, method, expires_at, hash, currency, status FROM transactions WHERE id = ?",
	)
	modeGetTransactionOrdersQuery = regexp.QuoteMeta(
		"SELECT transaction_id, order_id, executor_id, price, currency, state, refund_address, debuglet_id FROM debuglet_order WHERE transaction_id = ?",
	)
	modeUpdateOrderStateQuery = regexp.QuoteMeta(
		"UPDATE debuglet_order SET state = ? WHERE transaction_id = ? AND order_id = ? RETURNING transaction_id, order_id, executor_id, price, currency, state, refund_address, debuglet_id",
	)
	modeGetAdmittedRunsQuery = regexp.QuoteMeta(
		"SELECT o.order_id, d.uuid FROM debuglet_order o JOIN debuglets d ON d.id = o.debuglet_id WHERE o.transaction_id = ?",
	)

	modeEarningsColumns    = []string{"executor_id", "currency", "total_income", "current_balance", "sui_wallet_address"}
	modeOrderColumns       = []string{"transaction_id", "order_id", "executor_id", "price", "currency", "state", "refund_address", "debuglet_id"}
	modeTransactionColumns = []string{"id", "auth_key", "price", "method", "expires_at", "hash", "currency", "status"}
)

type modeFixture struct {
	t    *testing.T
	e    *echo.Echo
	h    *Handler
	d    *dispatcher.Dispatcher
	mock sqlmock.Sqlmock
}

// modeNewFixture builds the disabled-mode handler stack on top of sqlmock:
// PaymentHandler (Sui.Disabled=true), Dispatcher, Handler and registered Echo
// routes. No executor is registered yet.
func modeNewFixture(t *testing.T) *modeFixture {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	t.Cleanup(func() {
		mock.ExpectClose()
		if err := db.Close(); err != nil {
			t.Errorf("failed to close mock db: %v", err)
		}
	})
	return modeNewFixtureWithDB(t, db, mock)
}

func modeNewFixtureWithDB(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) *modeFixture {
	t.Helper()
	cfg := &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}
	ph := payments.NewPaymentHandler(db, cfg, zap.NewNop())
	d, err := dispatcher.New(zap.NewNop(), db, "test", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	// The fixtures exercise the routes of a dispatcher serving the local
	// development profile; the enforced profile has its own tests in auth_test.go.
	h := NewHandler(d, db, zap.NewNop(), LocalDevelopment(true))
	e := echo.New()
	e.Logger.SetOutput(io.Discard)
	h.RegisterRoutes(e)
	return &modeFixture{t: t, e: e, h: h, d: d, mock: mock}
}

// registerExecutor registers modeExecutorID with gigabit capacity through the
// direct registry callbacks. RegisterExecutor issues the earnings lookup and
// insert; both are part of the recorded fixture.
func (f *modeFixture) registerExecutor() {
	f.t.Helper()
	f.mock.ExpectQuery(modeGetEarningsInQuery).
		WithArgs(modeExecutorID, modeExecutorCurrency).
		WillReturnError(sql.ErrNoRows)
	f.mock.ExpectQuery(modeCreateEarningsQuery).
		WithArgs(modeExecutorID, modeExecutorCurrency, modeExecutorWallet).
		WillReturnRows(sqlmock.NewRows(modeEarningsColumns).AddRow(modeExecutorID, modeExecutorCurrency, int64(0), int64(0), modeExecutorWallet))

	owner := apiTestOwner(f.t, f.d, modeExecutorID)
	wallet := modeExecutorWallet
	if err := apiTestRegister(f.t.Context(), f.d, owner, &protocol.HelloResponse{
		ExecutorId: modeExecutorID, Version: "test", PricePerBwS: modePricePerBwS,
		Currency: modeExecutorCurrency, SuiWallet: &wallet,
	}, "127.0.0.1"); err != nil {
		f.t.Fatalf("register executor: %v", err)
	}
	if !owner.MarkRegistered() {
		f.t.Fatal("executor owner retired before registration completed")
	}
	if _, ok := f.d.GetExecutor(modeExecutorID); !ok {
		f.t.Fatalf("executor %q not registered", modeExecutorID)
	}
	f.expectationsMet("executor registration")
	mutation := apiTestMutation(f.t, f.t.Context(), owner)
	defer mutation.Finish()
	if _, err := f.d.OnResources(mutation.Context(), mutation, &protocol.ResourcesRequest{
		ExecutorId:        modeExecutorID,
		BandwidthCapacity: int64(resource.Gigabit),
	}); err != nil {
		f.t.Fatalf("failed to set executor capacity: %v", err)
	}
}

func (f *modeFixture) expectationsMet(stage string) {
	f.t.Helper()
	if err := f.mock.ExpectationsWereMet(); err != nil {
		f.t.Fatalf("%s: unmet sqlmock expectations: %v", stage, err)
	}
}

// do serves one JSON request through the registered Echo routes.
func (f *modeFixture) do(method, path string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		f.t.Fatalf("failed to marshal request body: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	f.e.ServeHTTP(rec, req)
	return rec
}

// recentDebugletIDs returns the executor's dispatch history; it stays empty
// unless SubmitDebuglets committed an admission.
func (f *modeFixture) recentDebugletIDs() int {
	f.t.Helper()
	exec, ok := f.d.GetExecutor(modeExecutorID)
	if !ok {
		f.t.Fatalf("executor %q not registered", modeExecutorID)
	}
	return len(exec.RecentDebugletIDs(10))
}

// modeDebuglets is a request that is valid enough to reach LockPrice and, for
// submissions, scheduler admission: known executor, positive policy, base64
// wasm, no listener or ICMP requirement.
func modeDebuglets() []DebugletRequest {
	return []DebugletRequest{{
		OrderID:    modeOrderID,
		ExecutorID: modeExecutorID,
		Wasm:       base64.StdEncoding.EncodeToString([]byte("\x00asm mode")),
		Policy: DebugletPolicyRequest{
			FloorBW:   modeFloorBW,
			CeilBW:    modeFloorBW,
			TimeoutMS: modeTimeoutMS,
		},
	}}
}

func modeIntentBody(method string) PaymentIntentRequest {
	return PaymentIntentRequest{
		Debuglets:     modeDebuglets(),
		PaymentMethod: method,
		RefundAddress: modeRefundAddr,
	}
}

func modeSubmitBody(transactionID, authKey string, debuglets []DebugletRequest) SubmitDebugletsRequest {
	return SubmitDebugletsRequest{
		Debuglets:     debuglets,
		TransactionId: transactionID,
		AuthKey:       authKey,
	}
}

// modeRequestHash computes the intent hash the handler will compare against: the
// debuglets are round-tripped through JSON first so that the hashed value is
// exactly what c.Bind produces (nil versus empty slices, omitted fields).
func modeRequestHash(t *testing.T, debuglets []DebugletRequest) string {
	t.Helper()
	b, err := json.Marshal(SubmitDebugletsRequest{Debuglets: debuglets})
	if err != nil {
		t.Fatalf("failed to marshal debuglets: %v", err)
	}
	var bound SubmitDebugletsRequest
	if err := json.Unmarshal(b, &bound); err != nil {
		t.Fatalf("failed to unmarshal debuglets: %v", err)
	}
	return hashDebugletRequest(bound.Debuglets)
}

// modeTransactionRows builds one transactions row as GetTransactionByID and
// CreateTransaction return it.
func modeTransactionRows(id, authKey, method, currency, hash string, status models.TransactionState) *sqlmock.Rows {
	return sqlmock.NewRows(modeTransactionColumns).AddRow(
		id, authKey, modeOrderPrice, method, time.Now().Add(5*time.Minute).UTC(), hash, currency, int64(status),
	)
}

func modeOrderRows(transactionID, currency string, state models.TransactionState) *sqlmock.Rows {
	return sqlmock.NewRows(modeOrderColumns).AddRow(
		transactionID, modeOrderID, modeExecutorID, modeOrderPrice, currency, int64(state), modeRefundAddr, nil,
	)
}

// modeExpectNoAdmittedRuns answers the submission's lookup of the runs
// already admitted for the transaction: there are none.
func modeExpectNoAdmittedRuns(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(modeGetAdmittedRunsQuery).
		WithArgs(modeChainTxID).
		WillReturnRows(sqlmock.NewRows([]string{"order_id", "uuid"}))
}

func modeAssertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, want, rec.Body.String())
	}
}

func modeAssertBody(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	if got := strings.TrimSpace(rec.Body.String()); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func modeAssertBodyContains(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	if got := rec.Body.String(); !strings.Contains(got, want) {
		t.Fatalf("body = %q, want it to contain %q", got, want)
	}
}

// TestModeDisabledChainIntentNeedsNoDatabase: the intent rejection happens
// before any database or executor access, so the handler stack built on a nil
// *sql.DB still answers 503. That the rejection writes no row is covered on a
// real database by TestWalletFreeHTTPFlow.
func TestModeDisabledChainIntentNeedsNoDatabase(t *testing.T) {
	f := modeNewFixtureWithDB(t, nil, nil)
	for _, method := range []string{"USDC", "SUI"} {
		rec := f.do(http.MethodPut, "/payment/intent", modeIntentBody(method))
		modeAssertStatus(t, rec, http.StatusServiceUnavailable)
		modeAssertBody(t, rec, modeDisabledBody)
	}
}

// TestModeLockPriceGuard calls LockPrice directly with a disabled chain method:
// it must return payments.ErrPaymentsDisabled and issue no CreateDebugletOrder
// query, even though the executor lookup would succeed.
func TestModeLockPriceGuard(t *testing.T) {
	for _, method := range []string{"USDC", "SUI"} {
		t.Run(method, func(t *testing.T) {
			f := modeNewFixture(t)
			f.registerExecutor()

			price, err := f.h.LockPrice(modeIntentBody(method), modeChainTxID, modeRefundAddr, t.Context())
			if !errors.Is(err, payments.ErrPaymentsDisabled) {
				t.Fatalf("LockPrice error = %v, want errors.Is(err, payments.ErrPaymentsDisabled)", err)
			}
			if price != 0 {
				t.Fatalf("LockPrice price = %d, want 0", price)
			}
			f.expectationsMet("direct LockPrice")
		})
	}
}

// TestModeChainSubmissionKeepsExistingRejections: the auth-key, hash and paid
// checks that precede the mode gate keep their existing responses for a stored
// chain transaction in disabled mode.
func TestModeChainSubmissionKeepsExistingRejections(t *testing.T) {
	debuglets := modeDebuglets()
	altered := modeDebuglets()
	altered[0].Args = []string{"--altered-after-intent"}

	cases := []struct {
		name       string
		status     models.TransactionState
		authKey    string
		debuglets  []DebugletRequest
		wantStatus int
		wantBody   string
	}{
		{
			name:       "wrong auth key",
			status:     models.Paid,
			authKey:    "not-the-auth-key",
			debuglets:  debuglets,
			wantStatus: http.StatusUnauthorized,
			wantBody:   "unknown transaction or wrong auth key",
		},
		{
			name:       "altered request field",
			status:     models.Paid,
			authKey:    modeChainAuthKey,
			debuglets:  altered,
			wantStatus: http.StatusBadRequest,
			wantBody:   "Request does not match the intent",
		},
		{
			name:       "unpaid transaction",
			status:     models.Outstanding,
			authKey:    modeChainAuthKey,
			debuglets:  debuglets,
			wantStatus: http.StatusBadRequest,
			wantBody:   "has not yet been completed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := modeNewFixture(t)
			f.registerExecutor()

			hash := modeRequestHash(t, debuglets)
			f.mock.ExpectQuery(modeGetTransactionQuery).
				WithArgs(modeChainTxID).
				WillReturnRows(modeTransactionRows(modeChainTxID, modeChainAuthKey, "SUI", "USDC", hash, tc.status))

			rec := f.do(http.MethodPut, "/debuglet", modeSubmitBody(modeChainTxID, tc.authKey, tc.debuglets))
			modeAssertStatus(t, rec, tc.wantStatus)
			modeAssertBodyContains(t, rec, tc.wantBody)
			f.expectationsMet(tc.name)
			if n := f.recentDebugletIDs(); n != 0 {
				t.Fatalf("executor dispatch history has %d entries, want 0", n)
			}
		})
	}
}
