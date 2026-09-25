package api

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
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
	modeCreateTransactionQuery = regexp.QuoteMeta(
		"INSERT INTO transactions (id, auth_key, price, currency, method, expires_at, status, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id, auth_key, price, method, expires_at, hash, currency, status",
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
	modeInsertDebugletQuery = regexp.QuoteMeta(
		"INSERT INTO debuglets (uuid, start_time, end_time, usage, ceil_bw, executor_id, addresses, state, transaction_id, order_id, dispatcher_incarnation, session_id)",
	)

	modeEarningsColumns    = []string{"executor_id", "currency", "total_income", "current_balance", "sui_wallet_address"}
	modeOrderColumns       = []string{"transaction_id", "order_id", "executor_id", "price", "currency", "state", "refund_address", "debuglet_id"}
	modeTransactionColumns = []string{"id", "auth_key", "price", "method", "expires_at", "hash", "currency", "status"}
)

// modeErrSentinelInsert is returned by the mocked debuglets INSERT. Reaching it
// proves the submission passed the mode gate and scheduler admission.
var modeErrSentinelInsert = errors.New("mode sentinel: debuglet insert reached")

// modeArgCapture is a sqlmock argument matcher that accepts any value and
// records it, so that a randomly generated transaction ID can be compared
// across queries and against the HTTP response.
type modeArgCapture struct {
	value driver.Value
}

func (a *modeArgCapture) Match(v driver.Value) bool {
	a.value = v
	return true
}

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

// TestModeDisabledChainIntentRejectedBeforeOrderWrites: a USDC or SUI intent that
// is otherwise valid enough to reach LockPrice (registered executor with
// capacity, valid debuglets) is answered with 503 and the bounded message, and
// no debuglet_order or transactions row is written. sqlmock has no order or
// transaction expectations, so any write would surface both as a non-503
// response and as an unexpected call.
func TestModeDisabledChainIntentRejectedBeforeOrderWrites(t *testing.T) {
	for _, method := range []string{"USDC", "SUI"} {
		t.Run(method, func(t *testing.T) {
			f := modeNewFixture(t)
			f.registerExecutor()

			rec := f.do(http.MethodPut, "/payment/intent", modeIntentBody(method))
			modeAssertStatus(t, rec, http.StatusServiceUnavailable)
			modeAssertBody(t, rec, modeDisabledBody)
			f.expectationsMet("disabled chain intent")
		})
	}
}

// TestModeDisabledChainIntentNeedsNoDatabase is supporting evidence only: the
// intent rejection happens before any database or executor access, so the
// handler stack built on a nil *sql.DB still answers 503.
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

// TestModeDisabledTestIntentSucceeds: in disabled mode a TEST intent still
// writes its Outstanding order and a Paid TEST transaction and returns the
// existing payload shape {"method":"TEST","intent":{"transaction_id":...,
// "auth_key":""}}.
func TestModeDisabledTestIntentSucceeds(t *testing.T) {
	f := modeNewFixture(t)
	f.registerExecutor()

	debuglets := modeDebuglets()
	hash := modeRequestHash(t, debuglets)
	orderTxID := &modeArgCapture{}
	transactionTxID := &modeArgCapture{}

	f.mock.ExpectQuery(modeCreateOrderQuery).
		WithArgs(orderTxID, modeOrderID, modeExecutorID, modeOrderPrice, "TEST", modeRefundAddr, int64(models.Outstanding)).
		WillReturnRows(modeOrderRows("", "TEST", models.Outstanding))
	// CreateDummyIntent stores method TEST, an empty auth key, the request hash
	// and status Paid; price and currency are not part of its parameters.
	f.mock.ExpectQuery(modeCreateTransactionQuery).
		WithArgs(transactionTxID, "", sqlmock.AnyArg(), sqlmock.AnyArg(), "TEST", sqlmock.AnyArg(), int64(models.Paid), hash).
		WillReturnRows(modeTransactionRows(modeChainTxID, "", "TEST", "", hash, models.Paid))

	rec := f.do(http.MethodPut, "/payment/intent", modeIntentBody("TEST"))
	modeAssertStatus(t, rec, http.StatusOK)
	f.expectationsMet("TEST intent")

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("response is not a JSON object: %v; body: %s", err, rec.Body.String())
	}
	if len(raw) != 2 || raw["method"] == nil || raw["intent"] == nil {
		t.Fatalf("response keys = %v, want exactly method and intent", raw)
	}
	var resp struct {
		Method string      `json:"method"`
		Intent DummyIntent `json:"intent"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode intent response: %v", err)
	}
	var intentKeys map[string]json.RawMessage
	if err := json.Unmarshal(raw["intent"], &intentKeys); err != nil {
		t.Fatalf("intent is not a JSON object: %v", err)
	}
	if len(intentKeys) != 2 || intentKeys["transaction_id"] == nil || intentKeys["auth_key"] == nil {
		t.Fatalf("intent keys = %v, want exactly transaction_id and auth_key", intentKeys)
	}
	if resp.Method != "TEST" {
		t.Fatalf("method = %q, want TEST", resp.Method)
	}
	if resp.Intent.AuthKey != "" {
		t.Fatalf("auth_key = %q, want empty", resp.Intent.AuthKey)
	}
	if b, err := hex.DecodeString(resp.Intent.TransactionID); err != nil || len(b) != 16 {
		t.Fatalf("transaction_id = %q, want 16 random bytes hex-encoded", resp.Intent.TransactionID)
	}
	if orderTxID.value != resp.Intent.TransactionID || transactionTxID.value != resp.Intent.TransactionID {
		t.Fatalf("transaction id mismatch: order row %v, transaction row %v, response %q",
			orderTxID.value, transactionTxID.value, resp.Intent.TransactionID)
	}
}

// TestModeUnknownIntentMethodKeepsExisting400: an unknown method keeps the
// existing 400 in disabled mode and touches no database. The body is the
// documented error envelope; it was an untyped JSON string before the envelope
// was introduced.
func TestModeUnknownIntentMethodKeepsExisting400(t *testing.T) {
	f := modeNewFixture(t)
	f.registerExecutor()

	rec := f.do(http.MethodPut, "/payment/intent", modeIntentBody("EUR"))
	modeAssertStatus(t, rec, http.StatusBadRequest)
	modeAssertBody(t, rec, `{"code":"unsupported_payment_method","message":"unknown payment method: EUR"}`)
	f.expectationsMet("unknown intent method")
}

// TestModeDisabledChainSubmissionRejectedBeforeAdmission: a submission backed by
// a persisted, paid chain transaction with the correct auth key and the exact
// request hash is answered with 503 after the transaction read. sqlmock proves
// there is no Begin, debuglets INSERT, order-state update or refund query, and
// the executor's dispatch history proves the scheduler admitted nothing.
func TestModeDisabledChainSubmissionRejectedBeforeAdmission(t *testing.T) {
	for _, currency := range []string{"USDC", "SUI"} {
		t.Run(currency, func(t *testing.T) {
			f := modeNewFixture(t)
			f.registerExecutor()

			debuglets := modeDebuglets()
			hash := modeRequestHash(t, debuglets)
			f.mock.ExpectQuery(modeGetTransactionQuery).
				WithArgs(modeChainTxID).
				WillReturnRows(modeTransactionRows(modeChainTxID, modeChainAuthKey, "SUI", currency, hash, models.Paid))

			rec := f.do(http.MethodPut, "/debuglet", modeSubmitBody(modeChainTxID, modeChainAuthKey, debuglets))
			modeAssertStatus(t, rec, http.StatusServiceUnavailable)
			modeAssertBody(t, rec, modeDisabledBody)
			f.expectationsMet("disabled chain submission")
			if n := f.recentDebugletIDs(); n != 0 {
				t.Fatalf("executor dispatch history has %d entries, want 0 (no scheduler admission)", n)
			}
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

// TestModeDisabledTestSubmissionReachesAdmission: a paid TEST transaction is
// still admitted in disabled mode. The mocked debuglets INSERT returns a
// sentinel error, proving the request passed the mode gate and scheduler
// admission and reached the real insert boundary; the existing failure path
// then attempts RefundTransaction, which reads the transaction and its orders
// inside a new database transaction and rolls back because TEST refunds are
// unsupported.
func TestModeDisabledTestSubmissionReachesAdmission(t *testing.T) {
	f := modeNewFixture(t)
	f.registerExecutor()

	debuglets := modeDebuglets()
	hash := modeRequestHash(t, debuglets)
	f.mock.ExpectQuery(modeGetTransactionQuery).
		WithArgs(modeChainTxID).
		WillReturnRows(modeTransactionRows(modeChainTxID, "", "TEST", "", hash, models.Paid))

	// SubmitDebuglets: admission passed, the insert fails with the sentinel and
	// the deferred rollback follows.
	modeExpectNoAdmittedRuns(f.mock)
	f.mock.ExpectBegin()
	f.mock.ExpectQuery(modeInsertDebugletQuery).WillReturnError(modeErrSentinelInsert)
	f.mock.ExpectRollback()

	// RefundTransaction for TEST: transaction and order reads, the existing
	// order-state update inside the transaction, then rollback because refunds
	// are unsupported for TEST.
	f.mock.ExpectBegin()
	f.mock.ExpectQuery(modeGetTransactionQuery).
		WithArgs(modeChainTxID).
		WillReturnRows(modeTransactionRows(modeChainTxID, "", "TEST", "", hash, models.Paid))
	f.mock.ExpectQuery(modeGetTransactionOrdersQuery).
		WithArgs(modeChainTxID).
		WillReturnRows(modeOrderRows(modeChainTxID, "TEST", models.Outstanding))
	f.mock.ExpectQuery(modeUpdateOrderStateQuery).
		WithArgs(int64(models.Refunded), modeChainTxID, modeOrderID).
		WillReturnRows(modeOrderRows(modeChainTxID, "TEST", models.Refunded))
	f.mock.ExpectRollback()

	rec := f.do(http.MethodPut, "/debuglet", modeSubmitBody(modeChainTxID, "", debuglets))
	modeAssertStatus(t, rec, http.StatusInternalServerError)
	// The scripted expectations above are what prove the insert boundary was
	// reached; the response reports the failure without the database text.
	assertEnvelope(t, "TEST submission", rec, http.StatusInternalServerError, CodeInternal, "failed to initialize debuglets")
	if strings.Contains(rec.Body.String(), modeErrSentinelInsert.Error()) {
		t.Fatalf("the database diagnostic reached the client: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), paymentsDisabledMessage) {
		t.Fatalf("TEST submission must not be classified as disabled: %s", rec.Body.String())
	}
	f.expectationsMet("TEST submission")
	if n := f.recentDebugletIDs(); n != 0 {
		t.Fatalf("executor dispatch history has %d entries, want 0 (insert failed before commit)", n)
	}
}
