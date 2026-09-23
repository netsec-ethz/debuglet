package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/demo/service"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

// maintenanceFixture is one dispatcher behind its HTTP API, with the admission
// switch this process reads pointed at a file the test owns. The routes
// establish their caller before anything else, so the fixture admits requests
// the way the loopback profile does.
type maintenanceFixture struct {
	t          *testing.T
	db         *sql.DB
	d          *dispatcher.Dispatcher
	server     *httptest.Server
	switchFile string
}

func newMaintenanceFixture(t *testing.T) *maintenanceFixture {
	t.Helper()
	return newMaintenanceFixtureWith(t, LocalDevelopment(true))
}

func newMaintenanceFixtureWith(t *testing.T, options ...Option) *maintenanceFixture {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "maintenance.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	testutil.ApplyMigrations(t, db, "../../database/migrations")
	logger := zap.NewNop()
	ph := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)
	d, err := dispatcher.New(logger, db, "maintenance-test", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	e := echo.New()
	e.HideBanner = true
	NewHandler(d, db, logger, options...).RegisterRoutes(e)
	server := httptest.NewServer(e)
	t.Cleanup(func() { server.CloseClientConnections(); server.Close() })
	f := &maintenanceFixture{t: t, db: db, d: d, server: server, switchFile: filepath.Join(t.TempDir(), "maintenance")}
	t.Setenv(dispatcher.MaintenanceFileEnv, f.switchFile)
	return f
}

func (f *maintenanceFixture) pause(reason string) {
	f.t.Helper()
	if err := service.WriteMaintenance(f.switchFile, reason, time.Now()); err != nil {
		f.t.Fatal(err)
	}
}

func (f *maintenanceFixture) resume() {
	f.t.Helper()
	if _, err := service.ClearMaintenance(f.switchFile); err != nil {
		f.t.Fatal(err)
	}
}

// put sends one request and decodes the documented error envelope. A success
// leaves the envelope empty, which every caller below treats as a failure.
func (f *maintenanceFixture) put(path string, payload any) (int, ErrorResponse) {
	f.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPut, f.server.URL+path, bytes.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := f.server.Client().Do(request)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		f.t.Fatal(err)
	}
	var envelope ErrorResponse
	_ = json.Unmarshal(answer, &envelope)
	return response.StatusCode, envelope
}

func (f *maintenanceFixture) count(table string) int {
	f.t.Helper()
	var rows int
	if err := f.db.QueryRow("SELECT count(*) FROM " + table).Scan(&rows); err != nil {
		f.t.Fatalf("count %s: %v", table, err)
	}
	return rows
}

// seedOrder writes the rows a completed payment intent leaves behind, in the
// state the test needs them: the routes below act on those rows, not on the
// chain this dispatcher does not have.
func (f *maintenanceFixture) seedOrder(id, authKey string, batch []DebugletRequest, status models.TransactionState) {
	f.t.Helper()
	ctx := context.Background()
	queries := database.New(f.db)
	if _, err := queries.CreateTransaction(ctx, database.CreateTransactionParams{
		ID: id, AuthKey: authKey, Price: 1000, Currency: "TEST", Method: "TEST",
		ExpiresAt: models.NewUTCTime(time.Now().Add(30 * time.Minute)),
		Status:    int64(status), Hash: hashDebugletRequest(batch),
	}); err != nil {
		f.t.Fatal(err)
	}
	if _, err := queries.CreateDebugletOrder(ctx, database.CreateDebugletOrderParams{
		TransactionID: id, OrderID: 1, ExecutorID: "no-such-executor", Price: 1000,
		Currency: "TEST", RefundAddress: "", State: int64(models.Outstanding),
	}); err != nil {
		f.t.Fatal(err)
	}
}

func maintenanceBatch() []DebugletRequest {
	return []DebugletRequest{{
		OrderID: 1, ExecutorID: "no-such-executor",
		Wasm:   base64.StdEncoding.EncodeToString([]byte("\x00asm\x01\x00\x00\x00")),
		Policy: DebugletPolicyRequest{FloorBW: 1000, CeilBW: 1000, TimeoutMS: 1000, Addresses: []string{"127.0.0.1"}},
	}}
}

// A dispatcher an operator has taken out of service answers a submission with
// 503 before it admits anything. The request below carries a transaction that
// does not exist, which is answered 401 as soon as admission is open again:
// that difference is what shows the refusal happens first, so a submitter is
// never charged for work this dispatcher will not accept.
func TestSubmissionIsRefusedForMaintenanceBeforeAnythingIsLookedUp(t *testing.T) {
	f := newMaintenanceFixture(t)
	f.pause("planned upgrade")
	submission := SubmitDebugletsRequest{
		TransactionId: "no-such-transaction", AuthKey: "wrong", Debuglets: maintenanceBatch(),
	}

	status, refusal := f.put("/debuglet", submission)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want %d (%+v)", status, http.StatusServiceUnavailable, refusal)
	}
	if refusal.Code != CodeUnavailable {
		t.Fatalf("code %q, want %q", refusal.Code, CodeUnavailable)
	}
	if !strings.Contains(refusal.Message, "maintenance") || !strings.Contains(refusal.Message, "planned upgrade") {
		t.Fatalf("the refusal does not say why: %q", refusal.Message)
	}
	if rows := f.count("debuglets"); rows != 0 {
		t.Fatalf("a refused submission persisted %d debuglets", rows)
	}

	f.resume()
	if status, answered := f.put("/debuglet", submission); status != http.StatusUnauthorized {
		t.Fatalf("status %d after maintenance, want %d (%+v)", status, http.StatusUnauthorized, answered)
	}
}

// Pricing new work is the first half of admitting it. A dispatcher that will
// not accept a batch must not sell an intent for it either: the submitter would
// pay for a submission that is then refused, and the money would have to be
// given back. The batch below names an executor this dispatcher does not know,
// which is what the route answers as soon as admission is open again, so the
// refusal is shown to happen before any pricing or order write.
func TestPaymentIntentIsRefusedForMaintenance(t *testing.T) {
	f := newMaintenanceFixture(t)
	f.pause("planned upgrade")
	intent := PaymentIntentRequest{Debuglets: maintenanceBatch(), PaymentMethod: "TEST"}

	status, refusal := f.put("/payment/intent", intent)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want %d (%+v)", status, http.StatusServiceUnavailable, refusal)
	}
	if refusal.Code != CodeUnavailable {
		t.Fatalf("code %q, want %q", refusal.Code, CodeUnavailable)
	}
	if !strings.Contains(refusal.Message, "maintenance") || !strings.Contains(refusal.Message, "planned upgrade") {
		t.Fatalf("the refusal does not say why: %q", refusal.Message)
	}
	if rows := f.count("transactions"); rows != 0 {
		t.Fatalf("a refused intent created %d transactions", rows)
	}
	if rows := f.count("debuglet_order"); rows != 0 {
		t.Fatalf("a refused intent priced %d orders", rows)
	}

	f.resume()
	if status, answered := f.put("/payment/intent", intent); status != http.StatusBadRequest || answered.Code != CodeUnknownExecutor {
		t.Fatalf("status %d (%+v) after maintenance, want %d and %q", status, answered, http.StatusBadRequest, CodeUnknownExecutor)
	}
}

// An order paid before admission stopped is the one case where refusing costs
// the submitter something: the batch is not accepted and the money is already
// spent. The refusal refunds it, and where the refund cannot be performed it
// says the order is still paid, so the submitter knows the same batch can be
// submitted again. This dispatcher has no chain, so the refund of a TEST order
// fails and the second half of that contract is what this exercises.
func TestAnAlreadyPaidOrderIsAccountedForWhenMaintenanceRefusesIt(t *testing.T) {
	f := newMaintenanceFixture(t)
	const transactionID, authKey = "paid-before-maintenance", "auth-key"
	batch := maintenanceBatch()
	f.seedOrder(transactionID, authKey, batch, models.Paid)

	f.pause("planned upgrade")
	status, refusal := f.put("/debuglet", SubmitDebugletsRequest{
		TransactionId: transactionID, AuthKey: authKey, Debuglets: batch,
	})
	if status != http.StatusServiceUnavailable || refusal.Code != CodeUnavailable {
		t.Fatalf("status %d code %q, want %d and %q", status, refusal.Code, http.StatusServiceUnavailable, CodeUnavailable)
	}
	if !strings.Contains(refusal.Message, "stays paid") {
		t.Fatalf("the refusal says nothing about the paid order: %q", refusal.Message)
	}
	if rows := f.count("debuglets"); rows != 0 {
		t.Fatalf("a refused submission persisted %d debuglets", rows)
	}
	// A refund that failed changed nothing: the order is still outstanding and
	// still spendable, which is exactly what the refusal told the submitter.
	orders, err := database.New(f.db).GetTransactionOrders(context.Background(), transactionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(orders) != 1 || orders[0].State != int64(models.Outstanding) {
		t.Fatalf("the order rows after a failed refund: %+v", orders)
	}
}

// A refund spends the order it gives back. The submission route admits a batch
// on its transaction's status, so once a drain has refunded an order the same
// batch is refused whether admission is stopped or open again: no batch is
// ever run for a payment that has been given back.
func TestARefundedOrderCannotBeSubmittedAgain(t *testing.T) {
	f := newMaintenanceFixture(t)
	const transactionID, authKey = "refunded-during-maintenance", "auth-key"
	batch := maintenanceBatch()
	f.seedOrder(transactionID, authKey, batch, models.Refunded)
	submission := SubmitDebugletsRequest{TransactionId: transactionID, AuthKey: authKey, Debuglets: batch}

	f.pause("planned upgrade")
	status, refusal := f.put("/debuglet", submission)
	if status != http.StatusServiceUnavailable || refusal.Code != CodeUnavailable {
		t.Fatalf("status %d code %q, want %d and %q", status, refusal.Code, http.StatusServiceUnavailable, CodeUnavailable)
	}
	if !strings.Contains(refusal.Message, "refunded") {
		t.Fatalf("a refunded order was not reported as refunded: %q", refusal.Message)
	}

	f.resume()
	status, answered := f.put("/debuglet", submission)
	if status != http.StatusBadRequest || answered.Code != CodePaymentIncomplete {
		t.Fatalf("status %d (%+v) after maintenance, want %d and %q", status, answered, http.StatusBadRequest, CodePaymentIncomplete)
	}
	if !strings.Contains(answered.Message, "refunded") {
		t.Fatalf("the refusal does not say the order was refunded: %q", answered.Message)
	}
	if rows := f.count("debuglets"); rows != 0 {
		t.Fatalf("a refunded batch was admitted as %d debuglets", rows)
	}
}

// Only an order the caller proved it may spend is reported on or refunded. An
// order it cannot open is answered with the bare refusal, exactly like a
// transaction that does not exist, and nothing of it is touched.
func TestMaintenanceRefundsNothingForAnOrderTheCallerCannotSpend(t *testing.T) {
	f := newMaintenanceFixture(t)
	const transactionID, authKey = "somebody-elses-order", "auth-key"
	batch := maintenanceBatch()
	f.seedOrder(transactionID, authKey, batch, models.Paid)

	f.pause("planned upgrade")
	_, unknown := f.put("/debuglet", SubmitDebugletsRequest{
		TransactionId: "no-such-transaction", AuthKey: authKey, Debuglets: batch,
	})
	status, refusal := f.put("/debuglet", SubmitDebugletsRequest{
		TransactionId: transactionID, AuthKey: "not-the-key", Debuglets: batch,
	})
	if status != http.StatusServiceUnavailable || refusal.Code != CodeUnavailable {
		t.Fatalf("status %d code %q, want %d and %q", status, refusal.Code, http.StatusServiceUnavailable, CodeUnavailable)
	}
	if refusal.Message != unknown.Message {
		t.Fatalf("an order this caller may not spend is answered differently from an unknown one: %q against %q", refusal.Message, unknown.Message)
	}
	paid, err := database.New(f.db).GetTransactionByID(context.Background(), transactionID)
	if err != nil {
		t.Fatal(err)
	}
	if paid.Status != int64(models.Paid) {
		t.Fatalf("somebody else's order was refunded: status %d", paid.Status)
	}
}

// The refusal carries the operator's note and says a dispatcher is paused, so
// it is only ever an answer to a request that may act at all. A caller that
// presents nothing learns that it must authenticate and nothing else, on both
// routes maintenance closes.
func TestAnUnauthenticatedRequestIsRefusedBeforeMaintenanceIsConsulted(t *testing.T) {
	f := newMaintenanceFixtureWith(t)
	f.pause("planned upgrade")
	for path, payload := range map[string]any{
		"/debuglet": SubmitDebugletsRequest{
			TransactionId: "no-such-transaction", AuthKey: "wrong", Debuglets: maintenanceBatch(),
		},
		"/payment/intent": PaymentIntentRequest{Debuglets: maintenanceBatch(), PaymentMethod: "TEST"},
	} {
		t.Run(path, func(t *testing.T) {
			status, refusal := f.put(path, payload)
			if status != http.StatusUnauthorized {
				t.Fatalf("status %d, want %d (%+v)", status, http.StatusUnauthorized, refusal)
			}
			if strings.Contains(refusal.Message, "maintenance") || strings.Contains(refusal.Message, "planned upgrade") {
				t.Fatalf("an unauthenticated caller was told about the maintenance: %q", refusal.Message)
			}
		})
	}
}
