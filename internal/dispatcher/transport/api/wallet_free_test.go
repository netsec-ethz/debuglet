package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/protocol"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	_ "modernc.org/sqlite"
)

// Fixture constants. The price of one order is
// wfPricePerBwS * wfFloorBW * (wfTimeoutMS / 1000), see Handler.LockPrice.
const (
	wfExecutorID   = "wf-executor"
	wfCurrency     = "TEST"
	wfPricePerBwS  = int64(1)
	wfFloorBW      = int64(1000)
	wfTimeoutMS    = int64(10_000)
	wfOrderPrice   = wfPricePerBwS * wfFloorBW * (wfTimeoutMS / 1000)
	wfHighCapacity = resource.Megabit
	wfLowCapacity  = resource.Bitrate(wfFloorBW - 1)

	wfChainTxID          = "wf-chain-paid"
	wfChainAuthKey       = "wf-chain-auth-key"
	wfChainOutstandingID = "wf-chain-outstanding"
	wfChainRefundAddr    = "0xwf-refund"

	wfDisabledMessage = "blockchain payments are disabled"
	// wfSentinel is raised by a test-only trigger so a valid TEST submission
	// proves it reached the debuglets insert without an executor transport.
	wfSentinel      = "wf_sentinel_insert_reached"
	wfTriggerName   = "wf_abort_debuglet_insert"
	wfRequestBound  = 5 * time.Second
	wfJoinBound     = 2 * time.Second
	wfMigrationsDir = "../../database/migrations"
)

// wfApplyMigrations initialises a fresh database from the checked-in goose
// migrations through the shared test helper, passing this package's relative
// migrations directory.
func wfApplyMigrations(t *testing.T, db *sql.DB) {
	t.Helper()
	testutil.ApplyMigrations(t, db, wfMigrationsDir)
}

// wfSnapshot is a canonical text rendering of every payment-relevant table.
type wfSnapshot string

func wfTakeSnapshot(t *testing.T, db *sql.DB) wfSnapshot {
	t.Helper()
	var b strings.Builder
	wfDump(t, db, &b, "transactions",
		"SELECT id, auth_key, price, method, hash, currency, status FROM transactions ORDER BY id")
	wfDump(t, db, &b, "debuglet_order",
		"SELECT transaction_id, order_id, executor_id, price, currency, state, refund_address FROM debuglet_order ORDER BY transaction_id, order_id")
	wfDump(t, db, &b, "debuglets",
		"SELECT uuid, executor_id, transaction_id, order_id, state FROM debuglets ORDER BY id")
	wfDump(t, db, &b, "earnings",
		"SELECT executor_id, currency, total_income, current_balance FROM earnings ORDER BY executor_id, currency")
	return wfSnapshot(b.String())
}

func wfDump(t *testing.T, db *sql.DB, b *strings.Builder, table, query string) {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatalf("snapshot %s: %v", table, err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("snapshot %s columns: %v", table, err)
	}
	fmt.Fprintf(b, "[%s]\n", table)
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("snapshot %s scan: %v", table, err)
		}
		for i, v := range vals {
			if bs, ok := v.([]byte); ok {
				vals[i] = string(bs)
			}
		}
		fmt.Fprintf(b, "%v\n", vals)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("snapshot %s rows: %v", table, err)
	}
}

// wfClient issues bounded JSON requests against the httptest server.
type wfClient struct {
	t    *testing.T
	base string
	http *http.Client
}

func (c *wfClient) do(method, path string, body any) (int, []byte) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wfRequestBound)
	defer cancel()

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("encode %s %s: %v", method, path, err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		c.t.Fatalf("build %s %s: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("%s %s read body: %v", method, path, err)
	}
	return resp.StatusCode, data
}

// wfLogged reports whether the API logged a private diagnostic containing
// needle. The response never carries it.
func wfLogged(entries []observer.LoggedEntry, needle string) bool {
	for _, entry := range entries {
		if strings.Contains(fmt.Sprint(entry.ContextMap()), needle) {
			return true
		}
	}
	return false
}

func wfExpect(t *testing.T, what string, status, want int, body []byte) {
	t.Helper()
	if status != want {
		t.Fatalf("%s: status %d, want %d; body: %s", what, status, want, body)
	}
}

func wfExpectDisabled(t *testing.T, what string, status int, body []byte) {
	t.Helper()
	wfExpect(t, what, status, http.StatusServiceUnavailable, body)
	var msg ErrorResponse
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatalf("%s: body is not a JSON error object: %v: %s", what, err, body)
	}
	if msg.Code != CodePaymentsDisabled || msg.Message != wfDisabledMessage {
		t.Fatalf("%s: envelope %+v, want code %q and message %q", what, msg, CodePaymentsDisabled, wfDisabledMessage)
	}
}

func wfDebuglets() []DebugletRequest {
	return []DebugletRequest{{
		OrderID:    1,
		ExecutorID: wfExecutorID,
		Wasm:       base64.StdEncoding.EncodeToString([]byte("\x00asm\x01\x00\x00\x00")),
		Policy: DebugletPolicyRequest{
			FloorBW:   wfFloorBW,
			CeilBW:    wfFloorBW,
			TimeoutMS: wfTimeoutMS,
			Addresses: []string{"127.0.0.1"},
		},
	}}
}

func wfSetCapacity(t *testing.T, d *dispatcher.Dispatcher, owner *rpc.SessionOwner, capacity resource.Bitrate) {
	t.Helper()
	mutation := apiTestMutation(t, context.Background(), owner)
	defer mutation.Finish()
	if _, err := d.OnResources(mutation.Context(), mutation, &protocol.ResourcesRequest{
		ExecutorId:        wfExecutorID,
		BandwidthCapacity: int64(capacity),
	}); err != nil {
		t.Fatalf("set capacity: %v", err)
	}
}

func wfDisabledConfig() *config.DispatcherConfig {
	return &config.DispatcherConfig{Sui: config.SuiConfig{
		Disabled:     true,
		Network:      "testnet",
		GRPCEndpoint: "127.0.0.1:1",
		KeystorePath: "/nonexistent/wf-keystore",
	}}
}

// TestWalletFreeHTTPFlow proves the wallet-free contract at the real HTTP and
// SQLite boundary: a disabled PaymentHandler, the real Dispatcher and Echo
// routes on loopback, backed by a fresh SQLite file initialised from the
// checked-in migrations. No executor process, wallet or chain endpoint exists.
func TestWalletFreeHTTPFlow(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	// The API keeps private diagnostics out of responses and in the log, so the
	// log is where a scripted database failure is observed.
	observedCore, observedLogs := observer.New(zapcore.WarnLevel)
	apiLogger := zap.New(observedCore)
	dbPath := filepath.Join(t.TempDir(), "dispatcher.sqlite")
	cfg := wfDisabledConfig()

	// Open the way the daemon does, so the flow runs with foreign keys
	// enforced. The daemon's opener never creates a file; an empty one is an
	// empty database.
	if err := os.WriteFile(dbPath, nil, 0o600); err != nil {
		t.Fatalf("create sqlite: %v", err)
	}
	db, err := sqlitedb.Open(dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	dbOpen := true
	t.Cleanup(func() {
		if dbOpen {
			db.Close()
		}
	})
	wfApplyMigrations(t, db)

	ph := payments.NewPaymentHandler(db, cfg, logger)
	d, err := dispatcher.New(logger, db, "wf-test", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	dispatcherOpen := true
	t.Cleanup(func() {
		if dispatcherOpen {
			d.Close()
		}
	})
	if err := d.RestoreScheduler(ctx); err != nil {
		t.Fatalf("restore scheduler: %v", err)
	}
	owner := apiTestOwner(t, d, wfExecutorID)
	if err := apiTestRegister(ctx, d, owner, &protocol.HelloResponse{
		ExecutorId: wfExecutorID, Version: "test", PricePerBwS: wfPricePerBwS, Currency: wfCurrency,
	}, "127.0.0.1"); err != nil {
		t.Fatalf("register executor: %v", err)
	}
	if !owner.MarkRegistered() {
		t.Fatal("executor owner retired before registration completed")
	}
	if _, ok := d.GetExecutor(wfExecutorID); !ok {
		t.Fatal("executor not registered")
	}
	wfSetCapacity(t, d, owner, wfHighCapacity)

	e := echo.New()
	e.HideBanner = true
	NewHandler(d, db, apiLogger, LocalDevelopment(true)).RegisterRoutes(e)
	srv := httptest.NewServer(e)
	serverOpen := true
	t.Cleanup(func() {
		if serverOpen {
			srv.Close()
		}
	})
	client := &wfClient{t: t, base: srv.URL, http: srv.Client()}
	queries := database.New(db)
	debuglets := wfDebuglets()
	wantHash := hashDebugletRequest(debuglets)

	// ---- 1. TEST intent, persisted state and status ----
	status, body := client.do(http.MethodPut, "/payment/intent", PaymentIntentRequest{
		Debuglets: debuglets, PaymentMethod: "TEST",
	})
	wfExpect(t, "TEST intent", status, http.StatusOK, body)
	var intent struct {
		Method string `json:"method"`
		Intent struct {
			TransactionID string `json:"transaction_id"`
			AuthKey       string `json:"auth_key"`
		} `json:"intent"`
	}
	if err := json.Unmarshal(body, &intent); err != nil {
		t.Fatalf("decode intent: %v: %s", err, body)
	}
	if intent.Method != "TEST" || intent.Intent.AuthKey != "" {
		t.Fatalf("unexpected intent payload: %s", body)
	}
	txID := intent.Intent.TransactionID
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(txID) {
		t.Fatalf("transaction id %q is not 16 random bytes in hex", txID)
	}
	tx, err := queries.GetTransactionByID(ctx, txID)
	if err != nil {
		t.Fatalf("transaction row: %v", err)
	}
	// CreateDummyIntent records the batch total as the price and TEST as the
	// currency; the order rows carry the per-order prices. With one order the
	// total is that order's price.
	if tx.Method != "TEST" || tx.Status != int64(models.Paid) || tx.AuthKey != "" || !strings.EqualFold(tx.Hash, wantHash) ||
		tx.Price != wfOrderPrice || tx.Currency != "TEST" {
		t.Fatalf("unexpected transaction row: %+v (want hash %s)", tx, wantHash)
	}
	orders, err := queries.GetTransactionOrders(ctx, txID)
	if err != nil {
		t.Fatalf("orders: %v", err)
	}
	if len(orders) != 1 || orders[0].OrderID != 1 || orders[0].ExecutorID != wfExecutorID || orders[0].Price != wfOrderPrice ||
		orders[0].Currency != "TEST" || orders[0].State != int64(models.Outstanding) {
		t.Fatalf("unexpected order rows: %+v", orders)
	}
	status, body = client.do(http.MethodGet, "/payment/"+txID+"/status", nil)
	wfExpect(t, "payment status", status, http.StatusOK, body)
	if strings.TrimSpace(string(body)) != "true" {
		t.Fatalf("payment status body %q, want true", body)
	}

	// ---- 2. Hash and auth-key checks still reject, rows unchanged ----
	before := wfTakeSnapshot(t, db)
	altered := wfDebuglets()
	altered[0].Args = []string{"altered"}
	status, body = client.do(http.MethodPut, "/debuglet", SubmitDebugletsRequest{
		Debuglets: altered, TransactionId: txID, AuthKey: "",
	})
	wfExpect(t, "altered submission", status, http.StatusBadRequest, body)
	if !strings.Contains(string(body), "does not match the intent") {
		t.Fatalf("altered submission body: %s", body)
	}
	status, body = client.do(http.MethodPut, "/debuglet", SubmitDebugletsRequest{
		Debuglets: debuglets, TransactionId: txID, AuthKey: "wrong",
	})
	wfExpect(t, "wrong auth key", status, http.StatusUnauthorized, body)
	if after := wfTakeSnapshot(t, db); after != before {
		t.Fatalf("rejected submissions changed rows:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	// ---- 3. Capacity rejection, then admission up to the insert boundary ----
	wfSetCapacity(t, d, owner, wfLowCapacity)
	status, body = client.do(http.MethodPut, "/debuglet", SubmitDebugletsRequest{
		Debuglets: debuglets, TransactionId: txID, AuthKey: "",
	})
	wfExpect(t, "insufficient capacity", status, http.StatusConflict, body)
	var capacityError ErrorResponse
	if err := json.Unmarshal(body, &capacityError); err != nil {
		t.Fatalf("capacity body is not the documented envelope: %v: %s", err, body)
	}
	if capacityError.Code != CodeCapacityExhausted || capacityError.Message != "capacity exceeded" {
		t.Fatalf("capacity envelope %+v, want code %q", capacityError, CodeCapacityExhausted)
	}
	if after := wfTakeSnapshot(t, db); after != before {
		t.Fatalf("capacity rejection changed rows:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	wfSetCapacity(t, d, owner, wfHighCapacity)
	if _, err := db.Exec(fmt.Sprintf(
		"CREATE TRIGGER %s BEFORE INSERT ON debuglets BEGIN SELECT RAISE(ABORT, '%s'); END", wfTriggerName, wfSentinel)); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	triggerInstalled := true
	dropTrigger := func() {
		if triggerInstalled {
			triggerInstalled = false
			if _, err := db.Exec("DROP TRIGGER " + wfTriggerName); err != nil {
				t.Errorf("drop trigger: %v", err)
			}
		}
	}
	t.Cleanup(dropTrigger)
	status, body = client.do(http.MethodPut, "/debuglet", SubmitDebugletsRequest{
		Debuglets: debuglets, TransactionId: txID, AuthKey: "",
	})
	wfExpect(t, "admission to insert boundary", status, http.StatusInternalServerError, body)
	var insertError ErrorResponse
	if err := json.Unmarshal(body, &insertError); err != nil {
		t.Fatalf("insert failure is not the documented envelope: %v: %s", err, body)
	}
	if insertError.Code != CodeInternal || insertError.Message != "failed to initialize debuglets" {
		t.Fatalf("insert failure envelope %+v, want code %q", insertError, CodeInternal)
	}
	if strings.Contains(string(body), wfSentinel) {
		t.Fatalf("the database diagnostic reached the client: %s", body)
	}
	if !wfLogged(observedLogs.TakeAll(), wfSentinel) {
		t.Fatalf("valid TEST submission did not reach the debuglets insert; body: %s", body)
	}
	dropTrigger()
	if after := wfTakeSnapshot(t, db); after != before {
		t.Fatalf("aborted insert changed rows:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if exec, _ := d.GetExecutor(wfExecutorID); len(exec.RecentDebugletIDs(10)) != 0 {
		t.Fatalf("aborted insert recorded debuglets: %v", exec.RecentDebugletIDs(10))
	}

	// ---- 4. Disabled chain paths: HTTP and direct calls, no mutation ----
	expires := models.NewUTCTime(time.Now().Add(5 * time.Minute))
	if _, err := queries.CreateTransaction(ctx, database.CreateTransactionParams{
		ID: wfChainTxID, AuthKey: wfChainAuthKey, Price: wfOrderPrice, Currency: "USDC", Method: "SUI",
		ExpiresAt: expires, Hash: wantHash, Status: int64(models.Paid),
	}); err != nil {
		t.Fatalf("seed chain transaction: %v", err)
	}
	if _, err := queries.CreateDebugletOrder(ctx, database.CreateDebugletOrderParams{
		TransactionID: wfChainTxID, OrderID: 1, ExecutorID: wfExecutorID, Price: wfOrderPrice,
		Currency: "USDC", RefundAddress: wfChainRefundAddr, State: int64(models.Outstanding),
	}); err != nil {
		t.Fatalf("seed chain order: %v", err)
	}
	if _, err := queries.CreateTransaction(ctx, database.CreateTransactionParams{
		ID: wfChainOutstandingID, AuthKey: "k", Price: 1, Currency: "SUI", Method: "SUI",
		ExpiresAt: expires, Hash: "h", Status: int64(models.Outstanding),
	}); err != nil {
		t.Fatalf("seed outstanding chain transaction: %v", err)
	}
	chainBefore := wfTakeSnapshot(t, db)

	for _, method := range []string{"USDC", "SUI"} {
		status, body = client.do(http.MethodPut, "/payment/intent", PaymentIntentRequest{
			Debuglets: debuglets, PaymentMethod: method, RefundAddress: wfChainRefundAddr,
		})
		wfExpectDisabled(t, method+" intent", status, body)
	}
	status, body = client.do(http.MethodPut, "/payment/intent", PaymentIntentRequest{
		Debuglets: debuglets, PaymentMethod: "BOGUS",
	})
	wfExpect(t, "unknown method intent", status, http.StatusBadRequest, body)
	status, body = client.do(http.MethodPut, "/debuglet", SubmitDebugletsRequest{
		Debuglets: debuglets, TransactionId: wfChainTxID, AuthKey: wfChainAuthKey,
	})
	wfExpectDisabled(t, "paid chain submission", status, body)
	status, body = client.do(http.MethodPut, "/debuglet", SubmitDebugletsRequest{
		Debuglets: debuglets, TransactionId: wfChainTxID, AuthKey: "wrong",
	})
	wfExpect(t, "chain submission with wrong auth key", status, http.StatusUnauthorized, body)

	chainDebuglet := &database.Debuglet{Uuid: uuid.New(), TransactionID: wfChainTxID, OrderID: 1, ExecutorID: wfExecutorID}
	direct := []struct {
		name string
		call func() error
	}{
		{"SetDebugletOrderComplete", func() error { return ph.SetDebugletOrderComplete(chainDebuglet, ctx) }},
		{"RefundDebugletOrder", func() error { return ph.RefundDebugletOrder(chainDebuglet, wfChainRefundAddr, ctx) }},
		{"RefundTransaction", func() error { return ph.RefundTransaction(wfChainTxID, ctx) }},
		{"TransferUSDC", func() error { return ph.TransferUSDC(1, wfChainRefundAddr, ctx) }},
		{"PayoutExecutor", func() error {
			return ph.PayoutExecutor(database.Earning{ExecutorID: wfExecutorID, Currency: "USDC", CurrentBalance: 1, SuiWalletAddress: wfChainRefundAddr}, ctx)
		}},
		{"CreatePaymentIntent", func() error {
			_, err := ph.CreatePaymentIntent("wf-never-created", 1, "USDC", "h", ctx)
			return err
		}},
	}
	for _, c := range direct {
		if err := c.call(); !errors.Is(err, payments.ErrPaymentsDisabled) {
			t.Fatalf("%s in disabled mode returned %v, want ErrPaymentsDisabled", c.name, err)
		}
	}
	ph.CompleteTransaction(wfChainOutstandingID, ctx)
	outstanding, err := queries.GetTransactionByID(ctx, wfChainOutstandingID)
	if err != nil {
		t.Fatalf("outstanding chain transaction: %v", err)
	}
	if outstanding.Status != int64(models.Outstanding) {
		t.Fatalf("CompleteTransaction marked a chain transaction as %d in disabled mode", outstanding.Status)
	}
	if after := wfTakeSnapshot(t, db); after != chainBefore {
		t.Fatalf("disabled chain paths changed rows:\nbefore:\n%s\nafter:\n%s", chainBefore, after)
	}

	// ---- 5. TEST completion and earnings; unsupported TEST refunds ----
	testDebuglet := &database.Debuglet{Uuid: uuid.New(), TransactionID: txID, OrderID: 1, ExecutorID: wfExecutorID}
	if err := ph.SetDebugletOrderComplete(testDebuglet, ctx); err != nil {
		t.Fatalf("TEST order completion: %v", err)
	}
	order, err := queries.GetDebugletOrder(ctx, database.GetDebugletOrderParams{TransactionID: txID, OrderID: 1})
	if err != nil {
		t.Fatalf("completed order: %v", err)
	}
	if order.State != int64(models.Credited) {
		t.Fatalf("completed order state %d, want Credited", order.State)
	}
	earning, err := queries.GetEarningsIn(ctx, database.GetEarningsInParams{ExecutorID: wfExecutorID, Currency: wfCurrency})
	if err != nil {
		t.Fatalf("TEST earnings: %v", err)
	}
	if earning.TotalIncome != wfOrderPrice || earning.CurrentBalance != wfOrderPrice {
		t.Fatalf("TEST earnings %+v, want income and balance %d", earning, wfOrderPrice)
	}
	completed := wfTakeSnapshot(t, db)
	if err := ph.RefundDebugletOrder(testDebuglet, "", ctx); err == nil {
		t.Fatal("TEST order refund succeeded; refunds are unsupported for TEST")
	} else if errors.Is(err, payments.ErrPaymentsDisabled) {
		t.Fatalf("TEST order refund reported the chain sentinel: %v", err)
	}
	if err := ph.RefundTransaction(txID, ctx); err == nil {
		t.Fatal("TEST transaction refund succeeded; refunds are unsupported for TEST")
	} else if errors.Is(err, payments.ErrPaymentsDisabled) {
		t.Fatalf("TEST transaction refund reported the chain sentinel: %v", err)
	}
	if after := wfTakeSnapshot(t, db); after != completed {
		t.Fatalf("unsupported TEST refunds changed rows:\nbefore:\n%s\nafter:\n%s", completed, after)
	}

	startCtx, cancelStart := context.WithCancel(ctx)
	startErr := make(chan error, 1)
	go func() { startErr <- ph.Start(startCtx) }()
	select {
	case err := <-startErr:
		if err != nil {
			t.Fatalf("disabled Start returned %v", err)
		}
	case <-time.After(wfJoinBound):
		cancelStart()
		t.Fatalf("disabled Start did not return within %s; a payout loop or listener was started", wfJoinBound)
	}
	cancelStart()

	// ---- 6. Persistence across close and reopen ----
	srv.Close()
	serverOpen = false
	d.Close()
	dispatcherOpen = false
	if err := db.Close(); err != nil {
		t.Fatalf("close sqlite: %v", err)
	}
	dbOpen = false

	db2, err := sqlitedb.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen sqlite: %v", err)
	}
	defer db2.Close()
	reopened, err := database.New(db2).GetTransactionByID(ctx, txID)
	if err != nil {
		t.Fatalf("reopened transaction: %v", err)
	}
	if reopened.Status != int64(models.Paid) || !strings.EqualFold(reopened.Hash, wantHash) {
		t.Fatalf("reopened transaction row changed: %+v", reopened)
	}
	if after := wfTakeSnapshot(t, db2); after != completed {
		t.Fatalf("rows differ after reopen:\nbefore:\n%s\nafter:\n%s", completed, after)
	}
	ph2 := payments.NewPaymentHandler(db2, cfg, logger)
	paid, err := ph2.IsPaid(ctx, txID)
	if err != nil {
		t.Fatalf("IsPaid after reopen: %v", err)
	}
	if !paid {
		t.Fatal("TEST transaction no longer reported paid after reopen")
	}
	if err := ph2.CheckPaymentMethod("USDC"); !errors.Is(err, payments.ErrPaymentsDisabled) {
		t.Fatalf("reconstructed handler CheckPaymentMethod(USDC) = %v, want ErrPaymentsDisabled", err)
	}
}
