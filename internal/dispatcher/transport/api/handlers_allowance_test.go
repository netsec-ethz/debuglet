// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/pkg/wire"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// alNewFixture is ccNewFixtureWith with usage allowances enabled in the
// payment handler's configuration, which is where the daemon reads them.
func alNewFixture(t *testing.T, options ...Option) *ccFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "dispatcher.sqlite"), sqlitedb.Create())
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cfg := &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}, Allowance: config.AllowanceConfig{Enabled: true}}
	d, err := dispatcher.New(zap.NewNop(), db, "al-version", time.Minute, time.Minute, payments.NewPaymentHandler(db, cfg, zap.NewNop()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	peer := &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "TEST"}
	stop, err := startClientPeer(ctx, d, ccCapacity, peer)
	if err != nil {
		t.Fatalf("startClientPeer: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), ccCleanupBound)
		defer cancelCleanup()
		if err := stop(cleanupCtx); err != nil {
			t.Errorf("stop client peer: %v", err)
		}
	})
	e := echo.New()
	e.HideBanner = true
	NewHandler(d, db, zap.NewNop(), options...).RegisterRoutes(e)
	root := httptest.NewServer(e)
	t.Cleanup(func() {
		root.CloseClientConnections()
		root.Close()
	})
	return &ccFixture{t: t, ctx: ctx, db: db, queries: database.New(db), d: d, peer: peer, root: root}
}

// alAccounts registers an operator and an ordinary account and returns their
// IDs and session tokens.
func alAccounts(t *testing.T, f *ccFixture) (operatorID, operatorToken, userID, userToken string) {
	t.Helper()
	operator, operatorToken, _ := authAccount(t, f, "operator")
	authGrantOperator(t, f, operator.ID)
	user, userToken, _ := authAccount(t, f, "user")
	return operator.ID, operatorToken, user.ID, userToken
}

// alGrant posts a grant request as the account holding token.
func alGrant(t *testing.T, f *ccFixture, token, account, body string) (int, ErrorResponse, wire.AllowanceGrantResult) {
	t.Helper()
	status, _, data, _ := authRequest(t, f, http.MethodPost, "/operator/accounts/"+account+"/allowance", []byte(body), authBearer(token))
	var envelope ErrorResponse
	var result wire.AllowanceGrantResult
	if status == http.StatusOK || status == http.StatusCreated {
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("decode the grant %s: %v", data, err)
		}
	} else if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("the refusal is not the documented envelope: %v: %s", err, data)
	}
	return status, envelope, result
}

// alAllowance reads GET /me/allowance as the account holding token.
func alAllowance(t *testing.T, f *ccFixture, token string) (int, ErrorResponse, wire.Allowance) {
	t.Helper()
	status, _, data, _ := authRequest(t, f, http.MethodGet, "/me/allowance", nil, authBearer(token))
	var envelope ErrorResponse
	var allowance wire.Allowance
	if status == http.StatusOK {
		if err := json.Unmarshal(data, &allowance); err != nil {
			t.Fatalf("decode the allowance %s: %v", data, err)
		}
	} else if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("the refusal is not the documented envelope: %v: %s", err, data)
	}
	return status, envelope, allowance
}

func alWant(granted, reserved, consumed, remaining string) wire.Allowance {
	return wire.Allowance{Currency: "TEST", Granted: granted, Reserved: reserved, Consumed: consumed, Remaining: remaining, PricingRule: PricingRule}
}

func alEconomics(t *testing.T, f *ccFixture, token string) wire.Economics {
	t.Helper()
	status, _, data, _ := authRequest(t, f, http.MethodGet, "/me", nil, authBearer(token))
	var user wire.User
	if status != http.StatusOK || json.Unmarshal(data, &user) != nil || user.Economics == nil {
		t.Fatalf("GET /me answered %d: %s", status, data)
	}
	return *user.Economics
}

// An account's intents are reserved within its grants; an intent beyond them
// answers 429 allowance_exceeded naming remaining and required units and
// writes no transaction, order or owner.
func TestAllowanceCapsAccountIntents(t *testing.T) {
	f := alNewFixture(t)
	operatorID, operatorToken, userID, userToken := alAccounts(t, f)
	if !alEconomics(t, f, userToken).Allowances {
		t.Fatal("GET /me does not report allowances as enabled")
	}
	before := ecRowCounts(t, f)
	status, envelope, _, data := iaPutIntent(t, f, userToken, iaDebuglet(1, 1000, 2000))
	if status != http.StatusTooManyRequests || envelope.Code != CodeAllowanceExceeded ||
		!strings.Contains(envelope.Message, "0 TEST units remaining") || !strings.Contains(envelope.Message, "requires 2000") {
		t.Fatalf("intent without a grant answered %d: %s", status, data)
	}
	if after := ecRowCounts(t, f); after["transactions"] != before["transactions"] || after["debuglet_order"] != before["debuglet_order"] || after["transaction_users"] != before["transaction_users"] {
		t.Fatalf("a refused intent wrote rows: before %v after %v", before, after)
	}

	status, _, grant := alGrant(t, f, operatorToken, userID, `{"amount":"5000","reason":"trial","idempotency_key":"first"}`)
	if status != http.StatusCreated || grant.Grant.Amount != "5000" || grant.Grant.GrantedBy != operatorID || grant.Allowance != alWant("5000", "0", "0", "5000") {
		t.Fatalf("grant answered %d: %+v", status, grant)
	}
	for i := range 2 {
		if status, _, _, data := iaPutIntent(t, f, userToken, iaDebuglet(int64(i), 1000, 2000)); status != http.StatusOK {
			t.Fatalf("intent %d within the allowance answered %d: %s", i, status, data)
		}
	}
	before = ecRowCounts(t, f)
	status, envelope, _, data = iaPutIntent(t, f, userToken, iaDebuglet(3, 1000, 2000))
	if status != http.StatusTooManyRequests || envelope.Code != CodeAllowanceExceeded ||
		!strings.Contains(envelope.Message, "1000 TEST units remaining") || !strings.Contains(envelope.Message, "requires 2000") {
		t.Fatalf("intent beyond the allowance answered %d: %s", status, data)
	}
	if after := ecRowCounts(t, f); after["transactions"] != before["transactions"] || after["debuglet_order"] != before["debuglet_order"] || after["transaction_users"] != before["transaction_users"] {
		t.Fatalf("a refused intent wrote rows: before %v after %v", before, after)
	}
	if status, _, allowance := alAllowance(t, f, userToken); status != http.StatusOK || allowance != alWant("5000", "4000", "0", "1000") {
		t.Fatalf("allowance answered %d: %+v", status, allowance)
	}
	// The quote never consults the allowance.
	if status, _, _, data := ecQuote(t, f, userToken, "TEST", iaDebuglet(1, 1000, 20000)); status != http.StatusOK {
		t.Fatalf("quote beyond the allowance answered %d: %s", status, data)
	}
}

// Eight concurrent intents against one grant never reserve more than it.
func TestAllowanceConcurrentIntentsNeverOverReserve(t *testing.T) {
	f := alNewFixture(t)
	_, operatorToken, userID, userToken := alAccounts(t, f)
	if status, _, _ := alGrant(t, f, operatorToken, userID, `{"amount":"10000","reason":"trial","idempotency_key":"first"}`); status != http.StatusCreated {
		t.Fatalf("grant answered %d", status)
	}
	statuses := make([]int, 8)
	var wg sync.WaitGroup
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, _ := json.Marshal(PaymentIntentRequest{Debuglets: []DebugletRequest{iaDebuglet(int64(i), 1000, 2000)}, PaymentMethod: "TEST"})
			req, err := http.NewRequestWithContext(f.ctx, http.MethodPut, f.root.URL+"/payment/intent", strings.NewReader(string(body)))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+userToken)
			resp, err := f.root.Client().Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()
			statuses[i] = resp.StatusCode
		}()
	}
	wg.Wait()
	accepted, refused := 0, 0
	for _, status := range statuses {
		switch status {
		case http.StatusOK:
			accepted++
		case http.StatusTooManyRequests:
			refused++
		default:
			t.Fatalf("concurrent intents answered %v", statuses)
		}
	}
	if accepted != 5 || refused != 3 {
		t.Fatalf("concurrent intents answered %v, want five accepted and three refused", statuses)
	}
	var reserved int64
	if err := f.db.QueryRow(`SELECT SUM(t.price) FROM transactions t JOIN transaction_users tu ON tu.transaction_id = t.id`).Scan(&reserved); err != nil || reserved != 10000 {
		t.Fatalf("reserved %d, %v; want exactly the grant", reserved, err)
	}
	if status, _, allowance := alAllowance(t, f, userToken); status != http.StatusOK || allowance != alWant("10000", "10000", "0", "0") {
		t.Fatalf("allowance answered %d: %+v", status, allowance)
	}
}

// An unadmitted intent past its expiry is released by the account's next
// intent, and submitting it then answers that it expired unused.
func TestAllowanceExpiredIntentIsReleasedAndRefused(t *testing.T) {
	f := alNewFixture(t)
	_, operatorToken, userID, userToken := alAccounts(t, f)
	if status, _, _ := alGrant(t, f, operatorToken, userID, `{"amount":"4000","reason":"trial","idempotency_key":"first"}`); status != http.StatusCreated {
		t.Fatalf("grant answered %d", status)
	}
	batch := iaDebuglet(1, 1000, 2000)
	status, _, expired, data := iaPutIntent(t, f, userToken, batch)
	if status != http.StatusOK {
		t.Fatalf("intent answered %d: %s", status, data)
	}
	if _, err := f.db.Exec("UPDATE transactions SET expires_at = ? WHERE id = ?", models.NewUTCTime(time.Now().Add(-time.Hour)), expired); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if status, _, _, data := iaPutIntent(t, f, userToken, iaDebuglet(int64(i+2), 1000, 2000)); status != http.StatusOK {
			t.Fatalf("intent %d after the release answered %d: %s", i, status, data)
		}
	}
	body, _ := json.Marshal(SubmitDebugletsRequest{Debuglets: []DebugletRequest{batch}, TransactionId: expired})
	status, code, data, _ := authRequest(t, f, http.MethodPut, "/debuglet", body, authBearer(userToken))
	if status != http.StatusBadRequest || code != CodePaymentIncomplete || !strings.Contains(string(data), "expired unused") {
		t.Fatalf("submission of the released intent answered %d: %s", status, data)
	}
	if iaCount(t, f.db, "debuglets") != 0 {
		t.Fatal("the released intent admitted a run")
	}
	if status, _, allowance := alAllowance(t, f, userToken); status != http.StatusOK || allowance != alWant("4000", "4000", "0", "0") {
		t.Fatalf("allowance answered %d: %+v", status, allowance)
	}
}

// The grant route is operator-only, records a grant once per idempotency key,
// grants the configured default when no amount is named and refuses a changed
// body under a used key.
func TestAllowanceGrantRoute(t *testing.T) {
	f := alNewFixture(t)
	_, operatorToken, userID, userToken := alAccounts(t, f)
	body := `{"reason":"trial","idempotency_key":"first"}`
	if status, envelope, _ := alGrant(t, f, "", userID, body); status != http.StatusUnauthorized {
		t.Fatalf("anonymous grant answered %d %s", status, envelope.Code)
	}
	if status, envelope, _ := alGrant(t, f, userToken, userID, body); status != http.StatusForbidden || envelope.Code != CodeForbidden {
		t.Fatalf("grant by an ordinary account answered %d %s", status, envelope.Code)
	}
	status, _, first := alGrant(t, f, operatorToken, userID, body)
	if status != http.StatusCreated || first.Grant.Amount != "30000000" || first.Grant.Reason != "trial" || first.Grant.IdempotencyKey != "first" {
		t.Fatalf("default grant answered %d: %+v", status, first)
	}
	status, _, again := alGrant(t, f, operatorToken, userID, `{"amount":"30000000","reason":"trial","idempotency_key":"first"}`)
	if status != http.StatusOK || again.Grant != first.Grant || again.Allowance.Granted != "30000000" {
		t.Fatalf("repeated grant answered %d: %+v", status, again)
	}
	for _, changed := range []string{`{"amount":"1","reason":"trial","idempotency_key":"first"}`, `{"reason":"other","idempotency_key":"first"}`} {
		if status, envelope, _ := alGrant(t, f, operatorToken, userID, changed); status != http.StatusConflict || envelope.Code != CodeConflict {
			t.Fatalf("changed grant %s answered %d %s", changed, status, envelope.Code)
		}
	}
	if iaCount(t, f.db, "allowance_grants") != 1 {
		t.Fatal("a repeated or conflicting grant recorded a row")
	}
	for _, invalid := range []string{`{"amount":"0","reason":"trial","idempotency_key":"k"}`, `{"amount":"-5","reason":"trial","idempotency_key":"k"}`,
		`{"amount":"1.5","reason":"trial","idempotency_key":"k"}`, `{"reason":"  ","idempotency_key":"k"}`, `{"reason":"trial"}`} {
		if status, envelope, _ := alGrant(t, f, operatorToken, userID, invalid); status != http.StatusBadRequest || envelope.Code != CodeInvalidRequest {
			t.Fatalf("grant %s answered %d %s", invalid, status, envelope.Code)
		}
	}
	for _, account := range []string{uuid.NewString(), "not-an-account"} {
		if status, envelope, _ := alGrant(t, f, operatorToken, account, body); status != http.StatusNotFound || envelope.Code != CodeNotFound {
			t.Fatalf("grant to %s answered %d %s", account, status, envelope.Code)
		}
	}
}

// While allowances are disabled, the allowance routes answer 404 and an
// account's intent is not capped.
func TestAllowancesDisabledLeaveIntentsUnchanged(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, operatorToken, userID, userToken := alAccounts(t, f)
	if alEconomics(t, f, userToken).Allowances {
		t.Fatal("GET /me reports allowances while they are disabled")
	}
	if status, envelope, _ := alAllowance(t, f, userToken); status != http.StatusNotFound || envelope.Code != CodeNotFound || envelope.Message != "allowances are not enabled" {
		t.Fatalf("GET /me/allowance answered %d %+v", status, envelope)
	}
	if status, envelope, _ := alGrant(t, f, operatorToken, userID, `{"reason":"trial","idempotency_key":"k"}`); status != http.StatusNotFound || envelope.Message != "allowances are not enabled" {
		t.Fatalf("grant answered %d %+v", status, envelope)
	}
	if status, _, _, data := iaPutIntent(t, f, userToken, iaDebuglet(1, 1000, 2000)); status != http.StatusOK {
		t.Fatalf("uncapped intent answered %d: %s", status, data)
	}
}

// The request without a credential that the local development profile admits
// names no account and is not capped.
func TestAllowanceLeavesTheLocalDevelopmentCallerUncapped(t *testing.T) {
	f := alNewFixture(t, LocalDevelopment(true))
	if status, _, _, data := iaPutIntent(t, f, "", iaDebuglet(1, 1000, 2000)); status != http.StatusOK {
		t.Fatalf("local development intent answered %d: %s", status, data)
	}
	if iaCount(t, f.db, "transaction_users") != 0 {
		t.Fatal("the local development intent recorded an owner")
	}
}

// The earnings route reports an owned executor's earnings and transfers and
// answers 404 for another account's executor.
func TestExecutorEarningsForTheOwnerOnly(t *testing.T) {
	f := ccNewFixtureWith(t)
	owner, ownerToken, _ := authAccount(t, f, "owner")
	_, otherToken, _ := authAccount(t, f, "other")
	ctx := t.Context()
	const executorID = "owned-executor"
	if n, err := f.queries.CreateOwnedExecutor(ctx, database.CreateOwnedExecutorParams{
		ExecutorID: executorID, Name: "node", CreatedAt: models.NewUTCTime(time.Now()), Uuid: uuid.MustParse(owner.ID),
	}); err != nil || n != 1 {
		t.Fatalf("own executor: %d, %v", n, err)
	}
	if _, err := f.queries.CreateEarnings(ctx, database.CreateEarningsParams{ExecutorID: executorID, Currency: "TEST"}); err != nil {
		t.Fatal(err)
	}
	if err := f.queries.AddEarnings(ctx, database.AddEarningsParams{Amount: 42, ExecutorID: executorID, Currency: "TEST"}); err != nil {
		t.Fatal(err)
	}
	now := models.NewUTCTime(time.Now())
	if _, err := f.db.Exec(`INSERT INTO chain_transfers (kind, executor_id, amount, currency, receiver, state, digest, created_at, updated_at)
		VALUES ('payout', ?, 40, 'USDC', '0xwallet', 'unknown', 'digest-1', ?, ?)`, executorID, now, now); err != nil {
		t.Fatal(err)
	}

	status, _, data, _ := authRequest(t, f, http.MethodGet, "/operator/executors/"+executorID+"/earnings", nil, authBearer(ownerToken))
	var earnings wire.ExecutorEarnings
	if status != http.StatusOK || json.Unmarshal(data, &earnings) != nil {
		t.Fatalf("owner earnings answered %d: %s", status, data)
	}
	if earnings.Currency != "TEST" || earnings.TotalIncome != "42" || earnings.CurrentBalance != "42" || earnings.Payouts != "disabled" ||
		len(earnings.Transfers) != 1 || earnings.Transfers[0].Kind != "payout" || earnings.Transfers[0].Amount != "40" ||
		earnings.Transfers[0].State != "unknown" || earnings.Transfers[0].Digest != "digest-1" {
		t.Fatalf("earnings %+v", earnings)
	}
	for _, request := range []struct{ token, id string }{{otherToken, executorID}, {ownerToken, "no-such-executor"}} {
		if status, code := authAs(t, f, request.token, http.MethodGet, "/operator/executors/"+request.id+"/earnings", nil); status != http.StatusNotFound || code != CodeNotFound {
			t.Fatalf("earnings of %s answered %d %s", request.id, status, code)
		}
	}
}
