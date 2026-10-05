package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	grpcstatus "google.golang.org/grpc/status"
)

// These tests hold the public error boundary with sentinel values: a
// credential, a request value or a database diagnostic that must not reach a
// response, and, for credentials, not the routine log either. The log is
// observed at Info, the level a deployment runs at.

// dcNewFixture is the client contract fixture with the dispatcher, the payment
// handler and the API logging to one core observed at Info.
func dcNewFixture(t *testing.T, options ...Option) (*ccFixture, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zapcore.InfoLevel)
	return ccNewFixtureLogged(t, zap.New(core), options...), logs
}

// dcSentinel is a unique marker longer than the bound of a repeated value, so
// its full text can only appear where nothing bounds it.
func dcSentinel(t *testing.T, label string) string {
	t.Helper()
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	return "SENTINEL-" + label + "-" + hex.EncodeToString(random) + "-" + strings.Repeat("z", 64)
}

func dcRender(entry observer.LoggedEntry) string {
	return entry.Message + " " + fmt.Sprint(entry.ContextMap())
}

// dcAssertPrivate fails when any secret appears in the response body or in any
// entry logged so far.
func dcAssertPrivate(t *testing.T, what string, logs *observer.ObservedLogs, body []byte, secrets ...string) {
	t.Helper()
	for i, secret := range secrets {
		if secret == "" {
			t.Fatalf("%s: secret %d is empty", what, i)
		}
		if strings.Contains(string(body), secret) {
			t.Fatalf("%s: the response carries secret %d: %s", what, i, strings.ReplaceAll(string(body), secret, "<redacted>"))
		}
		for _, entry := range logs.All() {
			if rendered := dcRender(entry); strings.Contains(rendered, secret) {
				t.Fatalf("%s: the log carries secret %d: %s", what, i, strings.ReplaceAll(rendered, secret, "<redacted>"))
			}
		}
	}
}

// dcAssertLoggedCause checks the routine entry retains actionable correlation
// while keeping the private diagnostic out of both the response and Info logs.
func dcAssertLoggedCause(t *testing.T, what string, logs *observer.ObservedLogs, body []byte, route, sentinel string) {
	t.Helper()
	dcAssertPrivate(t, what, logs, body, sentinel)
	for _, entry := range logs.FilterMessage("request failed").All() {
		fields := entry.ContextMap()
		if fields["route"] == route && fields["code"] != "" && fields["status"] != nil {
			return
		}
	}
	t.Fatalf("%s: missing correlated request failure for %s", what, route)
}

func dcExpect(t *testing.T, what string, status int, body []byte, wantStatus int, wantCode, wantMessage string) {
	t.Helper()
	if status != wantStatus {
		t.Fatalf("%s: status = %d, want %d; body: %s", what, status, wantStatus, body)
	}
	envelope := envelopeOf(t, what, body)
	if envelope.Code != wantCode || (wantMessage != "" && envelope.Message != wantMessage) {
		t.Fatalf("%s: envelope %+v, want code %q and message %q", what, envelope, wantCode, wantMessage)
	}
}

func dcJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func dcDebuglets() []DebugletRequest {
	return []DebugletRequest{{
		ExecutorID: ccExecutorID,
		Wasm:       base64.StdEncoding.EncodeToString(ccGuest),
		Policy:     DebugletPolicyRequest{FloorBW: ccFloorBW, CeilBW: ccFloorBW, TimeoutMS: ccDurationMS, Addresses: []string{"127.0.0.1"}},
	}}
}

// dcIntent creates a TEST payment intent for debuglets and returns its
// transaction ID.
func dcIntent(t *testing.T, f *ccFixture, token string, debuglets []DebugletRequest) string {
	t.Helper()
	status, _, body, _ := authRequest(t, f, http.MethodPut, "/payment/intent",
		dcJSON(t, PaymentIntentRequest{Debuglets: debuglets, PaymentMethod: "TEST"}), authBearer(token))
	var intent struct {
		Intent DummyIntent `json:"intent"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &intent) != nil || intent.Intent.TransactionID == "" {
		t.Fatalf("TEST intent: status %d, body %s", status, body)
	}
	return intent.Intent.TransactionID
}

func dcSubmitBody(t *testing.T, txID, authKey string, debuglets []DebugletRequest) []byte {
	return dcJSON(t, SubmitDebugletsRequest{Debuglets: debuglets, TransactionId: txID, AuthKey: authKey})
}

// TestCredentialFailuresStayOutOfResponsesAndLogs presents every kind of
// rejected credential and then runs the ordinary flow. No response and no log
// entry carries a presented or an issued credential.
func TestCredentialFailuresStayOutOfResponsesAndLogs(t *testing.T) {
	f, logs := dcNewFixture(t)
	account, token, _ := authAccount(t, f, "disclosure")
	status, _, body, _ := authRequest(t, f, http.MethodPost, "/auth/login", dcJSON(t, LoginRequest{AccountKey: account.AccountKey}), nil)
	var session SessionResponse
	if status != http.StatusOK || json.Unmarshal(body, &session) != nil || session.Token == "" || session.CSRFToken == "" {
		t.Fatalf("login: status %d", status)
	}
	forged, _, _, err := newCredential(sessionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	storedKey, wrongKey := dcSentinel(t, "stored-auth-key"), dcSentinel(t, "wrong-auth-key")
	if _, err := f.queries.CreateTransaction(f.ctx, database.CreateTransactionParams{
		ID: "dc-paid", AuthKey: storedKey, Price: 1, Currency: "TEST", Method: "TEST",
		ExpiresAt: models.NewUTCTime(time.Now().Add(time.Hour)), Hash: hashDebugletRequest(dcDebuglets()), Status: int64(models.Paid),
	}); err != nil {
		t.Fatalf("seed transaction: %v", err)
	}
	// The oversized token is well formed apart from its length, so only the
	// length bound rejects it.
	cookie, bearer, oversized := dcSentinel(t, "cookie"), dcSentinel(t, "bearer"), sessionPrefix+"_"+dcSentinel(t, "oversized")+"."+strings.Repeat("z", maxCredentialLength)
	csrf, accountKey, recovery := dcSentinel(t, "csrf"), accountPrefix+"_"+dcSentinel(t, "account-key"), recoveryPrefix+"_"+dcSentinel(t, "recovery")

	for _, tc := range []struct {
		name, method, target string
		body                 []byte
		headers              map[string]string
		status               int
		code, message        string
		secrets              []string
	}{
		{"malformed session cookie", http.MethodGet, "/me", nil, map[string]string{"Cookie": sessionCookieName + "=" + cookie},
			http.StatusUnauthorized, CodeUnauthorized, "authentication required", []string{cookie}},
		{"malformed bearer token", http.MethodGet, "/me", nil, authBearer(bearer),
			http.StatusUnauthorized, CodeUnauthorized, "authentication required", []string{bearer}},
		{"oversized bearer token", http.MethodGet, "/me", nil, authBearer(oversized),
			http.StatusUnauthorized, CodeUnauthorized, "authentication required", []string{oversized}},
		{"unknown session token", http.MethodGet, "/me", nil, authBearer(forged),
			http.StatusUnauthorized, CodeUnauthorized, "authentication required", []string{forged}},
		{"wrong CSRF token", http.MethodPost, "/auth/logout", nil,
			map[string]string{"Cookie": sessionCookieName + "=" + session.Token, csrfHeaderName: csrf},
			http.StatusForbidden, CodeForbidden, "cookie-authenticated requests must repeat the session CSRF token", []string{csrf, session.Token, session.CSRFToken}},
		{"wrong account key", http.MethodPost, "/auth/login", dcJSON(t, LoginRequest{AccountKey: accountKey}), nil,
			http.StatusUnauthorized, CodeUnauthorized, "authentication required", []string{accountKey}},
		{"wrong recovery code", http.MethodPost, "/auth/recover", dcJSON(t, RecoverRequest{RecoveryCode: recovery}), nil,
			http.StatusUnauthorized, CodeUnauthorized, "authentication required", []string{recovery}},
		{"wrong auth key", http.MethodPut, "/debuglet", dcSubmitBody(t, "dc-paid", wrongKey, dcDebuglets()), authBearer(token),
			http.StatusUnauthorized, CodeUnauthorized, "unknown transaction or wrong auth key", []string{wrongKey, storedKey, token}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, _, body, _ := authRequest(t, f, tc.method, tc.target, tc.body, tc.headers)
			dcExpect(t, tc.name, status, body, tc.status, tc.code, tc.message)
			dcAssertPrivate(t, tc.name, logs, body, tc.secrets...)
		})
	}

	// The ordinary flow: intent, submission and reads with the issued session.
	txID := dcIntent(t, f, token, dcDebuglets())
	status, _, body, _ = authRequest(t, f, http.MethodPut, "/debuglet", dcSubmitBody(t, txID, "", dcDebuglets()), authBearer(token))
	var ids []string
	if status != http.StatusOK || json.Unmarshal(body, &ids) != nil || len(ids) != 1 {
		t.Fatalf("submission: status %d, body %s", status, body)
	}
	for _, target := range []string{"/debuglet/" + ids[0] + "/state", "/debuglet/" + ids[0] + "/logs", "/list-debuglets", "/me"} {
		if status, code := authAs(t, f, token, http.MethodGet, target, nil); status != http.StatusOK {
			t.Fatalf("GET %s: status %d (%s)", target, status, code)
		}
	}
	// The submission logged at Info, so the absence below is observed on a
	// live log and not on an empty one.
	if logs.FilterMessage("Run admitted").Len() == 0 {
		t.Fatal("the submission logged nothing at Info")
	}
	dcAssertPrivate(t, "ordinary flow", logs, nil, token, session.Token, session.CSRFToken, account.AccountKey, account.RecoveryCode)
}

// TestRepeatedRequestValuesAreBoundedOrRefused sends request values a
// response may repeat. Each is either repeated within the documented bound or
// refused with fixed text. A request value is not a credential: the log may
// record it as a diagnostic, so only the response is held to the bound.
func TestRepeatedRequestValuesAreBoundedOrRefused(t *testing.T) {
	f, _ := dcNewFixture(t)
	account, token, _ := authAccount(t, f, "echo")
	executor, method, unpaid := dcSentinel(t, "executor"), dcSentinel(t, "method"), dcSentinel(t, "transaction")
	unknown, query, wasm := dcSentinel(t, "unknown-transaction"), dcSentinel(t, "query"), dcSentinel(t, "wasm")
	runSentinel := dcSentinel(t, "run")
	run := runSentinel + "\n\x01\x7f"

	if _, err := f.queries.CreateTransaction(f.ctx, database.CreateTransactionParams{
		ID: unpaid, Price: 1, Currency: "TEST", Method: "TEST",
		ExpiresAt: models.NewUTCTime(time.Now().Add(time.Hour)), Hash: hashDebugletRequest(dcDebuglets()), Status: int64(models.Outstanding),
	}); err != nil {
		t.Fatalf("seed transaction: %v", err)
	}
	if err := f.queries.SetTransactionOwner(f.ctx, database.SetTransactionOwnerParams{TransactionID: unpaid, Uuid: uuid.MustParse(account.ID)}); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	unknownExecutor := dcDebuglets()
	unknownExecutor[0].ExecutorID = executor
	invalidWasm := dcDebuglets()
	invalidWasm[0].Wasm = wasm
	wasmTx := dcIntent(t, f, token, invalidWasm)

	for _, tc := range []struct {
		name, method, target string
		body                 []byte
		status               int
		code, message        string
		sentinel             string
	}{
		// Repeated within the bound.
		{"unknown executor", http.MethodPut, "/payment/intent", dcJSON(t, PaymentIntentRequest{Debuglets: unknownExecutor, PaymentMethod: "TEST"}),
			http.StatusBadRequest, CodeUnknownExecutor, "unknown executor: " + echoed(executor), executor},
		{"unknown payment method", http.MethodPut, "/payment/intent", dcJSON(t, PaymentIntentRequest{Debuglets: dcDebuglets(), PaymentMethod: method}),
			http.StatusBadRequest, CodeUnsupportedPaymentMethod, "unknown payment method: " + echoed(method), method},
		{"unknown executor key schedule", http.MethodGet, "/executors/" + executor + "/tesla", nil,
			http.StatusNotFound, CodeNotFound, "executor not found: " + echoed(executor), executor},
		{"unpaid transaction", http.MethodPut, "/debuglet", dcSubmitBody(t, unpaid, "", dcDebuglets()),
			http.StatusBadRequest, CodePaymentIncomplete, "Transaction " + echoed(unpaid) + " has not yet been completed", unpaid},
		// Refused with fixed text.
		{"unknown transaction", http.MethodPut, "/debuglet", dcSubmitBody(t, unknown, "", dcDebuglets()),
			http.StatusUnauthorized, CodeUnauthorized, "unknown transaction or wrong auth key", unknown},
		{"unknown payment status", http.MethodGet, "/payment/" + unknown + "/status", nil,
			http.StatusNotFound, CodeNotFound, "transaction not found", unknown},
		{"after parameter", http.MethodGet, "/debuglet/" + authSampleID + "/logs?after=" + query, nil,
			http.StatusBadRequest, CodeInvalidRequest, "invalid after parameter: must be a non-negative integer", query},
		{"limit parameter", http.MethodGet, "/debuglet/" + authSampleID + "/logs?limit=" + query, nil,
			http.StatusBadRequest, CodeInvalidRequest, "invalid limit parameter: must be a positive integer", query},
		{"list limit parameter", http.MethodGet, "/list-debuglets?limit=" + query, nil,
			http.StatusBadRequest, CodeInvalidRequest, "invalid limit parameter", query},
		{"list offset parameter", http.MethodGet, "/list-debuglets?offset=" + query, nil,
			http.StatusBadRequest, CodeInvalidRequest, "invalid offset parameter", query},
		{"run id with control characters", http.MethodGet, "/debuglet/" + url.PathEscape(run) + "/state", nil,
			http.StatusBadRequest, CodeInvalidRequest, "invalid debuglet id: want a lowercase canonical, non-nil UUID", runSentinel},
		{"cancelled run id with control characters", http.MethodDelete, "/debuglet", dcJSON(t, map[string]string{"debuglet_id": run, "executor_id": executor}),
			http.StatusBadRequest, CodeInvalidRequest, "invalid debuglet id: want a lowercase canonical, non-nil UUID", runSentinel},
		{"undecodable guest", http.MethodPut, "/debuglet", dcSubmitBody(t, wasmTx, "", invalidWasm),
			http.StatusBadRequest, CodeInvalidRequest, "invalid request (i=0): invalid wasm code", wasm},
		{"malformed body", http.MethodPut, "/debuglet", []byte(`{"auth_key": ` + query + `}`),
			http.StatusBadRequest, CodeInvalidRequest, "", query},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, _, body, _ := authRequest(t, f, tc.method, tc.target, tc.body, authBearer(token))
			dcExpect(t, tc.name, status, body, tc.status, tc.code, tc.message)
			if message := envelopeOf(t, tc.name, body).Message; strings.ContainsAny(message, "\n\x01\x7f") {
				t.Fatalf("%s: the message carries control characters: %q", tc.name, message)
			}
			if strings.Contains(string(body), tc.sentinel) {
				t.Fatalf("%s: the response repeats the whole value: %s", tc.name, body)
			}
		})
	}
}

// TestDatabaseFailuresReachOnlyTheLog makes the database fail with a sentinel
// on the write and read paths of the run, intent and submission routes. The
// client gets internal_error with fixed text and the log gets the cause. An
// enrolled executor is the operator's peer and receives the database text in
// its status; the run's owner reading the same run does not.
func TestDatabaseFailuresReachOnlyTheLog(t *testing.T) {
	f, logs := dcNewFixture(t)
	_, token, _ := authAccount(t, f, "database")
	trigger := func(t *testing.T, event, sentinel string) (drop func()) {
		t.Helper()
		if _, err := f.db.Exec(fmt.Sprintf("CREATE TRIGGER dc_failure %s BEGIN SELECT RAISE(ABORT, '%s'); END", event, sentinel)); err != nil {
			t.Fatalf("create trigger: %v", err)
		}
		dropped := false
		drop = func() {
			if !dropped {
				dropped = true
				if _, err := f.db.Exec("DROP TRIGGER dc_failure"); err != nil {
					t.Errorf("drop trigger: %v", err)
				}
			}
		}
		t.Cleanup(drop)
		return drop
	}

	t.Run("intent", func(t *testing.T) {
		sentinel := dcSentinel(t, "order-insert")
		drop := trigger(t, "BEFORE INSERT ON debuglet_order", sentinel)
		status, _, body, _ := authRequest(t, f, http.MethodPut, "/payment/intent",
			dcJSON(t, PaymentIntentRequest{Debuglets: dcDebuglets(), PaymentMethod: "TEST"}), authBearer(token))
		drop()
		dcExpect(t, "intent", status, body, http.StatusInternalServerError, CodeInternal, "failed to store the order")
		dcAssertLoggedCause(t, "intent", logs, body, "/payment/intent", sentinel)
	})

	t.Run("submission", func(t *testing.T) {
		txID := dcIntent(t, f, token, dcDebuglets())
		sentinel := dcSentinel(t, "run-insert")
		drop := trigger(t, "BEFORE INSERT ON debuglets", sentinel)
		status, _, body, _ := authRequest(t, f, http.MethodPut, "/debuglet", dcSubmitBody(t, txID, "", dcDebuglets()), authBearer(token))
		drop()
		dcExpect(t, "submission", status, body, http.StatusInternalServerError, CodeInternal, "failed to initialize debuglets")
		dcAssertLoggedCause(t, "submission", logs, body, "/debuglet", sentinel)
	})

	txID := dcIntent(t, f, token, dcDebuglets())
	status, _, body, _ := authRequest(t, f, http.MethodPut, "/debuglet", dcSubmitBody(t, txID, "", dcDebuglets()), authBearer(token))
	var ids []string
	if status != http.StatusOK || json.Unmarshal(body, &ids) != nil || len(ids) != 1 {
		t.Fatalf("submission: status %d, body %s", status, body)
	}
	id := uuid.MustParse(ids[0])

	t.Run("executor peer", func(t *testing.T) {
		sentinel := dcSentinel(t, "state-write")
		drop := trigger(t, "BEFORE UPDATE OF state ON debuglets", sentinel)
		ctx, cancel := f.requestCtx()
		defer cancel()
		_, stateErr := f.peer.direct.DebugletState(ctx, &pb.DebugletStateRequest{DebugletId: ids[0], ExecutorId: ccExecutorID, State: pb.RunState_RUN_STATE_STARTED})
		_, exitErr := f.peer.direct.DebugletExit(ctx, &pb.DebugletExitRequest{DebugletId: ids[0], ExitCode: 3})
		drop()
		for name, err := range map[string]error{"state": stateErr, "exit": exitErr} {
			message := grpcstatus.Convert(err).Message()
			if err == nil || strings.Contains(message, sentinel) || message != "operation failed; operator diagnostics have the details" {
				t.Fatalf("%s report lost failure classification or exposed private detail: %v", name, err)
			}
			// Private SQL causes name no public payment order or credential.
			if strings.Contains(message, txID) || strings.Contains(message, token) {
				t.Fatalf("%s report carries more than the database diagnostic: %s", name, message)
			}
		}
		status, _, body, _ := authRequest(t, f, http.MethodGet, "/debuglet/"+ids[0]+"/state", nil, authBearer(token))
		var state DebugletStateResponse
		if status != http.StatusOK || json.Unmarshal(body, &state) != nil || state.State == models.RunStateExited.String() || state.Error != "" {
			t.Fatalf("owner read after the refused reports: status %d, body %s", status, body)
		}
		dcAssertPrivate(t, "owner read", logs, body, sentinel)
	})

	t.Run("reads", func(t *testing.T) {
		// A stored value the row cannot be read back with: the scan error
		// quotes it.
		sentinel := dcSentinel(t, "stored-time")
		var original any
		if err := f.db.QueryRow("SELECT start_time FROM debuglets WHERE uuid = ?", id).Scan(&original); err != nil {
			t.Fatalf("read start_time: %v", err)
		}
		if _, err := f.db.Exec("UPDATE debuglets SET start_time = ? WHERE uuid = ?", sentinel, id); err != nil {
			t.Fatalf("corrupt start_time: %v", err)
		}
		t.Cleanup(func() {
			if _, err := f.db.Exec("UPDATE debuglets SET start_time = ? WHERE uuid = ?", original, id); err != nil {
				t.Errorf("restore start_time: %v", err)
			}
		})
		for _, tc := range []struct{ target, route, message string }{
			{"/debuglet/" + ids[0] + "/state", "/debuglet/:id/state", "failed to query debuglet"},
			{"/debuglet/" + ids[0] + "/logs", "/debuglet/:id/logs", "failed to query debuglet"},
			{"/list-debuglets", "/list-debuglets", "failed to retrieve debuglets for user"},
		} {
			status, _, body, _ := authRequest(t, f, http.MethodGet, tc.target, nil, authBearer(token))
			dcExpect(t, tc.target, status, body, http.StatusInternalServerError, CodeInternal, tc.message)
			dcAssertLoggedCause(t, tc.target, logs, body, tc.route, sentinel)
		}
	})
}

// TestSubmissionRefusalsKeepTheirCodes submits batches the dispatcher refuses
// at admission for what the executor is rather than for anything inside the
// dispatcher. Both used to answer 500 internal_error.
func TestSubmissionRefusalsKeepTheirCodes(t *testing.T) {
	t.Run("executor left after the intent", func(t *testing.T) {
		f, logs := dcNewFixture(t)
		_, token, _ := authAccount(t, f, "unavailable")
		txID := dcIntent(t, f, token, dcDebuglets())
		f.d.OnExecutorDisconnected(f.peer.owner)
		if _, ok := f.d.GetExecutor(ccExecutorID); ok {
			t.Fatal("the executor is still registered")
		}
		status, _, body, _ := authRequest(t, f, http.MethodPut, "/debuglet", dcSubmitBody(t, txID, "", dcDebuglets()), authBearer(token))
		dcExpect(t, "unavailable executor", status, body, http.StatusBadRequest, CodeUnknownExecutor, "the executor is not registered or not available")
		dcAssertLoggedCause(t, "unavailable executor", logs, body, "/debuglet", "executor '"+ccExecutorID+"' not found")
	})

	t.Run("policy requires ICMP", func(t *testing.T) {
		f, _ := dcNewFixture(t)
		_, token, _ := authAccount(t, f, "icmp")
		debuglets := dcDebuglets()
		debuglets[0].Policy.RequireICMP = true
		txID := dcIntent(t, f, token, debuglets)
		status, _, body, _ := authRequest(t, f, http.MethodPut, "/debuglet", dcSubmitBody(t, txID, "", debuglets), authBearer(token))
		dcExpect(t, "ICMP policy", status, body, http.StatusBadRequest, CodeInvalidPolicy, "")
		if !strings.Contains(string(body), "does not support ICMP") {
			t.Fatalf("the message does not say what the executor lacks: %s", body)
		}
	})
}

func TestCapabilityRefusalsOmitRegisteredExecutorID(t *testing.T) {
	for _, executorID := range []string{strings.Repeat("e", 96), "executor\n\t\x1b\x7f"} {
		t.Run(fmt.Sprintf("%q", executorID), func(t *testing.T) {
			peer := &cpPeer{id: executorID, price: ccPricePerBwS, currency: "TEST"}
			f := ccNewFixturePeer(t, zap.NewNop(), peer)
			_, token, _ := authAccount(t, f, "capabilities")
			if registered, ok := f.d.GetExecutor(executorID); !ok || registered.ID != executorID {
				t.Fatal("the executor was not registered with its original ID")
			}
			for _, capability := range []struct {
				name    string
				policy  DebugletPolicyRequest
				message string
			}{
				{"ICMP", DebugletPolicyRequest{RequireICMP: true}, "executor does not support ICMP, but policy requires it"},
				{"TCP listener", DebugletPolicyRequest{ListenTCP: true}, "executor has no public host, but policy requires a listener"},
				{"UDP listener", DebugletPolicyRequest{ListenUDP: true}, "executor has no public host, but policy requires a listener"},
			} {
				t.Run(capability.name, func(t *testing.T) {
					debuglets := dcDebuglets()
					debuglets[0].ExecutorID = executorID
					debuglets[0].Policy.RequireICMP = capability.policy.RequireICMP
					debuglets[0].Policy.ListenTCP = capability.policy.ListenTCP
					debuglets[0].Policy.ListenUDP = capability.policy.ListenUDP
					txID := dcIntent(t, f, token, debuglets)
					status, _, body, _ := authRequest(t, f, http.MethodPut, "/debuglet", dcSubmitBody(t, txID, "", debuglets), authBearer(token))
					dcExpect(t, capability.name, status, body, http.StatusBadRequest, CodeInvalidPolicy,
						"invalid policy (order 0): "+capability.message)
					var response ErrorResponse
					if err := json.Unmarshal(body, &response); err != nil {
						t.Fatal(err)
					}
					wantField := "policy.require_icmp"
					if capability.policy.ListenTCP {
						wantField = "policy.listen_tcp"
					}
					if capability.policy.ListenUDP {
						wantField = "policy.listen_udp"
					}
					if len(response.FieldErrors) != 1 || response.FieldErrors[0].Field != wantField || response.FieldErrors[0].Code != "unsupported" {
						t.Fatalf("missing capability field: %s", body)
					}
					if peer.uploadCount() != 0 {
						t.Fatal("a refused policy reached the executor")
					}
				})
			}
		})
	}
}

func TestHistoricalTerminalTextIsPrivateAcrossReadSurfaces(t *testing.T) {
	f, logs := dcNewFixture(t, LocalDevelopment(true))
	c := f.client(f.root.URL, false)
	sub := f.submit(c, nil)
	id := uuid.MustParse(sub.IDs[0])
	secret := dcSentinel(t, "terminal")
	if _, err := f.db.Exec("UPDATE debuglets SET state=?,error=? WHERE uuid=?", models.RunStateExited, "private stack "+secret, id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO debuglet_cancellations(debuglet_id,request_id,reason,requested_at) SELECT id,?,'cancelled via API',1 FROM debuglets WHERE uuid=?`, uuid.NewString(), id); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"state", "logs", "result", "recovery", "cancellation"} {
		status, _, body, _ := authRequest(t, f, http.MethodGet, "/debuglet/"+id.String()+"/"+suffix, nil, nil)
		if status != http.StatusOK {
			t.Fatalf("%s: %d %s", suffix, status, body)
		}
		dcAssertPrivate(t, suffix, logs, body, secret)
		if !strings.Contains(string(body), "debuglet failed; operator diagnostics have the details") {
			t.Fatalf("%s erased failure: %s", suffix, body)
		}
	}
}

func TestPrivateHTTPDiagnosticsRedactPresentedCredentials(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	request := httptest.NewRequest(http.MethodGet, "/fixture", nil)
	request.Header.Set("Authorization", "Bearer bearer-sentinel")
	request.AddCookie(&http.Cookie{Name: "session_token", Value: "cookie-sentinel"})
	response := httptest.NewRecorder()
	c := echo.New().NewContext(request, response)
	c.SetPath("/fixture")
	h := NewHandler(nil, nil, zap.New(core))
	h.errorHandler(apiErrorFrom(http.StatusInternalServerError, CodeInternal, "operation failed", errors.New("private SQL diagnostic bearer-sentinel cookie-sentinel\nsecond line")), c)
	for _, entry := range logs.All() {
		rendered := dcRender(entry)
		if strings.Contains(rendered, "bearer-sentinel") || strings.Contains(rendered, "cookie-sentinel") {
			t.Fatal("private diagnostic retained a credential")
		}
		if entry.Level >= zapcore.InfoLevel && strings.Contains(rendered, "private SQL diagnostic") {
			t.Fatal("routine diagnostic exposed internal cause")
		}
	}
	private := logs.FilterMessage("Private request diagnostic").All()
	if len(private) != 1 || !strings.Contains(dcRender(private[0]), "private SQL diagnostic") || strings.Contains(fmt.Sprint(private[0].ContextMap()["error"]), "\n") {
		t.Fatal("operator diagnostic lost or unbounded")
	}

	// A sign-in callback carries its authorization code and state in the query,
	// and a state-changing browser request its CSRF token in a header.
	core, logs = observer.New(zapcore.DebugLevel)
	request = httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=code-sentinel&state=state-sentinel", nil)
	request.Header.Set(csrfHeaderName, "csrf-sentinel")
	c = echo.New().NewContext(request, httptest.NewRecorder())
	c.SetPath("/auth/github/callback")
	h = NewHandler(nil, nil, zap.New(core))
	h.errorHandler(apiErrorFrom(http.StatusInternalServerError, CodeInternal, "operation failed", errors.New("exchange code-sentinel for state-sentinel with csrf-sentinel failed")), c)
	private = logs.FilterMessage("Private request diagnostic").All()
	if len(private) != 1 {
		t.Fatal("callback diagnostic lost")
	}
	rendered := dcRender(private[0])
	for _, secret := range []string{"code-sentinel", "state-sentinel", "csrf-sentinel"} {
		if strings.Contains(rendered, secret) {
			t.Errorf("private diagnostic retained %s", secret)
		}
	}
	if !strings.Contains(rendered, "exchange [redacted] for [redacted] with [redacted] failed") {
		t.Error("private diagnostic lost the redacted cause")
	}
}
