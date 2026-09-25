package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/pkg/client"

	"github.com/google/uuid"
)

// These tests drive the dispatcher's HTTP API in its enforced profile: the one
// a deployment gets unless it explicitly asked for local development. They
// cover what the identity cookie could not. Before this, the session_token
// cookie was read as a user UUID, a request without one continued anonymously,
// /user-ids published the UUIDs that were accepted as cookies, and the state,
// output and cancellation routes looked up whatever identifier they were
// handed. Every test below fails against that behaviour.

// authSampleID is a syntactically valid run identifier that names no run.
const authSampleID = "5f8f1f2c-2a18-4c1a-9a33-1c0f1c2b3d4e"

// authAccount registers an account on the fixture's dispatcher and logs in.
// It returns the account, its session token and a client presenting it.
func authAccount(t *testing.T, f *ccFixture, name string) (client.Account, string, *client.Client) {
	t.Helper()
	anonymous := f.client(f.root.URL, false)
	ctx, cancel := f.requestCtx()
	defer cancel()
	account, err := anonymous.CreateAccount(ctx, name)
	if err != nil {
		t.Fatalf("CreateAccount(%s): %v", name, err)
	}
	if account.AccountKey == "" || account.RecoveryCode == "" || account.AccountKey == account.RecoveryCode {
		t.Fatalf("CreateAccount(%s) issued no distinct credentials", name)
	}
	token := authLogin(t, f, account.AccountKey)
	if token == account.AccountKey || token == account.ID {
		t.Fatal("the issued session token is the account key or the account identifier")
	}
	authenticated, err := anonymous.WithCredential(token)
	if err != nil {
		t.Fatalf("WithCredential: %v", err)
	}
	return account, token, authenticated
}

// authLogin exchanges an account key for a session token.
func authLogin(t *testing.T, f *ccFixture, accountKey string) string {
	t.Helper()
	ctx, cancel := f.requestCtx()
	defer cancel()
	session, err := f.client(f.root.URL, false).Login(ctx, accountKey)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if session.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("the issued session expires at %d, which is not in the future", session.ExpiresAt)
	}
	return session.Token
}

// authRequest performs one raw request with the given headers and returns the
// response, so a route can be driven with any credential shape, including the
// ones no SDK would produce.
func authRequest(t *testing.T, f *ccFixture, method, target string, body []byte, headers map[string]string) (int, string, []byte, *http.Response) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(f.ctx, method, f.root.URL+target, reader)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := f.root.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	var envelope ErrorResponse
	_ = json.Unmarshal(data, &envelope)
	return resp.StatusCode, envelope.Code, data, resp
}

// authStatus is authRequest reduced to the decision it made.
func authStatus(t *testing.T, f *ccFixture, method, target string, body []byte, headers map[string]string) (int, string) {
	t.Helper()
	status, code, _, _ := authRequest(t, f, method, target, body, headers)
	return status, code
}

// authAs is authStatus with a bearer token, or anonymously when it is empty.
func authAs(t *testing.T, f *ccFixture, token, method, target string, body []byte) (int, string) {
	t.Helper()
	return authStatus(t, f, method, target, body, authBearer(token))
}

// authBearer is the header a native client presents. An empty token presents
// nothing at all.
func authBearer(token string) map[string]string {
	if token == "" {
		return nil
	}
	return map[string]string{"Authorization": "Bearer " + token}
}

// authIsUnauthorized reports the documented authentication failure.
func authIsUnauthorized(err error) bool {
	var httpErr *client.HTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusUnauthorized && httpErr.Code == CodeUnauthorized
}

// authIsNotFound reports the answer an object of another account earns.
func authIsNotFound(err error) bool {
	var httpErr *client.HTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound && httpErr.Code == CodeNotFound
}

// TestPresentedCredentialsAreVerified covers the credential states an
// authenticated API has to tell apart from a valid one. Every one of them used
// to be served: a request with no cookie continued anonymously, and a cookie
// holding any known user UUID was accepted as that user.
func TestPresentedCredentialsAreVerified(t *testing.T) {
	f := ccNewFixtureWith(t)
	account, _, authenticated := authAccount(t, f, "verified")
	ctx, cancel := f.requestCtx()
	defer cancel()

	// A working credential is the baseline every rejection is compared with.
	me, err := authenticated.Whoami(ctx)
	if err != nil {
		t.Fatalf("Whoami with a valid session: %v", err)
	}
	if me.ID != account.ID || me.Role != RoleUser {
		t.Fatalf("Whoami = %+v, want account %s with the ordinary role", me, account.ID)
	}

	forged, _, _, err := newCredential(sessionPrefix)
	if err != nil {
		t.Fatalf("mint a forged credential: %v", err)
	}
	for _, presented := range []struct {
		name    string
		headers map[string]string
	}{
		{name: "no credential", headers: nil},
		{name: "forged session token", headers: authBearer(forged)},
		{name: "the account key presented as a session", headers: authBearer(account.AccountKey)},
		{name: "the recovery code presented as a session", headers: authBearer(account.RecoveryCode)},
		{name: "a value that is not a credential", headers: authBearer("not-a-credential")},
		// The public identifier used to be the whole credential.
		{name: "the account UUID as a bearer token", headers: authBearer(account.ID)},
		{name: "the account UUID as a session cookie", headers: map[string]string{"Cookie": sessionCookieName + "=" + account.ID}},
		{name: "a forged session cookie", headers: map[string]string{"Cookie": sessionCookieName + "=" + forged}},
	} {
		t.Run(presented.name, func(t *testing.T) {
			status, code := authStatus(t, f, http.MethodGet, "/me", nil, presented.headers)
			if status != http.StatusUnauthorized || code != CodeUnauthorized {
				t.Fatalf("status = %d (%s), want 401 unauthorized", status, code)
			}
		})
	}
}

// TestSessionsExpireAndCanBeRevoked covers the lifecycle the cookie identity
// had none of: a session stops working at its expiry, and logout ends it
// before that.
func TestSessionsExpireAndCanBeRevoked(t *testing.T) {
	t.Run("revoked by logout", func(t *testing.T) {
		f := ccNewFixtureWith(t)
		_, _, authenticated := authAccount(t, f, "revoked")
		ctx, cancel := f.requestCtx()
		defer cancel()
		if _, err := authenticated.Whoami(ctx); err != nil {
			t.Fatalf("Whoami before logout: %v", err)
		}
		if err := authenticated.Logout(ctx); err != nil {
			t.Fatalf("Logout: %v", err)
		}
		if _, err := authenticated.Whoami(ctx); !authIsUnauthorized(err) {
			t.Fatalf("Whoami after logout: %v, want an unauthorized failure", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		f := ccNewFixtureWith(t)
		_, _, authenticated := authAccount(t, f, "expired")
		ctx, cancel := f.requestCtx()
		defer cancel()
		if _, err := authenticated.Whoami(ctx); err != nil {
			t.Fatalf("Whoami before expiry: %v", err)
		}
		// Move every issued session past its expiry. Nothing else changes, so
		// the expiry decision is the only thing under test.
		if _, err := f.db.ExecContext(f.ctx, "UPDATE sessions SET expires_at = ?", time.Now().UTC().Add(-time.Minute)); err != nil {
			t.Fatalf("expire the sessions: %v", err)
		}
		if _, err := authenticated.Whoami(ctx); !authIsUnauthorized(err) {
			t.Fatalf("Whoami after expiry: %v, want an unauthorized failure", err)
		}
	})
}

// TestCredentialsAreStoredHashed proves that a copy of the database yields no
// usable credential: neither the account credentials nor the session tokens
// are stored as they were issued.
func TestCredentialsAreStoredHashed(t *testing.T) {
	f := ccNewFixtureWith(t)
	account, token, _ := authAccount(t, f, "hashed")

	for _, query := range []string{
		"SELECT selector, secret_hash FROM user_credentials",
		"SELECT selector, verifier_hash, csrf_hash FROM sessions",
	} {
		stored := authStoredText(t, f, query)
		for _, issued := range []string{account.AccountKey, account.RecoveryCode, token} {
			prefix, _, _ := strings.Cut(issued, "_")
			_, verifier, ok := parseCredential(prefix, issued)
			if !ok {
				t.Fatalf("an issued credential is not in the documented shape")
			}
			// The verifier half is the secret. The selector half is a public
			// lookup handle and is expected to appear.
			if strings.Contains(stored, verifier) {
				t.Fatalf("%s stores a usable credential", query)
			}
		}
	}
}

// authStoredText concatenates every column of every row a query returns.
func authStoredText(t *testing.T, f *ccFixture, query string) string {
	t.Helper()
	rows, err := f.db.QueryContext(f.ctx, query)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	var stored strings.Builder
	seen := 0
	for rows.Next() {
		values := make([]any, len(columns))
		for i := range values {
			values[i] = new([]byte)
		}
		if err := rows.Scan(values...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		for _, value := range values {
			stored.Write(*value.(*[]byte))
			stored.WriteByte('\n')
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	if seen == 0 {
		t.Fatalf("%s returned no rows", query)
	}
	return stored.String()
}

// TestAccountRecoveryDoesNotTakeOverAnotherAccount covers the recovery path:
// it restores access to the account the code belongs to, invalidates what that
// account had, and can reach nobody else's.
func TestAccountRecoveryDoesNotTakeOverAnotherAccount(t *testing.T) {
	f := ccNewFixtureWith(t)
	owner, _, ownerClient := authAccount(t, f, "recovering owner")
	other, _, otherClient := authAccount(t, f, "other account")
	anonymous := f.client(f.root.URL, false)
	ctx, cancel := f.requestCtx()
	defer cancel()

	ownRun := f.submit(ownerClient, []string{"recovery"}).IDs[0]
	otherRun := f.submit(otherClient, []string{"other"}).IDs[0]

	recovered, err := anonymous.Recover(ctx, owner.RecoveryCode)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if recovered.ID != owner.ID {
		t.Fatalf("recovery returned account %s, want the account the code belongs to (%s)", recovered.ID, owner.ID)
	}
	if recovered.ID == other.ID {
		t.Fatal("recovery named another account")
	}
	if recovered.AccountKey == owner.AccountKey || recovered.RecoveryCode == owner.RecoveryCode {
		t.Fatal("recovery returned the credentials it was supposed to replace")
	}

	// What the account had before recovery is gone: the old key, the old
	// recovery code and every session it minted.
	if _, err := anonymous.Login(ctx, owner.AccountKey); !authIsUnauthorized(err) {
		t.Fatalf("login with the replaced account key: %v, want an unauthorized failure", err)
	}
	if _, err := anonymous.Recover(ctx, owner.RecoveryCode); !authIsUnauthorized(err) {
		t.Fatalf("the consumed recovery code still works: %v", err)
	}
	if _, err := ownerClient.Whoami(ctx); !authIsUnauthorized(err) {
		t.Fatalf("a session issued before recovery still works: %v", err)
	}

	// The recovered credentials reach the same account's runs and nothing
	// else. Recovery restores an account; it never hands over another one.
	restored, err := anonymous.WithCredential(authLogin(t, f, recovered.AccountKey))
	if err != nil {
		t.Fatalf("WithCredential: %v", err)
	}
	if _, err := restored.Status(ctx, ownRun); err != nil {
		t.Fatalf("the recovered account cannot read its own run: %v", err)
	}
	if _, err := restored.Status(ctx, otherRun); !authIsNotFound(err) {
		t.Fatalf("the recovered account reached another account's run: %v", err)
	}
}

// TestRunsAndOrdersAreReachableOnlyByTheirOwner covers the routes that used to
// look up whatever identifier they were handed: state, output, cancellation,
// the run list, the payment status and the by-IP candidate list.
func TestRunsAndOrdersAreReachableOnlyByTheirOwner(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, ownerToken, ownerClient := authAccount(t, f, "run owner")
	_, strangerToken, strangerClient := authAccount(t, f, "stranger")
	ctx, cancel := f.requestCtx()
	defer cancel()

	submission := f.submit(ownerClient, []string{"owned"})
	id := submission.IDs[0]
	f.seedLogs(id, [][]byte{[]byte("private output")})

	t.Run("the owner reaches its own run", func(t *testing.T) {
		if _, err := ownerClient.Status(ctx, id); err != nil {
			t.Fatalf("Status: %v", err)
		}
		page, err := ownerClient.Logs(ctx, id, client.LogOptions{Limit: 10})
		if err != nil {
			t.Fatalf("Logs: %v", err)
		}
		if len(page.Logs) != 1 || string(page.Logs[0].Output) != "private output" {
			t.Fatalf("the owner did not read its own output: %+v", page.Logs)
		}
	})

	t.Run("another account reaches nothing", func(t *testing.T) {
		if _, err := strangerClient.Status(ctx, id); !authIsNotFound(err) {
			t.Fatalf("Status: %v, want 404 not_found", err)
		}
		if _, err := strangerClient.Logs(ctx, id, client.LogOptions{Limit: 10}); !authIsNotFound(err) {
			t.Fatalf("Logs: %v, want 404 not_found", err)
		}
		if err := strangerClient.Cancel(ctx, id, ccExecutorID); !authIsNotFound(err) {
			t.Fatalf("Cancel: %v, want 404 not_found", err)
		}
		// The refusal is the one an identifier that names nothing gets, so the
		// response tells the stranger nothing about the run.
		if _, err := strangerClient.Status(ctx, uuid.NewString()); !authIsNotFound(err) {
			t.Fatalf("Status of an unknown run: %v, want 404 not_found", err)
		}
		// The refused cancellation did not touch the run either.
		if _, err := ownerClient.Status(ctx, id); err != nil {
			t.Fatalf("the owner's run is gone after a refused cancellation: %v", err)
		}
	})

	t.Run("an anonymous request reaches nothing", func(t *testing.T) {
		for _, target := range []string{"/debuglet/" + id + "/state", "/debuglet/" + id + "/logs", "/list-debuglets"} {
			status, code := authStatus(t, f, http.MethodGet, target, nil, nil)
			if status != http.StatusUnauthorized || code != CodeUnauthorized {
				t.Fatalf("%s: status = %d (%s), want 401 unauthorized", target, status, code)
			}
		}
	})

	t.Run("the run list is scoped to the account", func(t *testing.T) {
		owned := authListDebuglets(t, f, ownerToken, "")
		if len(owned) != 1 || owned[0] != id {
			t.Fatalf("the owner's list = %v, want exactly its own run", owned)
		}
		// Paging does not widen the scope, which is where a list is easiest to
		// get wrong.
		for _, query := range []string{"", "?limit=100&offset=0", "?limit=1", "?offset=0"} {
			if others := authListDebuglets(t, f, strangerToken, query); len(others) != 0 {
				t.Fatalf("another account's list%s = %v, want nothing", query, others)
			}
		}
	})

	t.Run("the payment order is private", func(t *testing.T) {
		target := "/payment/" + submission.TransactionID + "/status"
		if status, code := authAs(t, f, strangerToken, http.MethodGet, target, nil); status != http.StatusNotFound || code != CodeNotFound {
			t.Fatalf("another account read the payment status: %d (%s)", status, code)
		}
		if status, code := authAs(t, f, ownerToken, http.MethodGet, target, nil); status != http.StatusOK {
			t.Fatalf("the owner could not read its own payment status: %d (%s)", status, code)
		}
		if status, _ := authStatus(t, f, http.MethodGet, target, nil, nil); status != http.StatusUnauthorized {
			t.Fatalf("an anonymous payment status read answered %d, want 401", status)
		}
	})

	t.Run("by-IP enumeration lists only the caller's runs", func(t *testing.T) {
		owned := authByIP(t, f, ownerToken)
		if len(owned) != 1 || owned[0] != id {
			t.Fatalf("the owner's by-IP list = %v, want exactly its own run", owned)
		}
		if others := authByIP(t, f, strangerToken); len(others) != 0 {
			t.Fatalf("another account's by-IP list = %v, want nothing", others)
		}
		// Nothing is an empty array, not a null: the contract documents a list
		// and a client must not have to special-case owning none of them.
		_, _, body, _ := authRequest(t, f, http.MethodGet, "/executors/by-ip?ip=127.0.0.1", nil, authBearer(strangerToken))
		if !strings.Contains(string(body), `"debuglet_ids":[]`) {
			t.Fatalf("an empty by-IP result is not an empty array: %s", body)
		}
		if status, _ := authStatus(t, f, http.MethodGet, "/executors/by-ip?ip=127.0.0.1", nil, nil); status != http.StatusUnauthorized {
			t.Fatalf("an anonymous by-IP lookup answered %d, want 401", status)
		}
	})
}

// authListDebuglets reads one account's own runs.
func authListDebuglets(t *testing.T, f *ccFixture, token, query string) []string {
	t.Helper()
	status, code, data, _ := authRequest(t, f, http.MethodGet, "/list-debuglets"+query, nil, authBearer(token))
	if status != http.StatusOK {
		t.Fatalf("list-debuglets%s: status %d (%s)", query, status, code)
	}
	var rows []DebugletResponse
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatalf("decode the run list %s: %v", data, err)
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID.String())
	}
	return ids
}

// authByIP reads the by-IP response as one account.
func authByIP(t *testing.T, f *ccFixture, token string) []string {
	t.Helper()
	status, code, data, _ := authRequest(t, f, http.MethodGet, "/executors/by-ip?ip=127.0.0.1", nil, authBearer(token))
	if status != http.StatusOK {
		t.Fatalf("executors/by-ip: status %d (%s)", status, code)
	}
	var response ExecutorByIPResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatalf("decode the by-IP response %s: %v", data, err)
	}
	ids := make([]string, 0, len(response.DebugletIDs))
	for _, id := range response.DebugletIDs {
		ids = append(ids, id.String())
	}
	return ids
}

// TestCrossAccountTransactionReuseIsRefused covers a submission that presents
// another account's payment order. The auth key authorizes one batch; it does
// not say who may spend the order, and for TEST it is empty anyway.
func TestCrossAccountTransactionReuseIsRefused(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, ownerToken, _ := authAccount(t, f, "order owner")
	_, strangerToken, _ := authAccount(t, f, "order thief")

	debuglets, err := json.Marshal([]client.Request{ccRequest([]string{"reuse"})})
	if err != nil {
		t.Fatalf("marshal the batch: %v", err)
	}
	intentBody := []byte(`{"debuglets":` + string(debuglets) + `,"payment_method":"TEST","refund_address":""}`)
	status, code, data, _ := authRequest(t, f, http.MethodPut, "/payment/intent", intentBody, authBearer(ownerToken))
	if status != http.StatusOK {
		t.Fatalf("the owner could not create an intent: %d (%s): %s", status, code, data)
	}
	var intent struct {
		Intent struct {
			TransactionID string `json:"transaction_id"`
			AuthKey       string `json:"auth_key"`
		} `json:"intent"`
	}
	if err := json.Unmarshal(data, &intent); err != nil {
		t.Fatalf("decode the intent %s: %v", data, err)
	}
	key, err := json.Marshal(intent.Intent.AuthKey)
	if err != nil {
		t.Fatalf("marshal the auth key: %v", err)
	}
	submit := []byte(`{"debuglets":` + string(debuglets) +
		`,"transaction_id":"` + intent.Intent.TransactionID + `","auth_key":` + string(key) + `}`)

	// The order's identifier and its auth key are the whole capability the
	// server used to check. They are not enough any more.
	if status, code := authAs(t, f, strangerToken, http.MethodPut, "/debuglet", submit); status != http.StatusUnauthorized || code != CodeUnauthorized {
		t.Fatalf("another account spent the order: %d (%s), want 401 unauthorized", status, code)
	}
	if status, code := authAs(t, f, "", http.MethodPut, "/debuglet", submit); status != http.StatusUnauthorized || code != CodeUnauthorized {
		t.Fatalf("an anonymous submission was admitted: %d (%s), want 401 unauthorized", status, code)
	}
	// The owner's own submission still works, so the refusals above are about
	// who asked and not about the batch.
	if status, code, body, _ := authRequest(t, f, http.MethodPut, "/debuglet", submit, authBearer(ownerToken)); status != http.StatusOK {
		t.Fatalf("the owner could not spend its own order: %d (%s): %s", status, code, body)
	}
}

// TestOperatorOperationsAreSeparatedFromSubmitterOperations covers the routes
// that act on the dispatcher rather than on one account's objects. They were
// reachable by anyone who could reach the port.
func TestOperatorOperationsAreSeparatedFromSubmitterOperations(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, submitter, _ := authAccount(t, f, "ordinary submitter")

	for _, operation := range []struct {
		name   string
		method string
		target string
		body   []byte
	}{
		{name: "destination limit", method: http.MethodPatch, target: "/destination", body: []byte(`{"destination":"127.0.0.1","limit":1000000}`)},
		{name: "account enumeration", method: http.MethodGet, target: "/user-ids"},
	} {
		t.Run(operation.name, func(t *testing.T) {
			status, code := authStatus(t, f, operation.method, operation.target, operation.body, nil)
			if status != http.StatusUnauthorized || code != CodeUnauthorized {
				t.Fatalf("anonymous: status = %d (%s), want 401 unauthorized", status, code)
			}
			// The route's existence is public, so an account that may not use
			// it is told so rather than being shown a missing route.
			status, code = authAs(t, f, submitter, operation.method, operation.target, operation.body)
			if status != http.StatusForbidden || code != CodeForbidden {
				t.Fatalf("ordinary account: status = %d (%s), want 403 forbidden", status, code)
			}
		})
	}
}

// TestOperatorReachesAdministrationButNotPrivateRuns pins what the operator
// role is and is not: it admits the dispatcher-wide operations and nothing
// else. Another account's run stays private from it, and answers the same 404
// as a run that does not exist.
func TestOperatorReachesAdministrationButNotPrivateRuns(t *testing.T) {
	f := ccNewFixtureWith(t)
	owner, _, ownerClient := authAccount(t, f, "run owner")
	operator, _, operatorClient := authAccount(t, f, "operator")
	ctx, cancel := f.requestCtx()
	defer cancel()

	id := f.submit(ownerClient, []string{"owned"}).IDs[0]

	// The role is granted on the dispatcher host, never over HTTP.
	authGrantOperator(t, f, operator.ID)
	operatorToken := authLogin(t, f, operator.AccountKey)

	if status, code := authAs(t, f, operatorToken, http.MethodGet, "/user-ids", nil); status != http.StatusOK {
		t.Fatalf("the operator cannot enumerate accounts: %d (%s)", status, code)
	}
	if status, code := authAs(t, f, operatorToken, http.MethodPatch, "/destination",
		[]byte(`{"destination":"127.0.0.1","limit":1000000}`)); status != http.StatusNoContent {
		t.Fatalf("the operator cannot change a destination limit: %d (%s)", status, code)
	}
	for _, target := range []string{"/debuglet/" + id + "/state", "/debuglet/" + id + "/logs"} {
		if status, code := authAs(t, f, operatorToken, http.MethodGet, target, nil); status != http.StatusNotFound || code != CodeNotFound {
			t.Fatalf("%s as an operator: %d (%s), want the ordinary 404 not_found", target, status, code)
		}
	}
	// The account that owns the run still reaches it, so the refusal above is
	// about the operator and not about the run.
	if _, err := ownerClient.Status(ctx, id); err != nil {
		t.Fatalf("the owner lost access to its own run: %v", err)
	}
	if owner.ID == operator.ID {
		t.Fatal("the fixture reused one account for both roles")
	}
	// The demoted operator loses the administration operations immediately,
	// without waiting for its session to expire.
	authRevokeOperator(t, f, operator.ID)
	if status, code := authAs(t, f, operatorToken, http.MethodGet, "/user-ids", nil); status != http.StatusForbidden || code != CodeForbidden {
		t.Fatalf("a demoted operator still enumerates accounts: %d (%s)", status, code)
	}
	if _, err := operatorClient.Whoami(ctx); err != nil {
		t.Fatalf("demotion invalidated the session: %v", err)
	}
}

// authGrantOperator gives one account the operator role the way the dispatcher
// host does: directly in the database, never over HTTP.
func authGrantOperator(t *testing.T, f *ccFixture, account string) {
	t.Helper()
	authSetRole(t, f, account, RoleOperator)
}

func authRevokeOperator(t *testing.T, f *ccFixture, account string) {
	t.Helper()
	authSetRole(t, f, account, RoleUser)
}

func authSetRole(t *testing.T, f *ccFixture, account, role string) {
	t.Helper()
	id, err := uuid.Parse(account)
	if err != nil {
		t.Fatalf("parse account: %v", err)
	}
	changed, err := database.New(f.db).SetUserRole(f.ctx, database.SetUserRoleParams{Role: role, Uuid: id})
	if err != nil {
		t.Fatalf("set role: %v", err)
	}
	if changed != 1 {
		t.Fatalf("set role changed %d accounts, want 1", changed)
	}
}

// TestSessionCookieSecureComesFromConfigurationNotHeaders covers the attribute
// a request must never decide for itself. Echo derives its scheme from
// X-Forwarded-Proto and its relatives, which the caller sets.
func TestSessionCookieSecureComesFromConfigurationNotHeaders(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []Option
		secure  bool
	}{
		{name: "cleartext dispatcher", secure: false},
		{name: "dispatcher that knows it is behind TLS", options: []Option{CookieSecure(true)}, secure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := ccNewFixtureWith(t, tc.options...)
			account, _, _ := authAccount(t, f, "cookie")
			key, err := json.Marshal(account.AccountKey)
			if err != nil {
				t.Fatalf("marshal the account key: %v", err)
			}
			// The forwarding headers claim https in both cases.
			status, code, _, resp := authRequest(t, f, http.MethodPost, "/auth/login",
				[]byte(`{"account_key":`+string(key)+`}`),
				map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Ssl": "on", "X-Url-Scheme": "https"})
			if status != http.StatusOK {
				t.Fatalf("login: %d (%s)", status, code)
			}
			for _, cookie := range resp.Cookies() {
				if cookie.Secure != tc.secure {
					t.Fatalf("cookie %s has Secure=%t, want %t: the attribute followed the request instead of the deployment",
						cookie.Name, cookie.Secure, tc.secure)
				}
			}
		})
	}
}

// TestPublicDataStaysPublic keeps the deliberately public attribution data
// reachable: the executor list and the TESLA parameters an external verifier
// needs are not private run data.
func TestPublicDataStaysPublic(t *testing.T) {
	f := ccNewFixtureWith(t)
	for _, target := range []string{"/version", "/openapi.yaml", "/executors", "/executors/" + ccExecutorID + "/tesla"} {
		if status, code := authStatus(t, f, http.MethodGet, target, nil, nil); status != http.StatusOK {
			t.Fatalf("%s: status = %d (%s), want 200", target, status, code)
		}
	}
}

// TestEveryRegisteredRouteHasADecidedAccessPolicy compares the routes the
// dispatcher installs against the access matrix docs/API.md publishes, so a
// route added later cannot quietly reach the network without a decision.
// authRoutePolicy is one row of the access matrix docs/API.md publishes: the
// status an anonymous request earns in the enforced profile, and a request
// that actually reaches the route's handler.
type authRoutePolicy struct {
	anonymous int
	target    string
	body      []byte
	// public marks a route that requires no credential at all. A public route
	// may still answer 401: /auth/login and /auth/recover verify the
	// credential they are handed, they do not require one to be presented.
	public bool
}

// authAccessMatrix states the policy of every route RegisterRoutes installs.
// It is the one place the expected policy is written down, and both the
// runtime test below and the contract test compare against it.
var authAccessMatrix = map[string]authRoutePolicy{
	"GET /version":                        {anonymous: http.StatusOK, target: "/version", public: true},
	"GET /openapi.yaml":                   {anonymous: http.StatusOK, target: "/openapi.yaml", public: true},
	"POST /auth/login":                    {anonymous: http.StatusUnauthorized, target: "/auth/login", body: []byte(`{"account_key":""}`), public: true},
	"POST /auth/logout":                   {anonymous: http.StatusUnauthorized, target: "/auth/logout", body: []byte(`{}`)},
	"POST /auth/recover":                  {anonymous: http.StatusUnauthorized, target: "/auth/recover", body: []byte(`{"recovery_code":""}`), public: true},
	"PUT /debuglet":                       {anonymous: http.StatusUnauthorized, target: "/debuglet", body: []byte(`{"debuglets":[{"order_id":0,"executor_id":"` + ccExecutorID + `","wasm":"","policy":{"floor_bw":0,"ceil_bw":0,"timeout_ms":1000}}],"transaction_id":"none","auth_key":""}`)},
	"GET /debuglet/:id/logs":              {anonymous: http.StatusUnauthorized, target: "/debuglet/" + authSampleID + "/logs"},
	"GET /debuglet/:id/state":             {anonymous: http.StatusUnauthorized, target: "/debuglet/" + authSampleID + "/state"},
	"DELETE /debuglet":                    {anonymous: http.StatusUnauthorized, target: "/debuglet", body: []byte(`{"debuglet_id":"` + authSampleID + `","executor_id":"` + ccExecutorID + `"}`)},
	"GET /executors":                      {anonymous: http.StatusOK, target: "/executors", public: true},
	"GET /executors/by-ip":                {anonymous: http.StatusUnauthorized, target: "/executors/by-ip?ip=127.0.0.1"},
	"GET /executors/:id/tesla":            {anonymous: http.StatusOK, target: "/executors/" + ccExecutorID + "/tesla", public: true},
	"PATCH /destination":                  {anonymous: http.StatusUnauthorized, target: "/destination", body: []byte(`{"destination":"127.0.0.1","limit":1000000}`)},
	"PUT /payment/intent":                 {anonymous: http.StatusUnauthorized, target: "/payment/intent", body: []byte(`{"debuglets":[],"payment_method":"TEST","refund_address":""}`)},
	"GET /payment/:transaction_id/status": {anonymous: http.StatusUnauthorized, target: "/payment/none/status"},
	"GET /me":                             {anonymous: http.StatusUnauthorized, target: "/me"},
	"GET /user-ids":                       {anonymous: http.StatusUnauthorized, target: "/user-ids"},
	// Registering an account is the credential issuer: it has to be
	// reachable by a caller that has no credential yet.
	"PUT /user":           {anonymous: http.StatusOK, target: "/user", body: []byte(`{"name":"matrix"}`), public: true},
	"GET /list-debuglets": {anonymous: http.StatusUnauthorized, target: "/list-debuglets"},
	// The health routes answer an unauthenticated prober: they carry no run
	// data, and whoever runs a deployment has to reach them before it has
	// issued anybody a credential.
	"GET /healthz": {anonymous: http.StatusOK, target: "/healthz", public: true},
	"GET /readyz":  {anonymous: http.StatusOK, target: "/readyz", public: true},
	"GET /health":  {anonymous: http.StatusOK, target: "/health", public: true},
}

func TestEveryRegisteredRouteHasADecidedAccessPolicy(t *testing.T) {
	matrix := authAccessMatrix
	f := ccNewFixtureWith(t)
	registered := map[string]bool{}
	for _, route := range f.routes {
		registered[route] = true
		if _, decided := matrix[route]; !decided {
			t.Errorf("route %s is registered but this test states no access policy for it", route)
		}
	}
	for route := range matrix {
		if !registered[route] {
			t.Errorf("this test states a policy for %s, which no route serves", route)
		}
	}

	for route, want := range matrix {
		method, _, _ := strings.Cut(route, " ")
		status, code := authStatus(t, f, method, want.target, want.body, nil)
		if status != want.anonymous {
			t.Errorf("anonymous %s: status = %d (%s), want %d", route, status, code, want.anonymous)
		}
	}
}

// TestCookieSessionsCarryTheirFlagsAndNeedCSRFProof covers the browser client
// the cookie is retained for: the cookie is not script-readable, it does not
// travel cross-site, and a state change authenticated with it has to prove it
// was not made by another site.
func TestCookieSessionsCarryTheirFlagsAndNeedCSRFProof(t *testing.T) {
	f := ccNewFixtureWith(t)
	account, _, _ := authAccount(t, f, "browser")

	key, err := json.Marshal(account.AccountKey)
	if err != nil {
		t.Fatalf("marshal the account key: %v", err)
	}
	status, code, _, resp := authRequest(t, f, http.MethodPost, "/auth/login",
		[]byte(`{"account_key":`+string(key)+`}`), nil)
	if status != http.StatusOK {
		t.Fatalf("login: %d (%s)", status, code)
	}
	var session, csrf *http.Cookie
	for _, cookie := range resp.Cookies() {
		switch cookie.Name {
		case sessionCookieName:
			session = cookie
		case csrfCookieName:
			csrf = cookie
		}
	}
	if session == nil || csrf == nil {
		t.Fatalf("login set %v, want both the session and the CSRF cookie", resp.Cookies())
	}
	if !session.HttpOnly || session.SameSite != http.SameSiteStrictMode || session.Path != "/" {
		t.Fatalf("session cookie = %+v, want HttpOnly, SameSite=Strict and path /", session)
	}
	if session.Value == account.ID || session.Value == account.AccountKey {
		t.Fatal("the session cookie carries an identifier or the account key instead of a session token")
	}
	if csrf.HttpOnly {
		t.Fatal("the CSRF cookie is HttpOnly, so the page that has to repeat it cannot read it")
	}

	cookies := map[string]string{"Cookie": session.Name + "=" + session.Value + "; " + csrf.Name + "=" + csrf.Value}
	// A read is safe and needs no proof.
	if status, code := authStatus(t, f, http.MethodGet, "/me", nil, cookies); status != http.StatusOK {
		t.Fatalf("cookie-authenticated read: %d (%s), want 200", status, code)
	}
	// A state change made without the header is what another site could
	// provoke, so it is refused.
	body := []byte(`{"debuglet_id":"` + authSampleID + `","executor_id":"` + ccExecutorID + `"}`)
	if status, code := authStatus(t, f, http.MethodDelete, "/debuglet", body, cookies); status != http.StatusForbidden || code != CodeForbidden {
		t.Fatalf("cookie-authenticated cancellation without a CSRF token: %d (%s), want 403 forbidden", status, code)
	}
	// With the proof the request is authorized normally, and then answers the
	// ordinary refusal of a run this account does not own.
	proven := map[string]string{"Cookie": cookies["Cookie"], csrfHeaderName: csrf.Value}
	if status, code := authStatus(t, f, http.MethodDelete, "/debuglet", body, proven); status != http.StatusNotFound || code != CodeNotFound {
		t.Fatalf("cookie-authenticated cancellation with a CSRF token: %d (%s), want the ordinary 404 not_found", status, code)
	}
	// The CSRF token is not a credential on its own.
	if status, _ := authStatus(t, f, http.MethodGet, "/me", nil, map[string]string{csrfHeaderName: csrf.Value}); status != http.StatusUnauthorized {
		t.Fatalf("the CSRF token alone authenticated a request: %d", status)
	}
}

// TestLocalDevelopmentBypassStaysExplicit covers the documented development
// profile. It keeps the wallet-free local flow usable without a credential and
// without a browser, it hands out no account, and it still refuses a
// credential that does not verify.
func TestLocalDevelopmentBypassStaysExplicit(t *testing.T) {
	f := ccNewFixture(t)
	anonymous := f.client(f.root.URL, false)
	ctx, cancel := f.requestCtx()
	defer cancel()

	// The whole wallet-free flow, with no credential anywhere.
	submission := f.submit(anonymous, []string{"local"})
	id := submission.IDs[0]
	if _, err := anonymous.Status(ctx, id); err != nil {
		t.Fatalf("local Status: %v", err)
	}
	if _, err := anonymous.Logs(ctx, id, client.LogOptions{Limit: 5}); err != nil {
		t.Fatalf("local Logs: %v", err)
	}
	if status, code := authStatus(t, f, http.MethodGet, "/user-ids", nil, nil); status != http.StatusOK {
		t.Fatalf("local account enumeration: %d (%s), want 200 for the local operator", status, code)
	}

	// The bypass names no account, so the routes that report one still need a
	// credential even here.
	for _, target := range []string{"/me", "/list-debuglets"} {
		if status, code := authStatus(t, f, http.MethodGet, target, nil, nil); status != http.StatusUnauthorized {
			t.Fatalf("%s in local development: %d (%s), want 401", target, status, code)
		}
	}

	// A credential that does not verify is refused in local development too:
	// the bypass admits the absence of a credential, not a wrong one.
	forged, _, _, err := newCredential(sessionPrefix)
	if err != nil {
		t.Fatalf("mint a forged credential: %v", err)
	}
	if status, code := authAs(t, f, forged, http.MethodGet, "/debuglet/"+id+"/state", nil); status != http.StatusUnauthorized {
		t.Fatalf("a forged credential was served locally: %d (%s), want 401", status, code)
	}

	// And a request that does authenticate is scoped to its own account, even
	// in local development: the bypass is not a way to read somebody's runs.
	_, _, account := authAccount(t, f, "local account")
	if _, err := account.Status(ctx, id); !authIsNotFound(err) {
		t.Fatalf("an authenticated account read an ownerless local run: %v", err)
	}

	// The documented way to obtain a credential locally, with no browser and
	// no wallet: the local bootstrap login.
	session, err := anonymous.Login(ctx, "")
	if err != nil {
		t.Fatalf("local bootstrap login: %v", err)
	}
	local, err := anonymous.WithCredential(session.Token)
	if err != nil {
		t.Fatalf("WithCredential: %v", err)
	}
	me, err := local.Whoami(ctx)
	if err != nil {
		t.Fatalf("Whoami with the local credential: %v", err)
	}
	if me.Role != RoleOperator {
		t.Fatalf("the local development account has role %q, want %q", me.Role, RoleOperator)
	}
}

// TestLocalBootstrapLoginIsRefusedByEnforcedDeployments keeps the bypass from
// being reachable anywhere it was not explicitly asked for.
func TestLocalBootstrapLoginIsRefusedByEnforcedDeployments(t *testing.T) {
	f := ccNewFixtureWith(t)
	ctx, cancel := f.requestCtx()
	defer cancel()
	if _, err := f.client(f.root.URL, false).Login(ctx, ""); !authIsUnauthorized(err) {
		t.Fatalf("the local bootstrap login was served: %v, want an unauthorized failure", err)
	}
	// And no local development account exists to be logged into.
	if status, _ := authStatus(t, f, http.MethodGet, "/user-ids", nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("account enumeration answered %d, want 401", status)
	}
}
