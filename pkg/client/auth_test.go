package client

import (
	"net/http"
	"strings"
	"testing"
)

// The SDK's credential contract: the token is presented on every request to
// the one dispatcher the client was built for, and it never reaches a caller's
// eyes through an error, a diagnostic or a returned value it did not ask for.

const authTestToken = "dbs_c2VsZWN0b3ItMTZi.dmVyaWZpZXItMzJieXRlcy1vZi1zZWNyZXQtdmFsdWU"

// presented returns the Authorization header of every recorded request.
func presented(f *fakeServer) []string {
	requests := f.requests()
	headers := make([]string, len(requests))
	for i, request := range requests {
		headers[i] = request.Header.Get("Authorization")
	}
	return headers
}

func TestCredentialIsPresentedOnEveryRequest(t *testing.T) {
	f := newFakeServer(t, "")
	f.defaults()
	// One request per surface a caller reaches, with a body and without.
	routes := exerciseAll(t, f.client(t, Options{Credential: authTestToken}), "")
	seen := presented(f)
	if len(seen) != len(routes) {
		t.Fatalf("recorded %d requests, want one per call", len(seen))
	}
	for i, header := range seen {
		if header != "Bearer "+authTestToken {
			t.Fatalf("request %d presented %q, want the bearer credential", i, header)
		}
	}
}

// TestCredentialNeverReachesADiagnostic covers the paths a secret could escape
// through: the failure envelope of a rejecting server, a server that echoes
// the credential back, and a transport failure that quotes the request.
func TestCredentialNeverReachesADiagnostic(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "rejected", status: http.StatusUnauthorized, body: `{"code":"unauthorized","message":"authentication required"}`},
		{name: "echoed back by the server", status: http.StatusBadRequest, body: `{"code":"invalid_request","message":"bad token ` + authTestToken + `"}`},
		{name: "echoed in a bare string", status: http.StatusBadRequest, body: `"` + authTestToken + `"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t, "")
			f.handle("GET /executors", jsonHandler(tc.status, tc.body))
			_, err := f.client(t, Options{Credential: authTestToken}).Nodes(testContext(t))
			if err == nil {
				t.Fatal("a failing response was accepted")
			}
			if strings.Contains(err.Error(), authTestToken) {
				t.Fatalf("the credential reached the diagnostic: %v", err)
			}
		})
	}

	t.Run("transport failure", func(t *testing.T) {
		httpClient := &http.Client{Transport: fixtureRoundTripper(func(r *http.Request) (*http.Response, error) {
			return nil, &fixtureResponseError{message: "dial failed with " + r.Header.Get("Authorization")}
		})}
		c, err := New("http://127.0.0.1:9000", Options{HTTPClient: httpClient, Credential: authTestToken})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := c.Nodes(testContext(t)); err == nil {
			t.Fatal("a transport failure was accepted")
		} else if strings.Contains(err.Error(), authTestToken) {
			t.Fatalf("the credential reached the transport diagnostic: %v", err)
		}
	})
}

// TestWithCredentialKeepsTheEndpoint proves a derived client stays bound to the
// dispatcher it came from: a credential cannot be moved to another origin by
// reusing a client.
func TestWithCredentialKeepsTheEndpoint(t *testing.T) {
	f := newFakeServer(t, "/api")
	f.defaults()
	base := f.client(t, Options{})
	derived, err := base.WithCredential(authTestToken)
	if err != nil {
		t.Fatalf("WithCredential: %v", err)
	}
	if _, err := derived.Nodes(testContext(t)); err != nil {
		t.Fatalf("Nodes: %v", err)
	}
	if derived.origin != base.origin || derived.basePath != base.basePath {
		t.Fatalf("derived client points at %s%s, want %s%s", derived.origin, derived.basePath, base.origin, base.basePath)
	}
	// The original client keeps presenting nothing: deriving does not mutate
	// the client a caller already holds.
	if _, err := base.Nodes(testContext(t)); err != nil {
		t.Fatalf("Nodes on the base client: %v", err)
	}
	if seen := presented(f); len(seen) != 2 || seen[0] != "Bearer "+authTestToken || seen[1] != "" {
		t.Fatalf("presented headers %q, want the derived client authenticated and the original not", seen)
	}
}

func TestCredentialOptionIsValidated(t *testing.T) {
	if _, err := New("http://127.0.0.1:9000", Options{Credential: " " + authTestToken}); err == nil {
		t.Fatal("a padded credential was accepted")
	}
}

// TestAuthRoutesUseTheDocumentedShapes pins the requests the session routes
// send and the values they read back.
func TestAuthRoutesUseTheDocumentedShapes(t *testing.T) {
	f := newFakeServer(t, "")
	f.handle("PUT /user", jsonHandler(http.StatusOK, `{"id":"1a1a1a1a-2b2b-4c4c-8d8d-9e9e9e9e9e9e","name":"a","role":"user","account_key":"dba_k.v","recovery_code":"dbr_k.v"}`))
	f.handle("POST /auth/login", jsonHandler(http.StatusOK, `{"token":"`+authTestToken+`","csrf_token":"csrf","expires_at":4102444800,"id":"1a1a1a1a-2b2b-4c4c-8d8d-9e9e9e9e9e9e","name":"a","role":"user"}`))
	f.handle("GET /me", jsonHandler(http.StatusOK, `{"id":"1a1a1a1a-2b2b-4c4c-8d8d-9e9e9e9e9e9e","name":"a","role":"operator"}`))
	f.handle("POST /auth/recover", jsonHandler(http.StatusOK, `{"id":"1a1a1a1a-2b2b-4c4c-8d8d-9e9e9e9e9e9e","name":"a","role":"user","account_key":"dba_k2.v2","recovery_code":"dbr_k2.v2"}`))
	f.handle("POST /auth/logout", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	c := f.client(t, Options{Credential: authTestToken})
	ctx := testContext(t)

	account, err := c.CreateAccount(ctx, "a")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if account.AccountKey != "dba_k.v" || account.RecoveryCode != "dbr_k.v" {
		t.Fatalf("CreateAccount returned %+v", account)
	}
	session, err := c.Login(ctx, account.AccountKey)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if session.Token != authTestToken || session.ExpiresAt == 0 {
		t.Fatalf("Login returned %+v", session)
	}
	user, err := c.Whoami(ctx)
	if err != nil {
		t.Fatalf("Whoami: %v", err)
	}
	if user.Role != "operator" {
		t.Fatalf("Whoami returned %+v", user)
	}
	recovered, err := c.Recover(ctx, account.RecoveryCode)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if recovered.AccountKey == account.AccountKey {
		t.Fatal("Recover returned the credential it replaced")
	}
	if err := c.Logout(ctx); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	want := [][3]string{
		{"PUT", "/user", `{"name":"a"}`},
		{"POST", "/auth/login", `{"account_key":"dba_k.v"}`},
		{"GET", "/me", ``},
		{"POST", "/auth/recover", `{"recovery_code":"dbr_k.v"}`},
		{"POST", "/auth/logout", `{}`},
	}
	sent := f.requests()
	if len(sent) != len(want) {
		t.Fatalf("sent %d requests, want %d: %+v", len(sent), len(want), sent)
	}
	for i, w := range want {
		if sent[i].Method != w[0] || sent[i].Path != w[1] || string(sent[i].Body) != w[2] {
			t.Fatalf("request %d = %s %s %s, want %s %s %s", i, sent[i].Method, sent[i].Path, sent[i].Body, w[0], w[1], w[2])
		}
	}
}

// TestBlankAccountNameIsRejectedLocally keeps a pointless request off the
// network.
func TestBlankAccountNameIsRejectedLocally(t *testing.T) {
	f := newFakeServer(t, "")
	if _, err := f.client(t, Options{}).CreateAccount(testContext(t), "  "); err == nil {
		t.Fatal("a blank account name was accepted")
	}
	if n := len(f.requests()); n != 0 {
		t.Fatalf("a blank account name reached the network: %d requests", n)
	}
}
