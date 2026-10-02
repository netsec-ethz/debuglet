// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type cilogonStub struct {
	server                 *httptest.Server
	mu                     sync.Mutex
	key, signingKey        *rsa.PrivateKey
	kid, nonce, challenge  string
	claims                 map[string]any
	exchanges, keyRequests int
}

func newCILogonStub(t *testing.T, key *rsa.PrivateKey) *cilogonStub {
	t.Helper()
	p := &cilogonStub{key: key, signingKey: key, kid: "first"}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize",
				"token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/keys",
				"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			p.keyRequests++
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: p.kid, Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			p.exchanges++
			if err := r.ParseForm(); err != nil {
				t.Error(err)
				http.Error(w, "invalid request", 400)
				return
			}
			client, secret, ok := r.BasicAuth()
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if !ok || client != "test-id" || secret != "test-secret" || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "one-time" || r.Form.Get("redirect_uri") != "https://example.test/auth/cilogon/callback" || base64.RawURLEncoding.EncodeToString(challenge[:]) != p.challenge {
				t.Error("token exchange did not preserve client credentials, callback, or PKCE")
				http.Error(w, "invalid request", 400)
				return
			}
			claims := map[string]any{"iss": p.server.URL, "sub": "researcher-42", "aud": "test-id", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": p.nonce, "name": "Researcher"}
			for name, value := range p.claims {
				claims[name] = value
			}
			payload, err := json.Marshal(claims)
			if err != nil {
				t.Error(err)
				http.Error(w, "cannot encode claims", 500)
				return
			}
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: p.signingKey, KeyID: p.kid}}, (&jose.SignerOptions{}).WithType("JWT"))
			if err != nil {
				t.Error(err)
				http.Error(w, "cannot sign", 500)
				return
			}
			signed, err := signer.Sign(payload)
			if err != nil {
				t.Error(err)
				http.Error(w, "cannot sign", 500)
				return
			}
			token, err := signed.CompactSerialize()
			if err != nil {
				t.Error(err)
				http.Error(w, "cannot serialize", 500)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "provider-token", "token_type": "Bearer", "expires_in": 3600, "id_token": token})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.server.Close)
	return p
}

func (p *cilogonStub) fixture(t *testing.T) *ccFixture {
	t.Helper()
	return ccNewFixtureWith(t, CookieSecure(true), CILogon(CILogonConfig{Enabled: true, Issuer: p.server.URL, ClientID: "test-id", ClientSecret: "test-secret", CallbackURL: "https://example.test/auth/cilogon/callback", SuccessURL: "https://example.test/console/"}))
}

func cilogonResponse(t *testing.T, request *http.Request) *http.Response {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	return response
}

func (p *cilogonStub) begin(t *testing.T, f *ccFixture) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, f.root.URL+"/auth/cilogon", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := cilogonResponse(t, request)
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	if response.StatusCode != http.StatusFound || query.Get("client_id") != "test-id" || query.Get("response_type") != "code" || query.Get("nonce") == "" || query.Get("state") == "" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("invalid authorization redirect: %d %s", response.StatusCode, location)
	}
	p.mu.Lock()
	p.nonce, p.challenge = query.Get("nonce"), query.Get("code_challenge")
	p.mu.Unlock()
	callback, err := http.NewRequest(http.MethodGet, f.root.URL+"/auth/cilogon/callback?code=one-time&state="+url.QueryEscape(query.Get("state")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Cookies()) != 2 {
		t.Fatalf("login cookies = %d, want 2", len(response.Cookies()))
	}
	for _, cookie := range response.Cookies() {
		if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
			t.Fatalf("unsafe login cookie %q", cookie.Name)
		}
		callback.AddCookie(cookie)
	}
	return callback
}

func TestCILogonOIDCLoginReusesAccountAndRefreshesKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := newCILogonStub(t, key)
	f := p.fixture(t)
	var accountID string
	for attempt := 0; attempt < 3; attempt++ {
		if attempt == 2 {
			rotated, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			p.mu.Lock()
			p.key, p.signingKey, p.kid = rotated, rotated, "rotated"
			p.mu.Unlock()
		}
		request := p.begin(t, f)
		if attempt == 0 {
			wrongState := request.Clone(t.Context())
			query := wrongState.URL.Query()
			query.Set("state", "mismatched-state-that-is-at-least-43-characters-long")
			wrongState.URL.RawQuery = query.Encode()
			if response := cilogonResponse(t, wrongState); response.StatusCode != http.StatusFound || response.Header.Get("Location") != "https://example.test/console/?auth_error=expired" {
				t.Fatalf("mismatched state = %d", response.StatusCode)
			}
			p.mu.Lock()
			exchanges := p.exchanges
			p.mu.Unlock()
			if exchanges != 0 {
				t.Fatal("mismatched state reached the token endpoint")
			}
		}
		response := cilogonResponse(t, request)
		if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "https://example.test/console/" {
			t.Fatalf("callback = %d %s", response.StatusCode, response.Header.Get("Location"))
		}
		var token string
		for _, cookie := range response.Cookies() {
			if cookie.Name == sessionCookieName {
				if !cookie.HttpOnly || !cookie.Secure {
					t.Fatal("unsafe session cookie")
				}
				token = cookie.Value
			}
		}
		if token == "" {
			t.Fatal("callback did not issue a session")
		}
		authenticated, err := f.client(f.root.URL, false).WithCredential(token)
		if err != nil {
			t.Fatal(err)
		}
		user, err := authenticated.Whoami(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if attempt == 0 {
			accountID = user.ID
		}
		if user.ID != accountID || user.Role != RoleUser {
			t.Fatalf("unexpected account: %+v", user)
		}
		replayed := cilogonResponse(t, request)
		if replayed.StatusCode != http.StatusFound || replayed.Header.Get("Location") != "https://example.test/console/?auth_error=expired" {
			t.Fatalf("replay = %d %s", replayed.StatusCode, replayed.Header.Get("Location"))
		}
		p.mu.Lock()
		exchanges := p.exchanges
		p.mu.Unlock()
		if exchanges != attempt+1 {
			t.Fatalf("replay exchanged a consumed code: %d calls", exchanges)
		}
	}
	var users, identities int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM oauth_identities`).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if users != 1 || identities != 1 {
		t.Fatalf("relogin created duplicate accounts: users=%d identities=%d", users, identities)
	}
	p.mu.Lock()
	keyRequests := p.keyRequests
	p.mu.Unlock()
	if keyRequests < 2 {
		t.Fatalf("rotation did not refresh signing keys: %d requests", keyRequests)
	}
}

func TestCILogonOIDCRejectsInvalidTokens(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		claims   map[string]any
		wrongKey bool
	}{
		{"nonce", map[string]any{"nonce": "different-login"}, false},
		{"issuer", map[string]any{"iss": "https://other.example"}, false},
		{"audience", map[string]any{"aud": "other-client"}, false},
		{"expired", map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}, false},
		{"signature", nil, true},
		{"empty-subject", map[string]any{"sub": ""}, false},
		{"authorized-party", map[string]any{"azp": "other-client"}, false},
		{"multiple-audiences-without-party", map[string]any{"aud": []string{"test-id", "other-client"}}, false},
		{"access-token-hash", map[string]any{"at_hash": "invalid"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := newCILogonStub(t, key)
			p.mu.Lock()
			p.claims = test.claims
			if test.wrongKey {
				p.signingKey = otherKey
			}
			p.mu.Unlock()
			f := p.fixture(t)
			response := cilogonResponse(t, p.begin(t, f))
			if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "https://example.test/console/?auth_error=provider_unavailable" {
				t.Fatalf("invalid token accepted: %d %s", response.StatusCode, response.Header.Get("Location"))
			}
			for _, cookie := range response.Cookies() {
				if cookie.Name == sessionCookieName && cookie.Value != "" {
					t.Fatal("invalid token issued a session")
				}
			}
			var users int
			if err := f.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
				t.Fatal(err)
			}
			if users != 0 {
				t.Fatalf("invalid token created %d accounts", users)
			}
		})
	}
}
