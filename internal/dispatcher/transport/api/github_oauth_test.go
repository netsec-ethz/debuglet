package api

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	githubOAuthStateCookie = "github_oauth_state"
	githubOAuthPKCECookie  = "github_oauth_pkce"
)

func TestGitHubOAuthLoginCreatesAndReusesAccount(t *testing.T) {
	var exchangedVerifier string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil || r.Form.Get("client_secret") != "test-secret" || r.Form.Get("code") != "one-time" || r.Form.Get("code_verifier") == "" {
				t.Errorf("unexpected token exchange: %v %v", err, r.Form)
			}
			exchangedVerifier = r.Form.Get("code_verifier")
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"access_token":"github-token"}`)
		case "/user":
			if r.Header.Get("Authorization") != "Bearer github-token" {
				t.Errorf("authorization = %q", r.Header.Get("Authorization"))
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"id":42,"login":"octocat","name":"The Octocat"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	oldAuthorize, oldToken, oldUser, oldClient := githubAuthorizeURL, githubTokenURL, githubUserURL, githubOAuthHTTPClient
	githubAuthorizeURL, githubTokenURL, githubUserURL, githubOAuthHTTPClient = provider.URL+"/authorize", provider.URL+"/token", provider.URL+"/user", provider.Client()
	defer func() {
		githubAuthorizeURL, githubTokenURL, githubUserURL, githubOAuthHTTPClient = oldAuthorize, oldToken, oldUser, oldClient
	}()

	f := ccNewFixtureWith(t, CookieSecure(true), GitHubOAuth(GitHubOAuthConfig{Enabled: true, ClientID: "test-id", ClientSecret: "test-secret", CallbackURL: "https://example.test/api/auth/github/callback", SuccessURL: "https://example.test/console/"}))
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start, err := client.Get(f.root.URL + "/auth/github")
	if err != nil {
		t.Fatal(err)
	}
	defer start.Body.Close()
	if start.StatusCode != http.StatusFound {
		t.Fatalf("start status = %d", start.StatusCode)
	}
	location, err := url.Parse(start.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := location.Query().Get("state")
	if location.Query().Get("client_id") != "test-id" || state == "" || location.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("redirect = %s", location)
	}
	var stateCookie, verifierCookie *http.Cookie
	for _, cookie := range start.Cookies() {
		if cookie.Name == githubOAuthStateCookie {
			stateCookie = cookie
		}
		if cookie.Name == githubOAuthPKCECookie {
			verifierCookie = cookie
		}
	}
	if stateCookie == nil || verifierCookie == nil || !stateCookie.HttpOnly || !stateCookie.Secure || stateCookie.SameSite != http.SameSiteLaxMode || !verifierCookie.HttpOnly || !verifierCookie.Secure || verifierCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unsafe OAuth cookies: state=%#v verifier=%#v", stateCookie, verifierCookie)
	}
	challengeHash := sha256.Sum256([]byte(verifierCookie.Value))
	if location.Query().Get("code_challenge") != base64.RawURLEncoding.EncodeToString(challengeHash[:]) {
		t.Fatalf("PKCE challenge does not match verifier")
	}
	req, _ := http.NewRequest(http.MethodGet, f.root.URL+"/auth/github/callback?code=one-time&state="+url.QueryEscape(state), nil)
	req.AddCookie(stateCookie)
	req.AddCookie(verifierCookie)
	callback, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer callback.Body.Close()
	if callback.StatusCode != http.StatusFound || callback.Header.Get("Location") != "https://example.test/console/" {
		body, _ := io.ReadAll(callback.Body)
		t.Fatalf("callback = %d %q: %s", callback.StatusCode, callback.Header.Get("Location"), body)
	}
	if exchangedVerifier != verifierCookie.Value {
		t.Fatalf("token exchange used the wrong PKCE verifier")
	}
	var session *http.Cookie
	for _, cookie := range callback.Cookies() {
		if cookie.Name == sessionCookieName {
			session = cookie
		}
	}
	if session == nil || !session.HttpOnly || !session.Secure || !strings.HasPrefix(session.Value, sessionPrefix+"_") {
		t.Fatalf("unsafe session cookie: %#v", session)
	}
	var users, identities int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM oauth_identities`).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if users != 1 || identities != 1 {
		t.Fatalf("users=%d identities=%d", users, identities)
	}
}

func TestGitHubOAuthRejectsMismatchedState(t *testing.T) {
	f := ccNewFixtureWith(t, GitHubOAuth(GitHubOAuthConfig{Enabled: true, ClientID: "id", ClientSecret: "secret", CallbackURL: "https://example.test/api/auth/github/callback", SuccessURL: "https://example.test/console/"}))
	req, _ := http.NewRequest(http.MethodGet, f.root.URL+"/auth/github/callback?code=one-time&state=wrong", nil)
	req.AddCookie(&http.Cookie{Name: githubOAuthStateCookie, Value: "right"})
	req.AddCookie(&http.Cookie{Name: githubOAuthPKCECookie, Value: strings.Repeat("v", 43)})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "https://example.test/console/?auth_error=expired" {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

// stubGitHub serves the GitHub authorization, token and user endpoints from
// handler for the rest of the test.
func stubGitHub(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	provider := httptest.NewServer(handler)
	oldAuthorize, oldToken, oldUser, oldClient := githubAuthorizeURL, githubTokenURL, githubUserURL, githubOAuthHTTPClient
	githubAuthorizeURL, githubTokenURL, githubUserURL, githubOAuthHTTPClient = provider.URL+"/authorize", provider.URL+"/token", provider.URL+"/user", provider.Client()
	t.Cleanup(func() {
		githubAuthorizeURL, githubTokenURL, githubUserURL, githubOAuthHTTPClient = oldAuthorize, oldToken, oldUser, oldClient
		provider.Close()
	})
}

func githubFixture(t *testing.T, options ...Option) *ccFixture {
	t.Helper()
	return ccNewFixtureWith(t, append([]Option{CookieSecure(true), GitHubOAuth(GitHubOAuthConfig{Enabled: true, ClientID: "test-id", ClientSecret: "test-secret", CallbackURL: "https://example.test/api/auth/github/callback", SuccessURL: "https://example.test/console/"})}, options...)...)
}

// githubCallback starts a GitHub sign-in and returns the provider's callback
// for it, carrying the issued state, the login cookies and query.
func githubCallback(t *testing.T, f *ccFixture, query url.Values) *http.Request {
	t.Helper()
	start, err := http.NewRequest(http.MethodGet, f.root.URL+"/auth/github", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := cilogonResponse(t, start)
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil || response.StatusCode != http.StatusFound || location.Query().Get("state") == "" {
		t.Fatalf("start = %d %s", response.StatusCode, response.Header.Get("Location"))
	}
	query.Set("state", location.Query().Get("state"))
	callback, err := http.NewRequest(http.MethodGet, f.root.URL+"/auth/github/callback?"+query.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range response.Cookies() {
		callback.AddCookie(cookie)
	}
	return callback
}

// githubSignInFailed asserts the callback ended at the sign-in failure state
// without an account, a linked identity or a session.
func githubSignInFailed(t *testing.T, f *ccFixture, response *http.Response, code string) {
	t.Helper()
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "https://example.test/console/?auth_error="+code {
		t.Fatalf("callback = %d %s, want auth_error=%s", response.StatusCode, response.Header.Get("Location"), code)
	}
	for _, cookie := range response.Cookies() {
		if (cookie.Name == sessionCookieName || cookie.Name == csrfCookieName) && cookie.Value != "" {
			t.Fatalf("failed sign-in set %s", cookie.Name)
		}
	}
	var users, identities int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM oauth_identities`).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if users != 0 || identities != 0 {
		t.Fatalf("failed sign-in stored users=%d identities=%d", users, identities)
	}
}

func TestGitHubOAuthProviderOutageIsATemporarySignInFailure(t *testing.T) {
	var exchanges, lookups atomic.Int32
	stubGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			exchanges.Add(1)
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		case "/user":
			lookups.Add(1)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	})
	f := githubFixture(t)
	githubSignInFailed(t, f, cilogonResponse(t, githubCallback(t, f, url.Values{"code": {"one-time"}})), "provider_unavailable")
	if exchanges.Load() != 1 || lookups.Load() != 0 {
		t.Fatalf("token exchanges=%d user lookups=%d", exchanges.Load(), lookups.Load())
	}
}

func TestGitHubOAuthCancelledSignInCreatesNoAccount(t *testing.T) {
	var requests atomic.Int32
	stubGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	})
	f := githubFixture(t)
	githubSignInFailed(t, f, cilogonResponse(t, githubCallback(t, f, url.Values{"error": {"access_denied"}})), "cancelled")
	if requests.Load() != 0 {
		t.Fatalf("a cancelled sign-in contacted the provider %d times", requests.Load())
	}
}
