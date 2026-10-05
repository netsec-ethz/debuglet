// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
)

// TestIdentityLinkThroughProviderCallbacks links a CILogon identity to an
// account signed in with GitHub through both providers' real callbacks and the
// explicit confirmation, and refuses the same CILogon subject to a second
// account.
func TestIdentityLinkThroughProviderCallbacks(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cilogon := newCILogonStub(t, key)
	var githubID atomic.Int64
	stubGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			io.WriteString(w, `{"access_token":"github-token"}`)
		case "/user":
			id := githubID.Load()
			fmt.Fprintf(w, `{"id":%d,"login":"researcher-%d","name":"Researcher %d"}`, id, id, id)
		default:
			http.NotFound(w, r)
		}
	})
	f := githubFixture(t, CILogon(CILogonConfig{Enabled: true, Issuer: cilogon.server.URL, ClientID: "test-id", ClientSecret: "test-secret", CallbackURL: "https://example.test/auth/cilogon/callback", SuccessURL: "https://example.test/console/"}))

	signIn := func(id int64) map[string]string {
		t.Helper()
		githubID.Store(id)
		response := cilogonResponse(t, githubCallback(t, f, url.Values{"code": {"one-time"}}))
		if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "https://example.test/console/" {
			t.Fatalf("GitHub sign-in = %d %s", response.StatusCode, response.Header.Get("Location"))
		}
		return changedBrowser(t, response)
	}
	account := func(browser map[string]string) string {
		t.Helper()
		status, _, body, _ := authRequest(t, f, http.MethodGet, "/me", nil, browser)
		var user UserResponse
		if status != http.StatusOK || json.Unmarshal(body, &user) != nil || user.ID == "" {
			t.Fatalf("/me = %d: %s", status, body)
		}
		return user.ID
	}
	// link starts linking CILogon for browser and returns where the CILogon
	// callback sent the browser.
	link := func(browser map[string]string) string {
		t.Helper()
		status, _, body, response := authRequest(t, f, http.MethodPost, "/me/identities/cilogon/link", []byte(`{}`), browser)
		var started struct {
			AuthorizationURL string `json:"authorization_url"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &started) != nil {
			t.Fatalf("link start = %d: %s", status, body)
		}
		authorization, err := url.Parse(started.AuthorizationURL)
		if err != nil {
			t.Fatal(err)
		}
		query := authorization.Query()
		if query.Get("state") == "" || query.Get("nonce") == "" || query.Get("code_challenge") == "" {
			t.Fatalf("invalid authorization URL %s", authorization)
		}
		cilogon.mu.Lock()
		cilogon.nonce, cilogon.challenge = query.Get("nonce"), query.Get("code_challenge")
		cilogon.mu.Unlock()
		callback, err := http.NewRequest(http.MethodGet, f.root.URL+"/auth/cilogon/callback?code=one-time&state="+url.QueryEscape(query.Get("state")), nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, cookie := range response.Cookies() {
			callback.AddCookie(cookie)
		}
		result := cilogonResponse(t, callback)
		if result.StatusCode != http.StatusFound {
			t.Fatalf("CILogon callback = %d", result.StatusCode)
		}
		for _, cookie := range result.Cookies() {
			if cookie.Name == sessionCookieName && cookie.Value != "" {
				t.Fatal("the link callback issued a session")
			}
		}
		return result.Header.Get("Location")
	}

	browser := signIn(42)
	before := account(browser)
	if location := link(browser); location != "https://example.test/console/?auth_action=link_pending&provider=cilogon" {
		t.Fatalf("link callback redirected to %s", location)
	}
	status, _, body, response := authRequest(t, f, http.MethodPost, "/me/identities/cilogon/confirm", []byte(`{"confirm":true}`), browser)
	if status != http.StatusNoContent {
		t.Fatalf("confirmation = %d: %s", status, body)
	}
	browser = changedBrowser(t, response)
	if after := account(browser); after != before {
		t.Fatalf("linking changed the account from %s to %s", before, after)
	}
	var identities, owners, users int
	if err := f.db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT user_id) FROM oauth_identities`).Scan(&identities, &owners); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if identities != 2 || owners != 1 || users != 1 {
		t.Fatalf("after linking identities=%d owners=%d users=%d", identities, owners, users)
	}
	var owner int64
	if err := f.db.QueryRow(`SELECT user_id FROM oauth_identities WHERE provider = 'cilogon' AND subject = 'researcher-42'`).Scan(&owner); err != nil {
		t.Fatal(err)
	}

	// A second account cannot take the CILogon subject the first one linked.
	other := signIn(43)
	if account(other) == before {
		t.Fatal("a second GitHub identity signed in to the first account")
	}
	if location := link(other); location != "https://example.test/console/?auth_error=identity_conflict" {
		t.Fatalf("conflicting link redirected to %s", location)
	}
	if status, code := authStatus(t, f, http.MethodPost, "/me/identities/cilogon/confirm", []byte(`{"confirm":true}`), other); status != http.StatusConflict || code != CodeIdentityConflict {
		t.Fatalf("conflicting confirmation = %d %s", status, code)
	}
	var cilogonRows int
	var current int64
	if err := f.db.QueryRow(`SELECT COUNT(*), MIN(user_id) FROM oauth_identities WHERE provider = 'cilogon'`).Scan(&cilogonRows, &current); err != nil {
		t.Fatal(err)
	}
	if cilogonRows != 1 || current != owner {
		t.Fatalf("the CILogon identity moved: rows=%d owner=%d, want owner %d", cilogonRows, current, owner)
	}
}
