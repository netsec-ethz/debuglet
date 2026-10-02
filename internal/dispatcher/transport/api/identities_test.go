// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

func identityFixture(t *testing.T) *ccFixture {
	return ccNewFixtureWith(t, Authentication(credentialTestAudience, "https://dispatcher.example/console/device"),
		GitHubOAuth(GitHubOAuthConfig{Enabled: true, ClientID: "client", ClientSecret: "secret", CallbackURL: "https://dispatcher.example/api/auth/github/callback", SuccessURL: "https://dispatcher.example/console/"}),
		CILogon(CILogonConfig{Enabled: true, Issuer: "https://cilogon.org", ClientID: "client", ClientSecret: "secret", CallbackURL: "https://dispatcher.example/api/auth/cilogon/callback", SuccessURL: "https://dispatcher.example/console/"}))
}
func seedPendingIdentity(t *testing.T, f *ccFixture, browser map[string]string, provider, issuer, subject string) int64 {
	t.Helper()
	token := strings.TrimPrefix(browser["Cookie"], sessionCookieName+"=")
	selector, _, _ := parseCredential(sessionPrefix, token)
	q := database.New(f.db)
	session, err := q.GetIdentitySession(context.Background(), selector)
	if err != nil {
		t.Fatal(err)
	}
	err = q.StorePendingIdentityLink(context.Background(), database.StorePendingIdentityLinkParams{UserID: session.UserID, Provider: provider, Issuer: issuer, Subject: subject, Login: "same display name", SessionSelector: selector, ExpiresAt: models.NewUTCTime(time.Now().UTC().Add(time.Minute))})
	if err != nil {
		t.Fatal(err)
	}
	return session.UserID
}
func changedBrowser(t *testing.T, response *http.Response) map[string]string {
	t.Helper()
	headers := map[string]string{}
	for _, cookie := range response.Cookies() {
		switch cookie.Name {
		case sessionCookieName:
			headers["Cookie"] = sessionCookieName + "=" + cookie.Value
		case csrfCookieName:
			headers[csrfHeaderName] = cookie.Value
		}
	}
	if headers["Cookie"] == "" || headers[csrfHeaderName] == "" {
		t.Fatal("missing rotated cookies")
	}
	return headers
}

func TestIdentityLinkConfirmationPreservesOwnershipAndRevokesCredentials(t *testing.T) {
	f := identityFixture(t)
	browser := credentialBrowser(t, f)
	apiCredential := createTestCredential(t, f, browser, "account:read")
	owner := seedPendingIdentity(t, f, browser, "github", "https://github.com", "42")
	if status, _ := authStatus(t, f, http.MethodPost, "/me/identities/github/confirm", []byte(`{"confirm":false}`), browser); status != 400 {
		t.Fatalf("unconfirmed link %d", status)
	}
	status, _, body, response := authRequest(t, f, http.MethodPost, "/me/identities/github/confirm", []byte(`{"confirm":true}`), browser)
	if status != 204 {
		t.Fatalf("confirmation %d: %s", status, body)
	}
	rotated := changedBrowser(t, response)
	var identityOwner int64
	if err := f.db.QueryRow("SELECT user_id FROM oauth_identities WHERE issuer=? AND subject=?", "https://github.com", "42").Scan(&identityOwner); err != nil {
		t.Fatal(err)
	}
	if identityOwner != owner {
		t.Fatal("link changed canonical owner")
	}
	if status, _ := authStatus(t, f, http.MethodGet, "/me", nil, browser); status != 401 {
		t.Fatalf("old browser still valid %d", status)
	}
	if status, _ := authAs(t, f, apiCredential.Token, http.MethodGet, "/me", nil); status != 401 {
		t.Fatalf("old API credential still valid %d", status)
	}
	if status, _ := authStatus(t, f, http.MethodGet, "/me", nil, rotated); status != 200 {
		t.Fatalf("rotated session %d", status)
	}
	if status, _ := authStatus(t, f, http.MethodPost, "/me/identities/github/confirm", []byte(`{"confirm":true}`), rotated); status != 409 {
		t.Fatalf("confirmation replay %d", status)
	}
}

func TestIdentityLinkCannotStealOrAutomaticallyMergeAccounts(t *testing.T) {
	f := identityFixture(t)
	a, b := credentialBrowser(t, f), credentialBrowser(t, f)
	ownerA := seedPendingIdentity(t, f, a, "github", "https://github.com", "42")
	ownerB := seedPendingIdentity(t, f, b, "github", "https://github.com", "42")
	outcomes := make(chan int, 2)
	var wg sync.WaitGroup
	for _, browser := range []map[string]string{a, b} {
		wg.Add(1)
		go func(headers map[string]string) {
			defer wg.Done()
			status, _ := authStatus(t, f, http.MethodPost, "/me/identities/github/confirm", []byte(`{"confirm":true}`), headers)
			outcomes <- status
		}(browser)
	}
	wg.Wait()
	close(outcomes)
	success, conflict := 0, 0
	for status := range outcomes {
		if status == 204 {
			success++
		}
		if status == 409 {
			conflict++
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("concurrent results success=%d conflict=%d", success, conflict)
	}
	var owner, count int64
	if err := f.db.QueryRow("SELECT user_id,COUNT(*) FROM oauth_identities").Scan(&owner, &count); err != nil {
		t.Fatal(err)
	}
	if count != 1 || (owner != ownerA && owner != ownerB) {
		t.Fatal("identity has inconsistent ownership")
	}
	var users int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&users); err != nil {
		t.Fatal(err)
	}
	if users != 2 {
		t.Fatalf("accounts merged by display name: %d", users)
	}
}

func TestIdentityUnlinkLastUsableMethodAndRecentAuthentication(t *testing.T) {
	f := identityFixture(t)
	browser := credentialBrowser(t, f)
	owner := seedPendingIdentity(t, f, browser, "github", "https://github.com", "42")
	_, _, _, response := authRequest(t, f, http.MethodPost, "/me/identities/github/confirm", []byte(`{"confirm":true}`), browser)
	browser = changedBrowser(t, response)
	if _, err := f.db.Exec("DELETE FROM user_credentials WHERE user_id=?", owner); err != nil {
		t.Fatal(err)
	}
	if status, _ := authStatus(t, f, http.MethodDelete, "/me/identities/github", []byte(`{"confirm":true}`), browser); status != 409 {
		t.Fatalf("last method removal %d", status)
	}
	seedPendingIdentity(t, f, browser, "cilogon", "https://cilogon.org", "subject")
	_, _, _, response = authRequest(t, f, http.MethodPost, "/me/identities/cilogon/confirm", []byte(`{"confirm":true}`), browser)
	browser = changedBrowser(t, response)
	if status, _, body, response := authRequest(t, f, http.MethodDelete, "/me/identities/github", []byte(`{"confirm":true}`), browser); status != 204 {
		t.Fatalf("remove with alternative %d: %s", status, body)
	} else {
		browser = changedBrowser(t, response)
	}
	// Rotation keeps the original provider authentication time.
	if _, err := f.db.Exec("UPDATE sessions SET authenticated_at = ?", models.NewUTCTime(time.Now().UTC().Add(-11*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if status, _ := authStatus(t, f, http.MethodPost, "/me/identities/github/link", []byte(`{}`), browser); status != 403 {
		t.Fatalf("stale reauthentication %d", status)
	}
	status, _, body, _ := authRequest(t, f, http.MethodGet, "/me/identities", nil, browser)
	if status != 200 {
		t.Fatal(status)
	}
	var listed struct {
		ReauthenticationRequired bool `json:"reauthentication_required"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatal(err)
	}
	if !listed.ReauthenticationRequired {
		t.Fatal("list did not request reauthentication")
	}
}

func TestExternalIdentityNamespacesAreIssuerBound(t *testing.T) {
	f := identityFixture(t)
	owners := []int64{}
	for _, issuer := range []string{"https://cilogon.org", "https://test.cilogon.org"} {
		tx, err := f.db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		id, err := externalIdentityUser(context.Background(), database.New(tx), externalProfile{Provider: "cilogon", Issuer: issuer, Subject: "same-subject", Login: "same-name", Name: "same-name"})
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		owners = append(owners, id)
	}
	if owners[0] == owners[1] {
		t.Fatal("different issuers were merged")
	}
}
