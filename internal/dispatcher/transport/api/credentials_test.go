// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const credentialTestAudience = "https://dispatcher.example/api"

func credentialFixture(t *testing.T) *ccFixture {
	return ccNewFixtureWith(t, func(h *Handler) {
		h.authPublicURL = credentialTestAudience
		h.deviceVerificationURL = "https://dispatcher.example/console/device"
	})
}
func credentialJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func credentialBrowser(t *testing.T, f *ccFixture) map[string]string {
	t.Helper()
	account, _, _ := authAccount(t, f, "browser approval")
	status, _, body, _ := authRequest(t, f, http.MethodPost, "/auth/login", credentialJSON(t, LoginRequest{AccountKey: account.AccountKey}), nil)
	if status != http.StatusOK {
		t.Fatalf("login status %d", status)
	}
	var session SessionResponse
	if err := json.Unmarshal(body, &session); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"Cookie": sessionCookieName + "=" + session.Token, csrfHeaderName: session.CSRFToken}
}
func createTestCredential(t *testing.T, f *ccFixture, browser map[string]string, scopes ...string) IssuedCredential {
	t.Helper()
	status, _, body, _ := authRequest(t, f, http.MethodPost, "/me/credentials", credentialJSON(t, CredentialRequest{Audience: credentialTestAudience, Scopes: scopes, Label: "test CLI"}), browser)
	if status != http.StatusCreated {
		t.Fatalf("credential creation status %d: %s", status, body)
	}
	var issued IssuedCredential
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatal(err)
	}
	return issued
}

func TestAPICredentialScopesAudienceAndRevocation(t *testing.T) {
	f := credentialFixture(t)
	browser := credentialBrowser(t, f)
	issued := createTestCredential(t, f, browser, "account:read")
	if !strings.HasPrefix(issued.Token, "dbt_") {
		t.Fatal("API credential has wrong kind")
	}
	if s, _ := authAs(t, f, issued.Token, http.MethodGet, "/me", nil); s != 200 {
		t.Fatalf("account read %d", s)
	}
	for _, target := range []string{"/list-debuglets", "/user-ids", "/me/credentials"} {
		if s, _ := authAs(t, f, issued.Token, http.MethodGet, target, nil); s != 403 {
			t.Fatalf("ungranted %s = %d", target, s)
		}
	}
	if s, _ := authStatus(t, f, http.MethodGet, "/me", nil, map[string]string{"Cookie": sessionCookieName + "=" + issued.Token}); s != 401 {
		t.Fatalf("API token used as cookie %d", s)
	}
	if s, _ := authAs(t, f, strings.Replace(issued.Token, "dbt_", "dbs_", 1), http.MethodGet, "/me", nil); s != 401 {
		t.Fatalf("API token relabelled browser %d", s)
	}
	if _, err := f.db.Exec("UPDATE sessions SET audience = ? WHERE selector = ?", "https://other.example/api", issued.CredentialID); err != nil {
		t.Fatal(err)
	}
	if s, _ := authAs(t, f, issued.Token, http.MethodGet, "/me", nil); s != 401 {
		t.Fatalf("wrong audience %d", s)
	}
	if _, err := f.db.Exec("UPDATE sessions SET audience = ? WHERE selector = ?", credentialTestAudience, issued.CredentialID); err != nil {
		t.Fatal(err)
	}
	if s, _ := authStatus(t, f, http.MethodDelete, "/me/credentials/"+issued.CredentialID, nil, browser); s != 204 {
		t.Fatalf("revoke %d", s)
	}
	if s, _ := authAs(t, f, issued.Token, http.MethodGet, "/me", nil); s != 401 {
		t.Fatalf("revoked token %d", s)
	}
}

func TestCredentialManagementRequiresRecentCookieAndPreservesOwnership(t *testing.T) {
	f := credentialFixture(t)
	browser := credentialBrowser(t, f)
	issued := createTestCredential(t, f, browser, "account:read", "measurements:read")
	other := credentialBrowser(t, f)
	if s, _ := authStatus(t, f, http.MethodDelete, "/me/credentials/"+issued.CredentialID, nil, other); s != 404 {
		t.Fatalf("another account revoke %d", s)
	}
	if s, _ := authAs(t, f, issued.Token, http.MethodGet, "/debuglet/"+authSampleID+"/state", nil); s != 404 {
		t.Fatalf("missing run %d", s)
	}
	if _, err := f.db.Exec("UPDATE sessions SET authenticated_at = datetime('now', '-11 minutes') WHERE kind='browser'"); err != nil {
		t.Fatal(err)
	}
	if s, _ := authStatus(t, f, http.MethodPost, "/me/credentials", credentialJSON(t, CredentialRequest{Audience: credentialTestAudience, Scopes: []string{"account:read"}, Label: "stale"}), browser); s != 403 {
		t.Fatalf("old session create %d", s)
	}
}

func startTestDevice(t *testing.T, f *ccFixture) DeviceLoginStart {
	t.Helper()
	status, _, body, _ := authRequest(t, f, http.MethodPost, "/auth/device/start", credentialJSON(t, CredentialRequest{Audience: credentialTestAudience, Scopes: []string{"account:read"}, Label: "remote shell"}), nil)
	if status != 201 {
		t.Fatalf("device start %d: %s", status, body)
	}
	var login DeviceLoginStart
	if err := json.Unmarshal(body, &login); err != nil {
		t.Fatal(err)
	}
	return login
}
func pollTestDevice(t *testing.T, f *ccFixture, login DeviceLoginStart) DeviceLoginPoll {
	t.Helper()
	status, _, body, _ := authRequest(t, f, http.MethodPost, "/auth/device/poll", credentialJSON(t, DeviceLoginRequest{DeviceCode: login.DeviceCode, Audience: login.Audience}), nil)
	if status != 200 {
		t.Fatalf("poll %d: %s", status, body)
	}
	var poll DeviceLoginPoll
	if err := json.Unmarshal(body, &poll); err != nil {
		t.Fatal(err)
	}
	return poll
}
func readyDevicePoll(t *testing.T, f *ccFixture) {
	t.Helper()
	if _, err := f.db.Exec("UPDATE device_logins SET next_poll_at = 0"); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceLoginApprovalIsExplicitAndConsumedOnce(t *testing.T) {
	f := credentialFixture(t)
	browser := credentialBrowser(t, f)
	login := startTestDevice(t, f)
	request := DeviceApprovalRequest{UserCode: login.UserCode, Audience: login.Audience}
	if s, _ := authStatus(t, f, http.MethodPost, "/auth/device/inspect", credentialJSON(t, request), browser); s != 200 {
		t.Fatalf("inspect %d", s)
	}
	if s, _ := authStatus(t, f, http.MethodPost, "/auth/device/approve", credentialJSON(t, request), browser); s != 400 {
		t.Fatalf("implicit approval %d", s)
	}
	request.Confirm = true
	if s, _ := authStatus(t, f, http.MethodPost, "/auth/device/approve", credentialJSON(t, request), browser); s != 204 {
		t.Fatalf("approval %d", s)
	}
	readyDevicePoll(t, f)
	poll := pollTestDevice(t, f, login)
	if poll.State != "authorized" || poll.Credential == nil {
		t.Fatalf("poll state %s", poll.State)
	}
	if s, _ := authAs(t, f, poll.Credential.Token, http.MethodGet, "/me", nil); s != 200 {
		t.Fatalf("issued token %d", s)
	}
	if again := pollTestDevice(t, f, login); again.State != "consumed" || again.Credential != nil {
		t.Fatal("device transaction replayed")
	}
}

func TestDeviceLoginDenialExpiryCancellationAndBackoff(t *testing.T) {
	for _, state := range []string{"denied", "expired", "cancelled", "backoff", "wrong_audience", "wrong_code"} {
		t.Run(state, func(t *testing.T) {
			f := credentialFixture(t)
			browser := credentialBrowser(t, f)
			login := startTestDevice(t, f)
			request := DeviceApprovalRequest{UserCode: login.UserCode, Audience: login.Audience, Confirm: true}
			switch state {
			case "denied":
				if s, _ := authStatus(t, f, http.MethodPost, "/auth/device/deny", credentialJSON(t, request), browser); s != 204 {
					t.Fatalf("deny %d", s)
				}
			case "expired":
				if _, err := f.db.Exec("UPDATE device_logins SET expires_at = ?", time.Now().Add(-time.Second).Unix()); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				if s, _ := authStatus(t, f, http.MethodPost, "/auth/device/cancel", credentialJSON(t, DeviceLoginRequest{DeviceCode: login.DeviceCode, Audience: login.Audience}), nil); s != 204 {
					t.Fatalf("cancel %d", s)
				}
			case "wrong_audience":
				request.Audience = "https://other.example/api"
				if s, _ := authStatus(t, f, http.MethodPost, "/auth/device/approve", credentialJSON(t, request), browser); s != 400 {
					t.Fatalf("audience %d", s)
				}
				return
			case "wrong_code":
				request.UserCode = "AAAAA-AAAAA"
				if s, _ := authStatus(t, f, http.MethodPost, "/auth/device/approve", credentialJSON(t, request), browser); s != 404 {
					t.Fatalf("wrong code %d", s)
				}
				return
			}
			poll := pollTestDevice(t, f, login)
			want := "access_denied"
			if state == "expired" {
				want = "expired_token"
			}
			if state == "backoff" {
				want = "slow_down"
				if poll.Interval != 10 {
					t.Fatalf("backoff %d", poll.Interval)
				}
			}
			if poll.State != want || poll.Credential != nil {
				t.Fatalf("state %s, want %s", poll.State, want)
			}
		})
	}
}

func TestConcurrentDevicePollIssuesOneCredential(t *testing.T) {
	f := credentialFixture(t)
	browser := credentialBrowser(t, f)
	login := startTestDevice(t, f)
	if s, _ := authStatus(t, f, http.MethodPost, "/auth/device/approve", credentialJSON(t, DeviceApprovalRequest{UserCode: login.UserCode, Audience: login.Audience, Confirm: true}), browser); s != 204 {
		t.Fatalf("approve %d", s)
	}
	readyDevicePoll(t, f)
	results := make(chan DeviceLoginPoll, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- pollTestDevice(t, f, login) }()
	}
	wg.Wait()
	close(results)
	issued := 0
	for result := range results {
		if result.State == "authorized" {
			issued++
		}
	}
	if issued != 1 {
		t.Fatalf("issued credentials %d", issued)
	}
	var count int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE kind='api'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("stored credentials %d", count)
	}
}

func TestDeviceLoginStartIsRateLimited(t *testing.T) {
	f := credentialFixture(t)
	body := credentialJSON(t, CredentialRequest{Audience: credentialTestAudience, Scopes: []string{"account:read"}, Label: "limited"})
	refused := false
	for range 15 {
		status, _ := authStatus(t, f, http.MethodPost, "/auth/device/start", body, nil)
		if status == 429 {
			refused = true
			break
		}
		if status != 201 {
			t.Fatalf("start %d", status)
		}
	}
	if !refused {
		t.Fatal("device issuance was not rate limited")
	}
}
