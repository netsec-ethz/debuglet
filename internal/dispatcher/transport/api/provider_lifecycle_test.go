// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"
	"time"
)

func cilogonSessionCookie(t *testing.T, response *http.Response) *http.Cookie {
	t.Helper()
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "https://example.test/console/" {
		t.Fatalf("login response = %d %q", response.StatusCode, response.Header.Get("Location"))
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			return cookie
		}
	}
	t.Fatal("login did not issue a session")
	return nil
}

func TestCILogonOutagesRecoverWithoutRestart(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, path      string
		expireDiscovery bool
	}{
		{"discovery", "/.well-known/openid-configuration", false},
		{"expired-discovery", "/.well-known/openid-configuration", true},
		{"token", "/token", false},
		{"signing-keys", "/keys", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := newCILogonStub(t, key)
			var handler *Handler
			f := p.fixture(t, func(h *Handler) { handler = h })
			if test.expireDiscovery {
				p.begin(t, f)
				handler.cilogonDiscovery.Lock()
				handler.cilogonDiscovery.expires = time.Time{}
				handler.cilogonDiscovery.Unlock()
			}
			p.mu.Lock()
			p.failPath = test.path
			p.mu.Unlock()
			var response *http.Response
			if test.path == "/.well-known/openid-configuration" {
				request, err := http.NewRequest(http.MethodGet, f.root.URL+"/auth/cilogon", nil)
				if err != nil {
					t.Fatal(err)
				}
				response = cilogonResponse(t, request)
			} else {
				response = cilogonResponse(t, p.begin(t, f))
			}
			if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "https://example.test/console/?auth_error=provider_unavailable" {
				t.Fatalf("outage response = %d %q", response.StatusCode, response.Header.Get("Location"))
			}
			var accounts, sessions int
			if err := f.db.QueryRow("SELECT (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM sessions)").Scan(&accounts, &sessions); err != nil {
				t.Fatal(err)
			}
			if accounts != 0 || sessions != 0 {
				t.Fatalf("outage created accounts=%d sessions=%d", accounts, sessions)
			}
			p.mu.Lock()
			p.failPath = ""
			p.mu.Unlock()
			cilogonSessionCookie(t, cilogonResponse(t, p.begin(t, f)))
		})
	}
}

func TestCILogonReauthenticationReplacesOnlyAfterSuccessfulExchange(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := newCILogonStub(t, key)
	f := p.fixture(t)
	oldCookie := cilogonSessionCookie(t, cilogonResponse(t, p.begin(t, f)))
	oldClient, err := f.client(f.root.URL, false).WithCredential(oldCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	before, err := oldClient.Whoami(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.failPath = "/token"
	p.mu.Unlock()
	failed := cilogonResponse(t, p.begin(t, f, oldCookie))
	if failed.Header.Get("Location") != "https://example.test/console/?auth_error=provider_unavailable" {
		t.Fatal("failed reauthentication did not report provider unavailability")
	}
	if _, err := oldClient.Whoami(t.Context()); err != nil {
		t.Fatalf("failed reauthentication revoked existing session: %v", err)
	}
	p.mu.Lock()
	p.failPath = ""
	p.mu.Unlock()
	newCookie := cilogonSessionCookie(t, cilogonResponse(t, p.begin(t, f, oldCookie)))
	if newCookie.Value == oldCookie.Value {
		t.Fatal("reauthentication reused the existing credential")
	}
	if _, err := oldClient.Whoami(t.Context()); !authIsUnauthorized(err) {
		t.Fatalf("previous session survived replacement: %v", err)
	}
	newClient, err := f.client(f.root.URL, false).WithCredential(newCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	after, err := newClient.Whoami(t.Context())
	if err != nil || after.ID != before.ID {
		t.Fatalf("reauthentication changed the account: %+v: %v", after, err)
	}
}
