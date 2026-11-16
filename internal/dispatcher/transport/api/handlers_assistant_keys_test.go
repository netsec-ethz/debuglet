// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/assistantkeys"
	"github.com/netsec-ethz/debuglet/internal/studio"
)

func personalAssistantFixture(t *testing.T, provider http.Handler, operator bool) *ccFixture {
	t.Helper()
	server := httptest.NewServer(provider)
	t.Cleanup(server.Close)
	return ccNewFixtureWith(t, func(h *Handler) {
		store, err := assistantkeys.New(h.db, bytes.Repeat([]byte{7}, 32))
		if err != nil {
			t.Fatal(err)
		}
		PersonalAssistantKeys(store, "personal-model", "high")(h)
		// Only the test factory redirects generation to a local provider fixture.
		h.assistant.newPersonal = func(key string) (*studio.Assistant, error) {
			return studio.NewAssistant(studio.AssistantConfig{Endpoint: server.URL, Model: "personal-model", APIKey: key})
		}
		if operator {
			client, err := studio.NewAssistant(studio.AssistantConfig{Endpoint: server.URL, Model: "operator-model", APIKey: "operator-test-key"})
			if err != nil {
				t.Fatal(err)
			}
			Assistant(client)(h) // Option ordering must preserve personal configuration.
		}
		h.authPublicURL, h.deviceVerificationURL = credentialTestAudience, "https://dispatcher.example/console/device"
	})
}

func savePersonalKey(t *testing.T, f *ccFixture, browser map[string]string, key string) {
	t.Helper()
	status, _, body, _ := authRequest(t, f, "PUT", "/me/assistant-key", credentialJSON(t, map[string]string{"api_key": key}), browser)
	if status != 204 || len(body) != 0 {
		t.Fatalf("save key status %d: %s", status, body)
	}
}

func TestPersonalAssistantKeyOwnershipCRUDAndRecentBrowser(t *testing.T) {
	f := personalAssistantFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("key CRUD called provider") }), false)
	a, b := studioBrowser(t, f), studioBrowser(t, f)
	for _, route := range []struct{ method, path string }{{"GET", "/me/assistant-key"}, {"PUT", "/me/assistant-key"}, {"DELETE", "/me/assistant-key"}, {"POST", "/me/assistant-key/test"}} {
		if status, _ := authStatus(t, f, route.method, route.path, nil, nil); status != 401 {
			t.Fatalf("anonymous %s: %d", route.method, status)
		}
	}
	if status, _ := authStatus(t, f, "PUT", "/me/assistant-key", []byte(`{"api_key":"secret"}`), map[string]string{"Cookie": a["Cookie"]}); status != 403 {
		t.Fatal("missing CSRF accepted", status)
	}
	savePersonalKey(t, f, a, "sk-test-account-a")
	for _, check := range []struct {
		browser             map[string]string
		configured, enabled bool
		source              string
	}{{a, true, true, "personal"}, {b, false, false, "none"}} {
		status, _, body, response := authRequest(t, f, "GET", "/me/assistant-key", nil, check.browser)
		var state struct {
			Enabled, Configured bool
			Model               string
		}
		if err := json.Unmarshal(body, &state); err != nil {
			t.Fatal(err)
		}
		if status != 200 || !state.Enabled || state.Configured != check.configured || response.Header.Get("Cache-Control") != "no-store" || bytes.Contains(body, []byte("sk-test")) {
			t.Fatal("unsafe key metadata", status, string(body))
		}
		status, _, body, _ = authRequest(t, f, "GET", "/studio/assistant", nil, check.browser)
		var availability struct {
			Enabled bool
			Source  string
		}
		if err := json.Unmarshal(body, &availability); err != nil {
			t.Fatal(err)
		}
		if status != 200 || availability.Enabled != check.enabled || availability.Source != check.source {
			t.Fatal("account availability", string(body))
		}
	}
	issued := createTestCredential(t, f, a, "account:read", "measurements:write")
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		if status, _ := authAs(t, f, issued.Token, method, "/me/assistant-key", []byte(`{"api_key":"replace"}`)); status != 403 {
			t.Fatal("API token managed key", method, status)
		}
	}
	savePersonalKey(t, f, a, "sk-test-replacement")
	if status, _ := authStatus(t, f, "DELETE", "/me/assistant-key", nil, a); status != 204 {
		t.Fatal("delete", status)
	}
	if status, _ := authStatus(t, f, "POST", "/me/assistant-key/test", nil, a); status != 409 {
		t.Fatal("missing key tested operator credential", status)
	}
	if _, err := f.db.ExecContext(f.ctx, "UPDATE sessions SET authenticated_at = datetime('now','-11 minutes') WHERE kind = 'browser'"); err != nil {
		t.Fatal(err)
	}
	if status, _ := authStatus(t, f, "PUT", "/me/assistant-key", []byte(`{"api_key":"replacement"}`), a); status != 403 {
		t.Fatal("stale browser changed key", status)
	}
}

func TestPersonalAssistantConcurrentAccountsNormalAndStream(t *testing.T) {
	seen := make(chan string, 2)
	release := make(chan struct{})
	f := personalAssistantFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		body, _ := io.ReadAll(r.Body)
		marker := "account-A-prompt"
		if key == "sk-test-b" {
			marker = "account-B-prompt"
		}
		if (key != "sk-test-a" && key != "sk-test-b") || !bytes.Contains(body, []byte(marker)) || bytes.Contains(body, []byte("sk-test-")) {
			t.Error("account credential or prompt crossed request boundary")
		}
		seen <- key
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		assistantClarification(w)
	}), true)
	a, b := studioBrowser(t, f), studioBrowser(t, f)
	savePersonalKey(t, f, a, "sk-test-a")
	savePersonalKey(t, f, b, "sk-test-b")
	var wg sync.WaitGroup
	for _, req := range []struct {
		browser       map[string]string
		path, message string
	}{{a, "/studio/assistant", "account-A-prompt"}, {b, "/studio/assistant/stream", "account-B-prompt"}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := credentialJSON(t, map[string]any{"kind": "workflow", "document": communityTestWorkflow(), "message": req.message})
			status, _, body, _ := authRequest(t, f, "POST", req.path, data, req.browser)
			if status != 200 || !bytes.Contains(body, []byte("Which target")) || bytes.Contains(body, []byte("sk-test")) {
				t.Errorf("personal generation %d: %s", status, body)
			}
		}()
	}
	ctx, cancel := context.WithTimeout(context.Background(), ccRequestBound)
	defer cancel()
	for range 2 {
		select {
		case <-seen:
		case <-ctx.Done():
			close(release)
			wg.Wait()
			t.Fatal("requests did not run concurrently")
		}
	}
	close(release)
	wg.Wait()
}

func TestPersonalAssistantFailureNeverUsesOperatorAndDeleteRestoresIt(t *testing.T) {
	var personalCalls, operatorCalls atomic.Int32
	f := personalAssistantFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Authorization")
		if key == "Bearer sk-test-bad" {
			personalCalls.Add(1)
			http.Error(w, "sensitive upstream text sk-test-bad", 401)
			return
		}
		if key != "Bearer operator-test-key" {
			t.Error("unexpected credential")
		}
		operatorCalls.Add(1)
		assistantClarification(w)
	}), true)
	browser := studioBrowser(t, f)
	savePersonalKey(t, f, browser, "sk-test-bad")
	for _, path := range []string{"/studio/assistant", "/studio/assistant/stream"} {
		status, _, body, _ := authRequest(t, f, "POST", path, assistantBody(t), browser)
		if (status != 502 && status != 200) || !bytes.Contains(body, []byte("provider_auth")) || bytes.Contains(body, []byte("sensitive")) || bytes.Contains(body, []byte("sk-test-bad")) {
			t.Fatal("provider error lost or leaked", status, string(body))
		}
	}
	if personalCalls.Load() != 2 || operatorCalls.Load() != 0 {
		t.Fatal("silently fell back to operator")
	}
	if _, err := f.db.ExecContext(f.ctx, "UPDATE assistant_keys SET encrypted_key = zeroblob(32)"); err != nil {
		t.Fatal(err)
	}
	if status, _ := authStatus(t, f, "POST", "/studio/assistant", assistantBody(t), browser); status != 503 || personalCalls.Load() != 2 || operatorCalls.Load() != 0 {
		t.Fatal("unreadable key silently fell back", status)
	}
	if status, _ := authStatus(t, f, "DELETE", "/me/assistant-key", nil, browser); status != 204 {
		t.Fatal("delete unreadable key", status)
	}
	if status, _ := authStatus(t, f, "POST", "/studio/assistant", assistantBody(t), browser); status != 200 || operatorCalls.Load() != 1 {
		t.Fatal("explicit delete did not restore operator source", status)
	}
}
