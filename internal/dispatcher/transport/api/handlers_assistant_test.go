// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/studio"
)

func assistantFixture(t *testing.T, provider http.Handler) *ccFixture {
	t.Helper()
	server := httptest.NewServer(provider)
	t.Cleanup(server.Close)
	assistant, err := studio.NewAssistant(studio.AssistantConfig{Endpoint: server.URL, Model: "test-model", APIKey: "provider-test-secret"})
	if err != nil {
		t.Fatal(err)
	}
	return ccNewFixtureWith(t, Assistant(assistant))
}

func assistantBody(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"kind": "workflow", "document": communityTestWorkflow(), "message": "Explain the current graph"})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assistantClarification(w http.ResponseWriter) {
	studioJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": "Which target should the experiment measure?"}}}})
}

func TestAssistantAuthenticatedAvailabilityAndReply(t *testing.T) {
	var calls atomic.Int32
	f := assistantFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer provider-test-secret" || r.Header.Get("Cookie") != "" || r.Header.Get(csrfHeaderName) != "" {
			t.Error("incorrect provider credentials")
		}
		proposal, err := json.Marshal(map[string]any{"message": "The existing graph is ready to review.", "document": communityTestWorkflow()})
		if err != nil {
			t.Error(err)
			return
		}
		studioJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "proposal", "type": "function", "function": map[string]any{"name": "propose_document", "arguments": string(proposal)}}}}}}})
	}))
	browser := studioBrowser(t, f)
	for _, method := range []string{"GET", "POST"} {
		if status, code := authStatus(t, f, method, "/studio/assistant", assistantBody(t), nil); status != 401 || code != CodeUnauthorized {
			t.Fatalf("anonymous %s %d %s", method, status, code)
		}
	}
	if status, _ := authStatus(t, f, "POST", "/studio/assistant", assistantBody(t), map[string]string{"Cookie": browser["Cookie"]}); status != 403 {
		t.Fatalf("missing csrf: %d", status)
	}
	contract := oaContract(t)
	for _, method := range []string{"GET", "POST"} {
		status, _, body, response := authRequest(t, f, method, "/studio/assistant", assistantBody(t), browser)
		if status != 200 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %d %s", method, status, body)
		}
		if strings.Contains(string(body), "provider-test-secret") || strings.Contains(string(body), "127.0.0.1") {
			t.Fatal("private provider configuration leaked")
		}
		oaCheckResponse(t, contract, method, "/studio/assistant", status, body)
	}
	if calls.Load() != 1 {
		t.Fatalf("provider calls %d", calls.Load())
	}
	disabled := ccNewFixtureWith(t)
	session := studioBrowser(t, disabled)
	status, _, body, _ := authRequest(t, disabled, "GET", "/studio/assistant", nil, session)
	if status != 200 || !strings.Contains(string(body), `"enabled":false`) {
		t.Fatalf("disabled: %d %s", status, body)
	}
	if status, _ := authStatus(t, disabled, "POST", "/studio/assistant", assistantBody(t), session); status != 503 {
		t.Fatalf("disabled post %d", status)
	}
}

func TestAssistantRejectsInputAndSanitizesProviderFailure(t *testing.T) {
	var calls atomic.Int32
	f := assistantFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "provider-test-secret and upstream internals", 500)
	}))
	browser := studioBrowser(t, f)
	for _, body := range []string{`{}`, `{"kind":"workflow","document":{},"message":"hi","endpoint":"https://other.example"}`} {
		if status, _ := authStatus(t, f, "POST", "/studio/assistant", []byte(body), browser); status != 400 {
			t.Fatalf("malformed %d", status)
		}
	}
	if status, _ := authStatus(t, f, "POST", "/studio/assistant?endpoint=other", assistantBody(t), browser); status != 400 {
		t.Fatalf("query %d", status)
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached provider")
	}
	for i := 0; i < 2; i++ {
		status, _, body, _ := authRequest(t, f, "POST", "/studio/assistant", assistantBody(t), browser)
		if status != 502 || strings.Contains(string(body), "upstream internals") || strings.Contains(string(body), "provider-test-secret") {
			t.Fatalf("provider failure %d %s", status, body)
		}
	}
	if calls.Load() != 2 {
		t.Fatal("failure did not release account capacity")
	}
}

func TestAssistantDistinguishesInvalidGraphAndProviderFailure(t *testing.T) {
	for _, test := range []struct {
		name           string
		providerStatus int
		status         int
		code           string
		calls          int32
	}{
		{"invalid graph", http.StatusOK, http.StatusUnprocessableEntity, CodeInvalidRequest, 2},
		{"provider failure", http.StatusInternalServerError, http.StatusBadGateway, CodeUnavailable, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			invalid := communityTestWorkflow()
			invalid.Entry = "missing"
			proposal, err := json.Marshal(map[string]any{"message": "provider-test-secret and upstream internals", "document": invalid})
			if err != nil {
				t.Fatal(err)
			}
			f := assistantFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if test.providerStatus != http.StatusOK {
					http.Error(w, "provider-test-secret and upstream internals", test.providerStatus)
					return
				}
				studioJSON(w, http.StatusOK, map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "proposal", "type": "function", "function": map[string]any{"name": "propose_document", "arguments": string(proposal)}}}}}}})
			}))
			status, code, body, _ := authRequest(t, f, "POST", "/studio/assistant", assistantBody(t), studioBrowser(t, f))
			if status != test.status || code != test.code {
				t.Fatalf("status/code %d %s, want %d %s: %s", status, code, test.status, test.code, body)
			}
			if strings.Contains(string(body), "provider-test-secret") || strings.Contains(string(body), "upstream internals") {
				t.Fatal("provider details leaked")
			}
			if calls.Load() != test.calls {
				t.Fatalf("provider calls %d, want %d", calls.Load(), test.calls)
			}
			oaCheckResponse(t, oaContract(t), "POST", "/studio/assistant", status, body)
		})
	}
}

func TestAssistantRejectsParallelAccountAndLimitsGlobalRequests(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	f := assistantFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		assistantClarification(w)
	}))
	browser := studioBrowser(t, f)
	body := assistantBody(t)
	result := make(chan int, 1)
	go func() { status, _ := authStatus(t, f, "POST", "/studio/assistant", body, browser); result <- status }()
	select {
	case <-started:
	case <-time.After(ccRequestBound):
		t.Fatal("provider did not receive request")
	}
	status, _, _, resp := authRequest(t, f, "POST", "/studio/assistant", body, browser)
	close(release)
	if status != 429 || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("concurrent account %d", status)
	}
	if status := <-result; status != 200 {
		t.Fatalf("first request %d", status)
	}
	for i := 0; i < 3; i++ {
		if status, _ := authStatus(t, f, "POST", "/studio/assistant", body, studioBrowser(t, f)); status != 200 {
			t.Fatalf("burst request %d: %d", i, status)
		}
	}
	status, _, _, resp = authRequest(t, f, "POST", "/studio/assistant", body, studioBrowser(t, f))
	if status != 429 || resp.Header.Get("Retry-After") != "10" || calls.Load() != 4 {
		t.Fatalf("global rate: %d calls %d", status, calls.Load())
	}
}

func TestAssistantCredentialScopes(t *testing.T) {
	f := ccNewFixtureWith(t, Authentication(credentialTestAudience, ""))
	browser := credentialBrowser(t, f)
	for _, scope := range []string{"account:read", "measurements:read", "measurements:write"} {
		issued := createTestCredential(t, f, browser, scope)
		for _, operation := range []struct {
			method, scope string
			status        int
		}{{"GET", "measurements:read", 200}, {"POST", "measurements:write", 503}} {
			want := http.StatusForbidden
			if scope == operation.scope {
				want = operation.status
			}
			status, code := authAs(t, f, issued.Token, operation.method, "/studio/assistant", assistantBody(t))
			if status != want {
				t.Fatalf("%s credential %s: %d %s, want %d", scope, operation.method, status, code, want)
			}
		}
	}
}

func TestAssistantRejectsChunkedOversizeAndWrongContentType(t *testing.T) {
	var calls atomic.Int32
	f := assistantFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); assistantClarification(w) }))
	browser := studioBrowser(t, f)
	browser["Content-Type"] = "text/plain"
	if status, _ := authStatus(t, f, "POST", "/studio/assistant", assistantBody(t), browser); status != 415 {
		t.Fatalf("content type %d", status)
	}
	browser["Content-Type"] = "application/json"
	request, err := http.NewRequestWithContext(f.ctx, "POST", f.root.URL+"/studio/assistant", io.NopCloser(strings.NewReader(strings.Repeat(" ", studio.AssistantRequestLimit+1))))
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range browser {
		request.Header.Set(key, value)
	}
	response, err := f.root.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 413 {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("chunked oversize %d %s", response.StatusCode, body)
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid input reached provider %d", calls.Load())
	}
}
