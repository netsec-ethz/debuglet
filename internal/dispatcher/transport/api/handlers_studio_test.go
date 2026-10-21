// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/studio"
	"go.uber.org/zap"
)

// studioUnixFixture exercises the real HTTP transport and its connection
// cancellation. Fault cases replace only the isolated worker's HTTP handler.
func studioUnixFixture(t *testing.T, worker http.Handler, options ...Option) *ccFixture {
	t.Helper()
	return studioUnixFixtureConfigured(t, worker, nil, options...)
}

func studioUnixFixtureConfigured(t *testing.T, worker http.Handler, configure func(*dispatcher.Dispatcher) error, options ...Option) *ccFixture {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "studio.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: worker, ReadHeaderTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		if err := <-done; err != http.ErrServerClosed {
			t.Errorf("worker HTTP server: %v", err)
		}
	})
	options = append([]Option{Studio(config.StudioConfig{SocketPath: socket})}, options...)
	return ccNewFixtureConfigured(t, zap.NewNop(), &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "TEST"}, configure, options...)
}

// studioBrowser creates only an account and a browser session, as federated
// login does. It never creates an account key or recovery credential.
func studioBrowser(t *testing.T, f *ccFixture) map[string]string {
	t.Helper()
	queries := database.New(f.db)
	account, err := queries.CreateUser(f.ctx, database.CreateUserParams{Uuid: uuid.New(), Name: "hosted browser"})
	if err != nil {
		t.Fatal(err)
	}
	token, csrf, _, err := issueSession(f.ctx, queries, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"Cookie": sessionCookieName + "=" + token, csrfHeaderName: csrf}
}

func studioJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func TestStudioRequiresAccountAndCSRFWithoutAccountKeys(t *testing.T) {
	var calls atomic.Int32
	worker := studio.NewWorkerHandler(nil)
	f := studioUnixFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		worker.ServeHTTP(w, r)
	}), LocalDevelopment(true))
	browser := studioBrowser(t, f)
	contract := oaContract(t)
	for _, route := range []struct{ method, path string }{
		{"GET", "/studio/catalog"}, {"POST", "/studio/validate"}, {"POST", "/studio/build"},
		{"POST", "/studio/experiments/validate"}, {"POST", "/studio/experiments/build"},
	} {
		status, code := authStatus(t, f, route.method, route.path, []byte(`{}`), nil)
		if status != 401 || code != CodeUnauthorized {
			t.Fatalf("anonymous %s %s: %d %s", route.method, route.path, status, code)
		}
		if route.method == "POST" {
			status, code = authStatus(t, f, route.method, route.path, []byte(`{}`), map[string]string{"Cookie": browser["Cookie"]})
			if status != 403 || code != CodeForbidden {
				t.Fatalf("missing CSRF %s: %d %s", route.path, status, code)
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unauthenticated request reached worker")
	}
	for _, route := range []struct{ method, path string }{{"GET", "/studio/catalog"}, {"POST", "/studio/validate"}, {"POST", "/studio/experiments/validate"}} {
		status, _, body, _ := authRequest(t, f, route.method, route.path, []byte(`{}`), browser)
		if status != 200 {
			t.Fatalf("authenticated %s: %d %s", route.path, status, body)
		}
		oaCheckResponse(t, contract, route.method, route.path, status, body)
	}
	var keys int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM user_credentials").Scan(&keys); err != nil || keys != 0 {
		t.Fatalf("session-only account needs no keys: count=%d error=%v", keys, err)
	}
}

func TestStudioForwardsOnlyExactOperationsAndNoCredentials(t *testing.T) {
	var calls atomic.Int32
	f := studioUnixFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.String() != "/studio/validate" || r.Method != "POST" || r.Host != "studio" {
			t.Errorf("unexpected worker target %s %s host=%q", r.Method, r.URL, r.Host)
		}
		for name := range r.Header {
			if name != "Accept" && name != "Content-Type" && name != "Content-Length" {
				t.Errorf("forwarded request header %s", name)
			}
		}
		data, _ := io.ReadAll(r.Body)
		if string(data) != `{"version":1}` {
			t.Errorf("changed workflow body: %s", data)
		}
		w.Header().Set("Set-Cookie", "session_token=worker-controlled")
		w.Header().Set("Location", "https://untrusted.invalid/")
		w.Header().Set("X-Worker-Private", "private")
		studioJSON(w, 200, map[string]any{"diagnostics": []any{}})
	}))
	browser := studioBrowser(t, f)
	browser["X-Studio-Token"] = "local-token"
	browser["X-Forwarded-For"] = "private-address"
	browser["X-Account-ID"] = "private-account"
	browser["Origin"] = "https://console.example"
	browser["Authorization"] = "Bearer " + strings.TrimPrefix(browser["Cookie"], sessionCookieName+"=")
	status, _, _, response := authRequest(t, f, "POST", "/studio/validate", []byte(`{"version":1}`), browser)
	if status != 200 {
		t.Fatalf("proxy request: %d", status)
	}
	if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Location") != "" || response.Header.Get("X-Worker-Private") != "" || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected proxy headers: %v", response.Header)
	}
	for _, route := range []struct{ method, path string }{
		{"POST", "/studio/validate?path=/etc/passwd"}, {"POST", "/studio/%76alidate"},
		{"POST", "/studio/validate/"}, {"GET", "/studio/build"}, {"POST", "/studio/catalog"},
		{"POST", "/studio/session"}, {"POST", "/studio/api/build"}, {"POST", "/studio/../studio/build"},
	} {
		status, _ := authStatus(t, f, route.method, route.path, []byte(`{}`), browser)
		if status < 400 {
			t.Errorf("unexpected operation accepted %s %s: %d", route.method, route.path, status)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("unapproved operation reached worker: %d calls", calls.Load())
	}
}

func TestStudioAPICredentialScopes(t *testing.T) {
	f := studioUnixFixture(t, studio.NewWorkerHandler(nil), Authentication(credentialTestAudience, ""))
	browser := credentialBrowser(t, f)
	for _, scope := range []string{"account:read", "measurements:read", "measurements:write"} {
		issued := createTestCredential(t, f, browser, scope)
		for _, operation := range []struct{ method, path, scope string }{
			{"GET", "/studio/catalog", "measurements:read"},
			{"POST", "/studio/validate", "measurements:write"},
			{"POST", "/studio/experiments/validate", "measurements:write"},
		} {
			want := http.StatusForbidden
			if scope == operation.scope {
				want = http.StatusOK
			}
			status, code := authAs(t, f, issued.Token, operation.method, operation.path, []byte(`{}`))
			if status != want {
				t.Fatalf("%s credential, %s: %d %s, want %d", scope, operation.path, status, code, want)
			}
		}
	}
}

func TestStudioAcceptsExactResponseLimit(t *testing.T) {
	f := studioUnixFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprint(studioResponseLimit))
		_, _ = io.WriteString(w, `"`)
		_, _ = io.WriteString(w, strings.Repeat("x", studioResponseLimit-2))
		_, _ = io.WriteString(w, `"`)
	}))
	req, _ := http.NewRequestWithContext(f.ctx, "GET", f.root.URL+"/studio/catalog", nil)
	for name, value := range studioBrowser(t, f) {
		req.Header.Set(name, value)
	}
	response, err := f.root.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	size, err := io.Copy(io.Discard, response.Body)
	if response.StatusCode != 200 || size != studioResponseLimit || err != nil {
		t.Fatalf("exact response limit: status=%d size=%d error=%v", response.StatusCode, size, err)
	}
}

func TestStudioSlowReaderReleasesCapacity(t *testing.T) {
	var calls atomic.Int32
	f := studioUnixFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) != 1 {
			studioJSON(w, 200, map[string]any{"diagnostics": []any{}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprint(studioResponseLimit))
		_, _ = io.WriteString(w, `"`)
		_, _ = io.WriteString(w, strings.Repeat("x", studioResponseLimit-2))
		_, _ = io.WriteString(w, `"`)
	}), func(h *Handler) { h.studio.writeTimeout = 100 * time.Millisecond })
	browser := studioBrowser(t, f)
	req, _ := http.NewRequestWithContext(f.ctx, "GET", f.root.URL+"/studio/catalog", nil)
	for name, value := range browser {
		req.Header.Set(name, value)
	}
	response, err := f.root.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("initial response: %d", response.StatusCode)
	}
	// Keep the first response open without reading its 32 MiB body. The OS
	// receive window fills, so the dispatcher must expire the downstream write
	// before another request from this account can reach the worker.
	deadline := time.Now().Add(3 * time.Second)
	for {
		status, _ := authStatus(t, f, "GET", "/studio/catalog", nil, browser)
		if status == 200 {
			break
		}
		if status != 429 || time.Now().After(deadline) {
			t.Fatalf("stalled reader retained capacity: %d", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStudioRequestBoundsAndAdmission(t *testing.T) {
	var calls atomic.Int32
	f := studioUnixFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		studioJSON(w, 200, map[string]any{"diagnostics": []any{}})
	}))
	browser := studioBrowser(t, f)
	for _, route := range []struct {
		path  string
		limit int
	}{{"/studio/validate", studioWorkflowLimit}, {"/studio/build", studioWorkflowLimit}, {"/studio/experiments/validate", studioExperimentLimit}, {"/studio/experiments/build", studioExperimentLimit}} {
		for _, chunked := range []bool{false, true} {
			for _, extra := range []int{0, 1} {
				data := bytes.Repeat([]byte(" "), route.limit+extra)
				var reader io.Reader = bytes.NewReader(data)
				if chunked {
					reader = io.MultiReader(reader)
				}
				req, _ := http.NewRequestWithContext(f.ctx, "POST", f.root.URL+route.path, reader)
				req.Header.Set("Content-Type", "application/json")
				for k, v := range browser {
					req.Header.Set(k, v)
				}
				response, err := f.root.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(response.Body)
				_ = response.Body.Close()
				want := 200
				if extra != 0 {
					want = 413
				}
				if response.StatusCode != want {
					t.Fatalf("%s chunked=%v size=%d: %d %s", route.path, chunked, len(data), response.StatusCode, body)
				}
			}
		}
	}
	if calls.Load() != 8 {
		t.Fatalf("oversized body reached worker: %d calls", calls.Load())
	}
	for _, content := range []string{"text/plain", "application/json"} {
		headers := map[string]string{"Cookie": browser["Cookie"], csrfHeaderName: browser[csrfHeaderName], "Content-Type": content}
		if content == "application/json" {
			headers["Content-Encoding"] = "gzip"
		}
		if status, _ := authStatus(t, f, "POST", "/studio/build", []byte(`{}`), headers); status != 415 {
			t.Fatalf("unsupported media type: %d", status)
		}
	}
	limits := config.DefaultAdmissionConfig()
	limits.Account.RequestsPerMinute = 1
	admissionFixture := studioUnixFixtureConfigured(t, studio.NewWorkerHandler(nil), func(d *dispatcher.Dispatcher) error {
		return d.ConfigureDataLimits(limits, config.RetentionConfig{})
	})
	fresh := studioBrowser(t, admissionFixture)
	if status, _ := authStatus(t, admissionFixture, "POST", "/studio/validate", []byte(`{}`), fresh); status != 200 {
		t.Fatalf("first admission: %d", status)
	}
	status, code := authStatus(t, admissionFixture, "POST", "/studio/build", []byte(`{}`), fresh)
	if status != 429 || code != CodeAccountQuota {
		t.Fatalf("account admission bypassed: %d %s", status, code)
	}
}

func TestStudioUnavailableAndWorkerResponseBounds(t *testing.T) {
	for _, cfg := range []config.StudioConfig{{}, {SocketPath: filepath.Join(t.TempDir(), "absent.sock")}} {
		f := ccNewFixtureWith(t, Studio(cfg))
		browser := studioBrowser(t, f)
		status, code := authStatus(t, f, "GET", "/studio/catalog", nil, browser)
		if status != 503 || code != CodeUnavailable {
			t.Fatalf("unavailable: %d %s", status, code)
		}
	}
	for _, kind := range []string{"declared oversized", "chunked oversized", "invalid json", "redirect", "wrong content type", "busy"} {
		t.Run(kind, func(t *testing.T) {
			f := studioUnixFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch kind {
				case "declared oversized":
					w.Header().Set("Content-Length", fmt.Sprint(studioResponseLimit+1))
					w.WriteHeader(200)
				case "chunked oversized":
					w.(http.Flusher).Flush()
					_, _ = io.CopyN(w, strings.NewReader(strings.Repeat(" ", studioResponseLimit+1)), studioResponseLimit+1)
				case "invalid json":
					_, _ = w.Write([]byte("not json"))
				case "redirect":
					w.Header().Set("Location", "/studio/catalog")
					w.WriteHeader(302)
				case "wrong content type":
					w.Header().Set("Content-Type", "text/html")
					_, _ = w.Write([]byte(`{}`))
				case "busy":
					w.Header().Set("Retry-After", "9999")
					studioJSON(w, 429, map[string]string{"error": "busy"})
				}
			}))
			status, code, _, response := authRequest(t, f, "GET", "/studio/catalog", nil, studioBrowser(t, f))
			if kind == "busy" {
				if status != 429 || response.Header.Get("Retry-After") != "1" {
					t.Fatalf("worker busy: %d %v", status, response.Header)
				}
			} else if status != 502 || code != CodeUnavailable {
				t.Fatalf("invalid upstream response: %d %s", status, code)
			}
		})
	}
}

func TestStudioCapacityCancellationAndTimeout(t *testing.T) {
	entered := make(chan struct{}, studioConcurrentRequests)
	canceled := make(chan struct{}, studioConcurrentRequests)
	f := studioUnixFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Method == http.MethodGet {
			studioJSON(w, 200, map[string]any{"diagnostics": []any{}})
			return
		}
		entered <- struct{}{}
		<-r.Context().Done()
		canceled <- struct{}{}
	}))
	accounts := make([]map[string]string, studioConcurrentRequests+1)
	for i := range accounts {
		accounts[i] = studioBrowser(t, f)
	}
	var cancels []context.CancelFunc
	results := make(chan error, studioConcurrentRequests)
	for i := 0; i < studioConcurrentRequests; i++ {
		ctx, cancel := context.WithCancel(f.ctx)
		cancels = append(cancels, cancel)
		t.Cleanup(cancel)
		req, _ := http.NewRequestWithContext(ctx, "POST", f.root.URL+"/studio/build", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range accounts[i] {
			req.Header.Set(k, v)
		}
		go func() {
			response, err := f.root.Client().Do(req)
			if response != nil {
				_ = response.Body.Close()
			}
			results <- err
		}()
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("worker did not receive request")
		}
		if i == 0 {
			status, _, _, response := authRequest(t, f, "POST", "/studio/validate", []byte(`{}`), accounts[0])
			if status != 429 || response.Header.Get("Retry-After") != "1" {
				t.Fatalf("per-account capacity: %d", status)
			}
		}
	}
	start := time.Now()
	status, _ := authStatus(t, f, "POST", "/studio/build", []byte(`{}`), accounts[studioConcurrentRequests])
	if status != 429 || time.Since(start) > time.Second {
		t.Fatalf("global capacity queued: status=%d duration=%s", status, time.Since(start))
	}
	for _, cancel := range cancels {
		cancel()
	}
	for range cancels {
		select {
		case <-canceled:
		case <-time.After(3 * time.Second):
			t.Fatal("browser cancellation did not reach Unix worker")
		}
		select {
		case <-results:
		case <-time.After(3 * time.Second):
			t.Fatal("browser cancellation did not finish")
		}
	}
	// Every canceled account must be able to use the released slot again.
	for _, account := range accounts {
		status, _ := authStatus(t, f, "GET", "/studio/catalog", nil, account)
		if status != 200 {
			t.Fatalf("cancellation did not release capacity: %d", status)
		}
	}
	// A short test deadline proves server-side timeouts cancel the worker too.
	deadlineWorkerCanceled := make(chan struct{})
	timeoutFixture := studioUnixFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
		close(deadlineWorkerCanceled)
	}), func(h *Handler) { h.studio.timeout = 30 * time.Millisecond })
	status, code := authStatus(t, timeoutFixture, "POST", "/studio/build", []byte(`{}`), studioBrowser(t, timeoutFixture))
	if status != 504 || code != CodeUnavailable {
		t.Fatalf("worker timeout: %d %s", status, code)
	}
	select {
	case <-deadlineWorkerCanceled:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout did not cancel worker")
	}
}
