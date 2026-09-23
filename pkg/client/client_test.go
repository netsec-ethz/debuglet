package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Fixture values shared by the httptest-based tests.
const (
	fixtureTx       = "0123456789abcdef0123456789abcdef"
	fixtureID       = "a94c47e1-e09e-4ef2-a00f-e4db0eb4cdb0"
	fixtureExecutor = "fixture-executor"
	fixtureNodes    = `[{"id":"fixture-executor","ready":false,"last_seen":1700000000,"version":"fixture","tesla_delay_sec":5,"tesla_anchor_timestamp_ns":1700000000000000000,"tesla_anchor_key":"AQIDBA==","price_per_bw":0,"currency":"TEST"}]`
	fixtureState    = `{"state":"RunStateExited","error":"debuglet exited with code 7","executor_id":"fixture-executor"}`
	fixtureVersion  = `{"version":"fixture"}`
)

// recorded is one request as seen by the fake dispatcher, before routing.
type recorded struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   []byte
}

// varHandler is a swappable handler so one server can serve many cases.
type varHandler struct {
	mu sync.Mutex
	fn http.HandlerFunc
}

func (v *varHandler) set(fn http.HandlerFunc) {
	v.mu.Lock()
	v.fn = fn
	v.mu.Unlock()
}

func (v *varHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	fn := v.fn
	v.mu.Unlock()
	if fn == nil {
		http.NotFound(w, r)
		return
	}
	fn(w, r)
}

// fakeServer is an httptest dispatcher whose routes are mounted under an
// explicit prefix ("" for the root) and which records every request.
type fakeServer struct {
	t      *testing.T
	prefix string
	mux    *http.ServeMux
	srv    *httptest.Server

	mu     sync.Mutex
	routes map[string]*varHandler
	reqs   []recorded
}

func newFakeServer(t *testing.T, prefix string) *fakeServer { return startFake(t, prefix, false) }

// newFakeTLSServer is newFakeServer over TLS, for the cases about a remote
// endpoint and the caller's own transport.
func newFakeTLSServer(t *testing.T, prefix string) *fakeServer { return startFake(t, prefix, true) }

func startFake(t *testing.T, prefix string, useTLS bool) *fakeServer {
	t.Helper()
	f := &fakeServer{t: t, prefix: prefix, mux: http.NewServeMux(), routes: map[string]*varHandler{}}
	var inner http.Handler = f.mux
	if prefix != "" {
		root := http.NewServeMux()
		root.Handle(prefix+"/", http.StripPrefix(prefix, f.mux))
		root.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "outside base path", http.StatusNotFound)
		})
		inner = root
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Header: r.Header.Clone(), Body: body})
		f.mu.Unlock()
		inner.ServeHTTP(w, r)
	})
	if useTLS {
		f.srv = httptest.NewTLSServer(handler)
	} else {
		f.srv = httptest.NewServer(handler)
	}
	t.Cleanup(f.srv.Close)
	return f
}

// route returns the swappable handler for a Go 1.22 mux pattern such as
// "GET /debuglet/{id}/state" (relative to the prefix).
func (f *fakeServer) route(pattern string) *varHandler {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.routes[pattern]
	if !ok {
		v = &varHandler{}
		f.routes[pattern] = v
		f.mux.Handle(pattern, v)
	}
	return v
}

func (f *fakeServer) handle(pattern string, fn http.HandlerFunc) { f.route(pattern).set(fn) }

// defaults installs fixture-like handlers for every route.
func (f *fakeServer) defaults() {
	f.handle("PUT /payment/intent", intentHandler(fixtureTx, ""))
	f.handle("PUT /debuglet", submitHandler)
	f.handle("GET /executors", jsonHandler(http.StatusOK, fixtureNodes))
	f.handle("GET /debuglet/{id}/state", jsonHandler(http.StatusOK, fixtureState))
	f.handle("GET /debuglet/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "0" {
			jsonHandler(http.StatusOK, `{"state":"RunStateExited","after":7,"logs":[{"id":7,"timestamp":"2026-09-08T12:00:00Z","output":"AP8K"}],"has_more":true,"error":"debuglet exited with code 7"}`)(w, r)
			return
		}
		jsonHandler(http.StatusOK, fmt.Sprintf(`{"state":"RunStateExited","after":%s,"logs":null,"has_more":false,"error":"debuglet exited with code 7"}`, r.URL.Query().Get("after")))(w, r)
	})
	f.handle("DELETE /debuglet", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	f.handle("GET /version", jsonHandler(http.StatusOK, fixtureVersion))
}

func (f *fakeServer) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]recorded, len(f.reqs))
	copy(out, f.reqs)
	return out
}

func (f *fakeServer) reset() {
	f.mu.Lock()
	f.reqs = nil
	f.mu.Unlock()
}

func (f *fakeServer) count(method, path string) int {
	n := 0
	for _, r := range f.requests() {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

func (f *fakeServer) endpoint() string { return f.srv.URL + f.prefix }

func (f *fakeServer) client(t *testing.T, options Options) *Client {
	t.Helper()
	c, err := New(f.endpoint(), options)
	if err != nil {
		t.Fatalf("New(%q): %v", f.endpoint(), err)
	}
	return c
}

func jsonHandler(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func textHandler(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func intentHandler(transactionID, authKey string) http.HandlerFunc {
	body, _ := json.Marshal(map[string]any{
		"method": "TEST",
		"intent": map[string]string{"transaction_id": transactionID, "auth_key": authKey},
	})
	return jsonHandler(http.StatusOK, string(body))
}

// submitHandler returns one deterministic nonzero UUID per submitted debuglet.
func submitHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Debuglets []json.RawMessage `json:"debuglets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	ids := make([]string, len(req.Debuglets))
	for i := range ids {
		ids[i] = fmt.Sprintf("%08x-0000-4000-8000-%012x", i+1, i+1)
	}
	body, _ := json.Marshal(ids)
	jsonHandler(http.StatusOK, string(body))(w, r)
}

// hijackClose drops the connection without writing a response.
func hijackClose(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("response writer is not a hijacker")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		panic(err)
	}
	_ = conn.Close()
}

// blockingHandler optionally streams the start of a body, signals started
// and then blocks until release is closed or the request context ends.
func blockingHandler(started chan<- struct{}, release <-chan struct{}, streamBody bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if streamBody {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "[")
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
		}
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}
}

func sampleRequests() []Request {
	return []Request{{
		OrderID:    0,
		ExecutorID: fixtureExecutor,
		Args:       []string{"127.0.0.1:12345", "two words"},
		Wasm:       []byte{1, 2, 3},
		Policy: Policy{
			FloorBW:   1048576,
			CeilBW:    1048576,
			TimeoutMS: 10000,
			Addresses: []string{"127.0.0.1"},
		},
	}}
}

// sampleDebuglets is the frozen encoding of sampleRequests.
const sampleDebuglets = `[{"order_id":0,"executor_id":"fixture-executor","args":["127.0.0.1:12345","two words"],"wasm":"AQID","policy":{"floor_bw":1048576,"ceil_bw":1048576,"timeout_ms":10000,"addresses":["127.0.0.1"],"require_icmp":false,"listen_udp":false,"listen_tcp":false,"listen_scion":false}}]`

func sampleBatch(t *testing.T) *PreparedBatch {
	t.Helper()
	batch, err := Prepare(sampleRequests())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return batch
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func asSubmissionError(t *testing.T, err error) *SubmissionError {
	t.Helper()
	var se *SubmissionError
	if !errors.As(err, &se) {
		t.Fatalf("expected *SubmissionError, got %T: %v", err, err)
	}
	return se
}

func asHTTPError(t *testing.T, err error) *HTTPError {
	t.Helper()
	var he *HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("expected *HTTPError, got %T: %v", err, err)
	}
	return he
}

func asProtocolError(t *testing.T, err error) *protocolError {
	t.Helper()
	var pe *protocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *protocolError, got %T: %v", err, err)
	}
	return pe
}

// debugletsOf extracts the raw debuglets array bytes from an envelope.
func debugletsOf(t *testing.T, body []byte) []byte {
	t.Helper()
	var envelope struct {
		Debuglets json.RawMessage `json:"debuglets"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	return envelope.Debuglets
}
