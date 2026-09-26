package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// countingTransport tracks response bodies that have not been closed.
type countingTransport struct {
	next  http.RoundTripper
	open  atomic.Int32
	total atomic.Int32
	// responded, when set, receives a signal once response headers have
	// reached the client, so a test can cancel during the body read.
	responded chan struct{}
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.next.RoundTrip(r)
	if resp != nil && resp.Body != nil {
		c.open.Add(1)
		c.total.Add(1)
		resp.Body = &countedBody{ReadCloser: resp.Body, open: &c.open}
		if c.responded != nil {
			select {
			case c.responded <- struct{}{}:
			default:
			}
		}
	}
	return resp, err
}

// newCountingClient returns an http.Client whose transport counts bodies and
// signals received responses.
func newCountingClient(t *testing.T) (*http.Client, *countingTransport) {
	t.Helper()
	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	counting := &countingTransport{next: tr, responded: make(chan struct{}, 1)}
	return &http.Client{Transport: counting}, counting
}

type countedBody struct {
	io.ReadCloser
	open *atomic.Int32
	once sync.Once
}

func (b *countedBody) Close() error {
	b.once.Do(func() { b.open.Add(-1) })
	return b.ReadCloser.Close()
}

type fixtureRoundTripper func(*http.Request) (*http.Response, error)

func (f fixtureRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fixtureResponseError struct{ message string }

func (e *fixtureResponseError) Error() string { return e.message }

type fixtureFailingReader struct {
	beforeRead func()
	err        error
}

func (r fixtureFailingReader) Read([]byte) (int, error) {
	if r.beforeRead != nil {
		r.beforeRead()
	}
	return 0, r.err
}

// exerciseAll calls every route once and reports the expected
// method/path pairs in call order.
func exerciseAll(t *testing.T, c *Client, prefix string) [][2]string {
	t.Helper()
	ctx := testContext(t)
	if _, err := c.Nodes(ctx); err != nil {
		t.Fatalf("Nodes: %v", err)
	}
	if _, err := c.Status(ctx, fixtureID); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if _, err := c.Logs(ctx, fixtureID, LogOptions{}); err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if err := c.Cancel(ctx, fixtureID, fixtureExecutor); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if _, err := c.Version(ctx); err != nil {
		t.Fatalf("Version: %v", err)
	}
	if _, err := c.SubmitTEST(ctx, sampleBatch(t)); err != nil {
		t.Fatalf("SubmitTEST: %v", err)
	}
	return [][2]string{
		{"GET", prefix + "/executors"},
		{"GET", prefix + "/debuglet/" + fixtureID + "/state"},
		{"GET", prefix + "/debuglet/" + fixtureID + "/logs"},
		{"DELETE", prefix + "/debuglet"},
		{"GET", prefix + "/version"},
		{"PUT", prefix + "/payment/intent"},
		{"PUT", prefix + "/debuglet"},
	}
}

func TestClientTransport(t *testing.T) {
	t.Run("known keys in malformed HTTP responses", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			key      string
			response string
		}{
			{"status", "wire-secret-status", "HTTP/1.1 wire-secret-status Invalid\r\n\r\n"},
			{"header", "wire-secret-\"quoted\"-\\-é", "HTTP/1.1 200 OK\r\nX-wire-secret-\"quoted\"-\\-é invalid: value\r\n\r\n"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newFakeServer(t, "/api")
				f.defaults()
				f.handle("PUT /payment/intent", intentHandler(fixtureTx, tc.key))
				finished := make(chan struct{})
				f.handle("PUT /debuglet", func(w http.ResponseWriter, r *http.Request) {
					defer close(finished)
					// Consume the entire submission before sending malformed wire
					// bytes, so this tests response parsing after one complete PUT.
					if _, err := io.Copy(io.Discard, r.Body); err != nil {
						t.Errorf("consume submission: %v", err)
						return
					}
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Errorf("hijack: %v", err)
						return
					}
					defer conn.Close()
					if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
						t.Errorf("connection deadline: %v", err)
						return
					}
					if _, err := io.WriteString(conn, tc.response); err != nil {
						t.Errorf("write malformed response: %v", err)
					}
				})
				_, err := f.client(t, Options{}).SubmitTEST(testContext(t), sampleBatch(t))
				select {
				case <-finished:
				case <-time.After(2 * time.Second):
					t.Fatal("malformed-response handler did not finish")
				}
				se := asSubmissionError(t, err)
				if se.Stage != "submit" || se.TransactionID != fixtureTx || !se.OutcomeUnknown {
					t.Fatalf("malformed response classification: %v", err)
				}
				for _, diagnostic := range []string{err.Error(), se.Err.Error()} {
					if strings.Contains(diagnostic, "wire-secret") || !strings.Contains(diagnostic, "[redacted]") || !strings.Contains(diagnostic, "PUT /api/debuglet") {
						t.Fatal("HTTP parser diagnostic exposed a known key or lost its route")
					}
				}
				var original *url.Error
				if !errors.As(err, &original) || !strings.Contains(original.Error(), "wire-secret") {
					t.Fatal("original transport error is not available through errors.As")
				}
				if f.count("PUT", "/api/payment/intent") != 1 || f.count("PUT", "/api/debuglet") != 1 {
					t.Fatal("malformed response caused an extra attempt")
				}
			})
		}
	})

	t.Run("known keys in typed transport and read failures", func(t *testing.T) {
		const key = "transport-secret-\"\x01\n<&>é"
		keyJSON, err := json.Marshal(key)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name     string
			status   int // Zero returns a transport error before a response.
			message  string
			cancel   bool
			deadline bool
		}{
			{"transport raw", 0, key, false, false},
			{"transport Go quoted", 0, strconv.Quote(key), false, false},
			{"read JSON quoted", 200, string(keyJSON), false, false},
			{"read ASCII quoted", 200, strconv.QuoteToASCII(key), false, false},
			{"read canceled", 200, key, true, false},
			{"error read canceled", 503, strconv.Quote(key), true, false},
			{"transport canceled", 0, key, true, false},
			{"transport deadline", 0, key, false, true},
			{"read deadline", 200, key, false, true},
			{"error read deadline", 503, key, false, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(testContext(t))
				defer cancel()
				failure := &fixtureResponseError{message: "fixture response failure: " + tc.message}
				var open atomic.Int32
				intentAttempts, submitAttempts := 0, 0
				response := func(status int, body io.Reader) *http.Response {
					open.Add(1)
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: &countedBody{ReadCloser: io.NopCloser(body), open: &open}}
				}
				transport := fixtureRoundTripper(func(r *http.Request) (*http.Response, error) {
					defer r.Body.Close()
					if _, err := io.Copy(io.Discard, r.Body); err != nil {
						return nil, err
					}
					if r.URL.Path == "/api/payment/intent" {
						intentAttempts++
						body := `{"method":"TEST","intent":{"transaction_id":"` + fixtureTx + `","auth_key":` + string(keyJSON) + `}}`
						return response(http.StatusOK, strings.NewReader(body)), nil
					}
					submitAttempts++
					trigger := func() {
						if tc.cancel {
							cancel()
						}
						if tc.deadline {
							<-r.Context().Done()
						}
					}
					if tc.status == 0 {
						trigger()
						return nil, failure
					}
					return response(tc.status, fixtureFailingReader{beforeRead: trigger, err: failure}), nil
				})
				c, err := New("http://127.0.0.1/api", Options{HTTPClient: &http.Client{Transport: transport}, RequestTimeout: 100 * time.Millisecond})
				if err != nil {
					t.Fatal(err)
				}
				_, err = c.SubmitTEST(ctx, sampleBatch(t))
				se := asSubmissionError(t, err)
				if se.Stage != "submit" || se.TransactionID != fixtureTx || !se.OutcomeUnknown {
					t.Fatalf("typed failure classification: %v", err)
				}
				for _, diagnostic := range []string{err.Error(), se.Err.Error()} {
					if strings.Contains(diagnostic, "transport-secret") || !strings.Contains(diagnostic, "[redacted]") || !strings.Contains(diagnostic, "PUT /api/debuglet") {
						t.Fatal("typed failure diagnostic exposed a key or lost its route")
					}
				}
				var original *fixtureResponseError
				if !errors.As(err, &original) || original != failure || !errors.Is(err, failure) {
					t.Fatal("sanitizing a diagnostic broke the original error chain")
				}
				if tc.cancel && !errors.Is(err, context.Canceled) {
					t.Fatal("context cancellation was lost")
				}
				if tc.deadline && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("request deadline was lost")
				}
				if open.Load() != 0 || intentAttempts != 1 || submitAttempts != 1 {
					t.Fatal("typed failure left a response open or caused an extra attempt")
				}
			})
		}
	})

	t.Run("base path preserved on every route", func(t *testing.T) {
		for _, prefix := range []string{"", "/api", "/v1/dispatch"} {
			t.Run("prefix="+prefix, func(t *testing.T) {
				f := newFakeServer(t, prefix)
				f.defaults()
				c := f.client(t, Options{})
				want := exerciseAll(t, c, prefix)
				reqs := f.requests()
				if len(reqs) != len(want) {
					t.Fatalf("%d requests, want %d", len(reqs), len(want))
				}
				for i, w := range want {
					if reqs[i].Method != w[0] || reqs[i].Path != w[1] {
						t.Fatalf("request %d: %s %s, want %s %s", i, reqs[i].Method, reqs[i].Path, w[0], w[1])
					}
				}
				if q := reqs[2].Query; q != "after=0&limit=100" {
					t.Fatalf("logs query %q", q)
				}
				// A trailing slash on the endpoint normalises to the same prefix.
				c2, err := New(f.srv.URL+prefix+"/", Options{})
				if err != nil {
					t.Fatal(err)
				}
				if c2.basePath != prefix || c.basePath != prefix {
					t.Fatalf("basePath %q / %q, want %q", c.basePath, c2.basePath, prefix)
				}
				f.reset()
				if _, err := c2.Version(testContext(t)); err != nil {
					t.Fatal(err)
				}
				if got := f.requests()[0].Path; got != prefix+"/version" {
					t.Fatalf("trailing-slash endpoint requested %q", got)
				}
			})
		}
	})

	t.Run("malicious ids never reach the server", func(t *testing.T) {
		f := newFakeServer(t, "/api")
		f.defaults()
		c := f.client(t, Options{})
		ids := []string{
			"", " ", "..", "../version", "a/b", "%2F", "%2e%2e",
			fixtureID + "/../x", fixtureID + "%2F..%2Fx", fixtureID + "/state", "/" + fixtureID,
			fixtureID + " ", fixtureID + "\n", " " + fixtureID,
			strings.ReplaceAll(fixtureID, "-", ""), "{" + fixtureID + "}", "g" + fixtureID[1:],
			"00000000-0000-0000-0000-000000000000", fixtureID[:35], fixtureID + "0",
		}
		ctx := testContext(t)
		for _, id := range ids {
			if _, err := c.Status(ctx, id); err == nil {
				t.Errorf("Status accepted %q", id)
			}
			if _, err := c.Logs(ctx, id, LogOptions{}); err == nil {
				t.Errorf("Logs accepted %q", id)
			}
			if err := c.Cancel(ctx, id, fixtureExecutor); err == nil {
				t.Errorf("Cancel accepted %q", id)
			}
		}
		if err := c.Cancel(ctx, fixtureID, " "); err == nil {
			t.Errorf("Cancel accepted a blank executor id")
		}
		if n := len(f.requests()); n != 0 {
			t.Fatalf("%d requests reached the server", n)
		}
		// Upper-case hex is refused locally: the dispatcher accepts only the
		// lowercase spelling.
		if _, err := c.Status(ctx, strings.ToUpper(fixtureID)); err == nil {
			t.Fatal("upper-case id accepted")
		}
		if n := len(f.requests()); n != 0 {
			t.Fatalf("an upper-case id reached the server in %d requests", n)
		}
	})

	t.Run("endpoint validation", func(t *testing.T) {
		accept := []string{
			"http://127.0.0.1:9000", "http://127.0.0.1", "http://127.1.2.3/api", "http://[::1]:9000/api/",
			"https://127.0.0.1:9000", "https://example.com", "https://example.com:8443/api",
			"https://localhost:8443/api", "https://[::1]/a/b/c",
		}
		for _, endpoint := range accept {
			if _, err := New(endpoint, Options{}); err != nil {
				t.Errorf("New(%q) rejected: %v", endpoint, err)
			}
		}
		reject := map[string]string{
			"":                                  "absolute",
			"   ":                               "absolute",
			"127.0.0.1:9000":                    "valid URL",
			"//127.0.0.1:9000":                  "absolute",
			"/api":                              "absolute",
			"http://":                           "host is required",
			"http:///api":                       "host is required",
			"mailto:x@example.com":              "absolute",
			"ftp://127.0.0.1":                   "unsupported scheme",
			"ws://127.0.0.1":                    "unsupported scheme",
			"http://example.com":                "plaintext http",
			"http://localhost:9000":             "plaintext http",
			"http://10.0.0.1:9000":              "plaintext http",
			"http://[fe80::1]:9000":             "plaintext http",
			"http://user:secret@127.0.0.1:9000": "userinfo",
			"https://user@example.com":          "userinfo",
			"http://127.0.0.1:9000?x=1":         "query",
			"http://127.0.0.1:9000/?":           "query",
			"http://127.0.0.1:9000/#frag":       "fragment",
			"http://127.0.0.1:9000/api//v1":     "invalid base path segment",
			"http://127.0.0.1:9000//api":        "invalid base path segment",
			"http://127.0.0.1:9000/api/.":       "invalid base path segment",
			"http://127.0.0.1:9000/../api":      "invalid base path segment",
			"http://127.0.0.1:9000/api//":       "invalid base path segment",
			"http://127.0.0.1:port":             "valid URL",
		}
		for endpoint, want := range reject {
			_, err := New(endpoint, Options{})
			if err == nil {
				t.Errorf("New(%q) accepted", endpoint)
				continue
			}
			if !strings.Contains(err.Error(), want) {
				t.Errorf("New(%q) = %q, want it to mention %q", endpoint, err, want)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Errorf("New(%q) echoed credentials: %q", endpoint, err)
			}
		}
		if _, err := New("http://127.0.0.1:9000", Options{RequestTimeout: -time.Second}); err == nil || !strings.Contains(err.Error(), "negative request timeout") {
			t.Fatalf("negative timeout: %v", err)
		}
		c, err := New("https://example.com/api/", Options{})
		if err != nil {
			t.Fatal(err)
		}
		if c.timeout != 10*time.Second || c.basePath != "/api" || c.origin != "https://example.com" || c.loopback {
			t.Fatalf("client = %+v", c)
		}
		c, err = New("http://127.0.0.1:9000/", Options{RequestTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if c.timeout != time.Second || c.basePath != "" || !c.loopback {
			t.Fatalf("client = %+v", c)
		}
	})

	t.Run("remote TEST guard, supplied client cloning and TLS", func(t *testing.T) {
		f := newFakeTLSServer(t, "/api")
		f.defaults()
		addr := f.srv.Listener.Addr().String()
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal(err)
		}
		// A transport trusting the httptest certificate, dialing the server
		// for the certificate's DNS name example.com.
		base := f.srv.Client().Transport.(*http.Transport).Clone()
		base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}
		followAll := func(*http.Request, []*http.Request) error { return nil }
		caller := &http.Client{Transport: base, CheckRedirect: followAll, Timeout: 30 * time.Second}
		endpoint := "https://example.com:" + port + "/api"
		ctx := testContext(t)

		c, err := New(endpoint, Options{HTTPClient: caller})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.SubmitTEST(ctx, sampleBatch(t))
		se := asSubmissionError(t, err)
		if se.Stage != "intent" || se.OutcomeUnknown || se.TransactionID != "" || !errors.Is(err, errRemoteTEST) {
			t.Fatalf("remote TEST guard: %+v", se)
		}
		if n := len(f.requests()); n != 0 {
			t.Fatalf("guarded submission sent %d requests", n)
		}
		if _, err := c.Nodes(ctx); err != nil {
			t.Fatalf("read-only call over TLS: %v", err)
		}
		allowed, err := New(endpoint, Options{HTTPClient: caller, AllowRemoteTEST: true})
		if err != nil {
			t.Fatal(err)
		}
		sub, err := allowed.SubmitTEST(ctx, sampleBatch(t))
		if err != nil {
			t.Fatalf("AllowRemoteTEST submission: %v", err)
		}
		if sub.TransactionID != fixtureTx {
			t.Fatalf("submission %+v", sub)
		}
		if got := f.requests()[0].Header.Get("Host"); got != "" && got != "example.com:"+port {
			t.Fatalf("Host header %q", got)
		}
		// The caller's client is untouched ...
		if caller.Transport != http.RoundTripper(base) || caller.Timeout != 30*time.Second || caller.Jar != nil {
			t.Fatalf("caller client mutated: %+v", caller)
		}
		if reflect.ValueOf(caller.CheckRedirect).Pointer() != reflect.ValueOf(followAll).Pointer() {
			t.Fatalf("caller CheckRedirect replaced")
		}
		// ... while the clone rejects redirects even though the caller follows them.
		f.handle("GET /version", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/api/executors", http.StatusFound)
		})
		f.reset()
		_, err = c.Version(ctx)
		he := asHTTPError(t, err)
		if he.StatusCode != http.StatusFound || he.Method != "GET" || he.Path != "/api/version" {
			t.Fatalf("redirect result %+v", he)
		}
		if f.count("GET", "/api/executors") != 0 {
			t.Fatalf("redirect was followed")
		}
		// Plain http to the same non-loopback name is refused before any request.
		if _, err := New("http://example.com:"+port+"/api", Options{HTTPClient: caller}); err == nil {
			t.Fatalf("plaintext to example.com accepted")
		}
		if _, err := New("http://localhost:"+port+"/api", Options{HTTPClient: caller}); err == nil {
			t.Fatalf("plaintext to localhost accepted")
		}
	})

	t.Run("redirects are rejected", func(t *testing.T) {
		f := newFakeServer(t, "/api")
		f.defaults()
		f.handle("GET /executors", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/api/version", http.StatusFound)
		})
		f.handle("PUT /debuglet", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/api/version", http.StatusTemporaryRedirect)
		})
		c := f.client(t, Options{})
		ctx := testContext(t)
		_, err := c.Nodes(ctx)
		he := asHTTPError(t, err)
		if he.StatusCode != http.StatusFound || he.Path != "/api/executors" {
			t.Fatalf("redirect result %+v", he)
		}
		_, err = c.SubmitTEST(ctx, sampleBatch(t))
		se := asSubmissionError(t, err)
		if se.Stage != "submit" || se.TransactionID != fixtureTx || se.OutcomeUnknown || asHTTPError(t, err).StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("submit redirect: %+v", se)
		}
		if f.count("GET", "/api/version") != 0 {
			t.Fatalf("redirect target was requested")
		}
	})

	t.Run("cancellation and timeouts", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			stream bool
		}{{"headers", false}, {"body", true}} {
			t.Run("cancel during "+tc.name, func(t *testing.T) {
				f := newFakeServer(t, "")
				release := make(chan struct{})
				defer close(release)
				started := make(chan struct{}, 1)
				f.handle("GET /executors", blockingHandler(started, release, tc.stream))
				hc, counting := newCountingClient(t)
				c := f.client(t, Options{HTTPClient: hc})
				ctx, cancel := context.WithCancel(testContext(t))
				defer cancel()
				// Cancel once the handler is blocked (headers case) or once the
				// client holds the response and is reading its body (body case).
				trigger := started
				if tc.stream {
					trigger = counting.responded
				}
				go func() {
					<-trigger
					cancel()
				}()
				_, err := c.Nodes(ctx)
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("expected context.Canceled, got %v", err)
				}
				if tc.stream && counting.total.Load() != 1 {
					t.Fatalf("response not received before cancellation")
				}
				if open := counting.open.Load(); open != 0 {
					t.Fatalf("%d bodies left open", open)
				}
			})
			t.Run("timeout during "+tc.name, func(t *testing.T) {
				f := newFakeServer(t, "")
				release := make(chan struct{})
				defer close(release)
				started := make(chan struct{}, 1)
				f.handle("GET /executors", blockingHandler(started, release, tc.stream))
				c := f.client(t, Options{RequestTimeout: 100 * time.Millisecond})
				begin := time.Now()
				_, err := c.Nodes(testContext(t))
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("expected context.DeadlineExceeded, got %v", err)
				}
				if elapsed := time.Since(begin); elapsed > 10*time.Second {
					t.Fatalf("timeout took %v", elapsed)
				}
				select {
				case <-started:
				default:
					t.Fatalf("handler never started")
				}
			})
		}
		t.Run("cancellation during error body preserves context and closes it", func(t *testing.T) {
			f := newFakeServer(t, "/api")
			release := make(chan struct{})
			defer close(release)
			f.handle("GET /version", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"auth_key":"cancelled-body-dummy-key","message":"`)
				w.(http.Flusher).Flush()
				select {
				case <-release:
				case <-r.Context().Done():
				}
			})
			hc, counting := newCountingClient(t)
			c := f.client(t, Options{HTTPClient: hc})
			ctx, cancel := context.WithCancel(testContext(t))
			defer cancel()
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				select {
				case <-counting.responded:
					cancel()
				case <-ctx.Done():
				}
			}()
			_, err := c.Version(ctx)
			cancel()
			<-joined
			if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "GET /api/version") || strings.Contains(err.Error(), "cancelled-body-dummy-key") {
				t.Fatalf("unsafe or incorrectly wrapped cancellation: %v", err)
			}
			if counting.total.Load() != 1 || counting.open.Load() != 0 || len(f.requests()) != 1 {
				t.Fatal("error response was not closed or request was retried")
			}
		})
		t.Run("already cancelled context sends nothing", func(t *testing.T) {
			f := newFakeServer(t, "")
			f.defaults()
			c := f.client(t, Options{})
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := c.Nodes(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("Nodes: %v", err)
			}
			_, err := c.SubmitTEST(ctx, sampleBatch(t))
			se := asSubmissionError(t, err)
			if !errors.Is(err, context.Canceled) || se.OutcomeUnknown || se.Stage != "intent" {
				t.Fatalf("SubmitTEST: %+v", se)
			}
			if n := len(f.requests()); n != 0 {
				t.Fatalf("%d requests sent on a cancelled context", n)
			}
		})
		t.Run("submit stage transport failure is unknown, cancelled before submit is not", func(t *testing.T) {
			f := newFakeServer(t, "")
			f.defaults()
			release := make(chan struct{})
			defer close(release)
			started := make(chan struct{}, 1)
			f.handle("PUT /debuglet", blockingHandler(started, release, false))
			c := f.client(t, Options{})
			ctx, cancel := context.WithCancel(testContext(t))
			defer cancel()
			go func() {
				<-started
				cancel()
			}()
			_, err := c.SubmitTEST(ctx, sampleBatch(t))
			se := asSubmissionError(t, err)
			if !errors.Is(err, context.Canceled) || se.Stage != "submit" || se.TransactionID != fixtureTx || !se.OutcomeUnknown {
				t.Fatalf("SubmitTEST: %+v", se)
			}
		})
	})

	t.Run("response bodies are always closed", func(t *testing.T) {
		f := newFakeServer(t, "/api")
		f.defaults()
		hc, counting := newCountingClient(t)
		c := f.client(t, Options{HTTPClient: hc})
		ctx := testContext(t)
		check := func(step string) {
			t.Helper()
			if open := counting.open.Load(); open != 0 {
				t.Fatalf("%s: %d response bodies left open", step, open)
			}
		}
		if _, err := c.Nodes(ctx); err != nil {
			t.Fatal(err)
		}
		check("success")
		f.handle("GET /debuglet/{id}/state", jsonHandler(http.StatusNotFound, `{"message":"debuglet not found"}`))
		if _, err := c.Status(ctx, fixtureID); err == nil {
			t.Fatal("expected 404")
		}
		check("error status")
		f.handle("GET /version", jsonHandler(http.StatusOK, `"`+strings.Repeat("a", maxSuccessBody)+`"`))
		if _, err := c.Version(ctx); err == nil {
			t.Fatal("expected oversized error")
		}
		check("oversized")
		f.handle("GET /version", jsonHandler(http.StatusOK, `{} {}`))
		if _, err := c.Version(ctx); err == nil {
			t.Fatal("expected malformed error")
		}
		check("malformed")
		f.handle("GET /version", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/api/executors", http.StatusFound)
		})
		if _, err := c.Version(ctx); err == nil {
			t.Fatal("expected redirect error")
		}
		check("redirect")
		if err := c.Cancel(ctx, fixtureID, fixtureExecutor); err != nil {
			t.Fatal(err)
		}
		check("no content")
		release := make(chan struct{})
		started := make(chan struct{}, 1)
		f.handle("GET /executors", blockingHandler(started, release, true))
		// Drop the stale signal from the earlier responses, then cancel once
		// the streaming response has been received.
		select {
		case <-counting.responded:
		default:
		}
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			<-counting.responded
			cancel()
		}()
		if _, err := c.Nodes(cctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("streaming cancel: %v", err)
		}
		close(release)
		check("cancelled body")
		if counting.total.Load() != 7 {
			t.Fatalf("%d responses observed, want 7", counting.total.Load())
		}
	})

	t.Run("body size bounds", func(t *testing.T) {
		f := newFakeServer(t, "")
		hc, counting := newCountingClient(t)
		c := f.client(t, Options{HTTPClient: hc})
		ctx := testContext(t)
		// Exactly 4 MiB of valid JSON is accepted.
		exact := `{"version":"` + strings.Repeat("v", maxSuccessBody-14) + `"}`
		if len(exact) != maxSuccessBody {
			t.Fatalf("fixture is %d bytes", len(exact))
		}
		f.handle("GET /version", jsonHandler(http.StatusOK, exact))
		v, err := c.Version(ctx)
		if err != nil || len(v.Version) != maxSuccessBody-14 {
			t.Fatalf("exact-size body: %v", err)
		}
		// One byte more is a clear size error, not a truncated decode.
		f.handle("GET /version", jsonHandler(http.StatusOK, `{"version":"`+strings.Repeat("v", maxSuccessBody-13)+`"}`))
		_, err = c.Version(ctx)
		if err == nil || !strings.Contains(err.Error(), "exceeds 4 MiB") {
			t.Fatalf("oversized body: %v", err)
		}
		asProtocolError(t, err)
		// Error bodies are bounded to 8 KiB.
		f.handle("GET /version", textHandler(http.StatusBadGateway, strings.Repeat("x", maxErrorBody+4096)))
		_, err = c.Version(ctx)
		he := asHTTPError(t, err)
		if he.StatusCode != http.StatusBadGateway || len(he.Message) != maxErrorBody || strings.Trim(he.Message, "x") != "" {
			t.Fatalf("bounded error message: status %d, %d bytes", he.StatusCode, len(he.Message))
		}
		// Exactly 8 KiB of a safe JSON error retains its message.
		exactError := `{"message":"` + strings.Repeat("m", maxErrorBody-len(`{"message":""}`)) + `"}`
		f.handle("GET /version", jsonHandler(http.StatusBadGateway, exactError))
		_, err = c.Version(ctx)
		he = asHTTPError(t, err)
		if len(exactError) != maxErrorBody || len(he.Message) != maxErrorBody-len(`{"message":""}`) || strings.Trim(he.Message, "m") != "" {
			t.Fatal("exact-limit JSON error was not retained")
		}
		// An incomplete transfer is unsafe even if the bytes read happen to
		// form a complete JSON object.
		f.handle("GET /version", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1024")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, `{"message":"incomplete-dummy-secret"}`)
		})
		_, err = c.Version(ctx)
		if asHTTPError(t, err).Message != omittedResponseDiagnostic || strings.Contains(err.Error(), "incomplete-dummy-secret") {
			t.Fatal("incomplete error transfer exposed its body")
		}
		// A JSON-shaped error truncated by the bound must never become a raw
		// envelope diagnostic, even if its prefix is a complete JSON value.
		const secret = "bounded-dummy-auth-key"
		for _, body := range []string{
			`{"auth_key":"` + secret + `","message":"` + strings.Repeat("x", maxErrorBody) + `"}`,
			`[{"auth_key":"` + secret + `"},"` + strings.Repeat("x", maxErrorBody) + `"]`,
			`"` + secret + strings.Repeat("x", maxErrorBody) + `"`,
			`{"message":"` + secret + `"}` + strings.Repeat(" ", maxErrorBody) + `{"auth_key":"` + secret + `"}`,
		} {
			f.handle("GET /version", jsonHandler(http.StatusBadGateway, body))
			_, err := c.Version(ctx)
			he := asHTTPError(t, err)
			if he.Message != omittedResponseDiagnostic || strings.Contains(err.Error(), secret) {
				t.Fatal("truncated JSON-shaped body exposed an unsafe diagnostic")
			}
		}
		// Sanitization can grow short keys and invalid UTF-8. The final public
		// message remains bounded and does not split a UTF-8 character.
		f.handle("GET /version", jsonHandler(http.StatusBadGateway, `{"auth_key":"k","message":"`+strings.Repeat("k", maxErrorBody/2)+`"}`))
		_, err = c.Version(ctx)
		he = asHTTPError(t, err)
		if len(he.Message) > maxErrorBody || strings.Contains(he.Message, "k") || !strings.Contains(he.Message, "[redacted]") {
			t.Fatal("expanded redaction is unsafe or unbounded")
		}
		f.handle("GET /version", textHandler(http.StatusBadGateway, strings.Repeat("\xff", maxErrorBody)))
		_, err = c.Version(ctx)
		he = asHTTPError(t, err)
		if len(he.Message) > maxErrorBody || !utf8.ValidString(he.Message) {
			t.Fatal("bounded diagnostic is not valid UTF-8")
		}
		if counting.open.Load() != 0 || counting.total.Load() != 11 {
			t.Fatalf("body bound cases observed %d responses and left %d open", counting.total.Load(), counting.open.Load())
		}
	})

	t.Run("malformed and trailing JSON", func(t *testing.T) {
		f := newFakeServer(t, "")
		c := f.client(t, Options{})
		ctx := testContext(t)
		for _, body := range []string{`{} {}`, `{"version":"x"} {}`, `{"version":"x"}x`, `{"version":"x"}]`, `{"version":`, ``, `   `, `nul`, `[]`, `"x"`, `{"version":1}`} {
			f.handle("GET /version", jsonHandler(http.StatusOK, body))
			_, err := c.Version(ctx)
			if err == nil {
				t.Errorf("body %q accepted", body)
				continue
			}
			asProtocolError(t, err)
		}
		f.handle("GET /version", jsonHandler(http.StatusOK, ` {"version":"x","unknown":{"deep":[1,2]}} `+"\n"))
		v, err := c.Version(ctx)
		if err != nil || v.Version != "x" {
			t.Fatalf("unknown fields and surrounding whitespace: %v %+v", err, v)
		}
		// Nodes: `{} {}` is rejected even though the first value would decode.
		f.handle("GET /executors", jsonHandler(http.StatusOK, `[] []`))
		if _, err := c.Nodes(ctx); err == nil {
			t.Fatalf("trailing array accepted")
		}
	})

	t.Run("http error path carries no query or body", func(t *testing.T) {
		f := newFakeServer(t, "/api")
		f.handle("GET /debuglet/{id}/logs", jsonHandler(http.StatusNotFound, `{"message":"debuglet not found"}`))
		c := f.client(t, Options{})
		_, err := c.Logs(testContext(t), fixtureID, LogOptions{After: 3, Limit: 5})
		he := asHTTPError(t, err)
		if he.Path != "/api/debuglet/"+fixtureID+"/logs" || he.Method != "GET" || he.Message != "debuglet not found" {
			t.Fatalf("%+v", he)
		}
		if strings.Contains(err.Error(), "?") || strings.Contains(err.Error(), "after=") {
			t.Fatalf("error leaks query: %v", err)
		}
		if !bytes.Equal([]byte(he.Error()), []byte("GET /api/debuglet/"+fixtureID+"/logs: status 404: debuglet not found")) {
			t.Fatalf("Error() = %q", he.Error())
		}
	})
}
