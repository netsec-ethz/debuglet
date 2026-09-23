package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

// Never consult the account's real saved dispatcher while testing defaults.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "dbl-client-tests-*")
	if err != nil {
		os.Exit(1)
	}
	if err := os.Setenv("XDG_CONFIG_HOME", dir); err != nil {
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	if err := os.RemoveAll(dir); err != nil && code == 0 {
		code = 1
	}
	os.Exit(code)
}

// Fixture values shared by the CLI tests. The auth key is a sentinel that
// must never reach stdout or stderr.
const (
	fixJobID    = "a94c47e1-e09e-4ef2-a00f-e4db0eb4cdb0"
	fixTxID     = "0123456789abcdef0123456789abcdef"
	fixExecutor = "fixture-executor"
	fixSecret   = "SECRET-AUTH-KEY-DO-NOT-PRINT"
	nilUUID     = "00000000-0000-0000-0000-000000000000"
)

// recorded is one request that reached a fixture server.
type recorded struct {
	Method string
	Path   string
	Query  string
	Body   []byte
}

// fixture is an httptest server that records every request before handing
// it to the test's handler.
type fixture struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests []recorded
}

func newFixture(t *testing.T, h http.Handler) *fixture {
	t.Helper()
	f := &fixture{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		f.mu.Lock()
		f.requests = append(f.requests, recorded{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: body})
		f.mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fixture) endpoint() string { return f.server.URL }

// count returns how many recorded requests match method and path prefix.
func (f *fixture) count(method, pathPrefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r.Method == method && strings.HasPrefix(r.Path, pathPrefix) {
			n++
		}
	}
	return n
}

func (f *fixture) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// last returns the most recent request matching method and path prefix.
func (f *fixture) last(method, pathPrefix string) (recorded, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.requests) - 1; i >= 0; i-- {
		r := f.requests[i]
		if r.Method == method && strings.HasPrefix(r.Path, pathPrefix) {
			return r, true
		}
	}
	return recorded{}, false
}

// unreachableFixture fails the test if any request arrives.
func unreachableFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
}

func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// intentOK answers PUT payment/intent with the fixture transaction and the
// secret auth key.
func intentOK(w http.ResponseWriter, _ *http.Request) {
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"method": "TEST",
		"intent": map[string]string{"transaction_id": fixTxID, "auth_key": fixSecret},
	})
}

// submitOK answers PUT debuglet with the fixture job ID.
func submitOK(w http.ResponseWriter, _ *http.Request) {
	writeJSONResponse(w, http.StatusOK, []string{fixJobID})
}

// blockUntilGone parks a handler until the client abandons the request.
func blockUntilGone(w http.ResponseWriter, r *http.Request) {
	<-r.Context().Done()
	w.WriteHeader(http.StatusServiceUnavailable)
}

// runCLI invokes run with captured stdout/stderr.
func runCLI(ctx context.Context, args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(ctx, args, &out, &errb)
	return code, out.String(), errb.String()
}

// wasmFile writes a small guest binary and returns its path.
func wasmFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guest.wasm")
	if err := os.WriteFile(path, []byte("\x00asm\x01\x00\x00\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// oneJSONDocument decodes stdout as exactly one JSON object.
func oneJSONDocument(t *testing.T, stdout string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(stdout))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("stdout is not a JSON object: %v\nstdout: %q", err, stdout)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("stdout holds more than one JSON document: %q", stdout)
	}
	return doc
}

func assertNoSecret(t *testing.T, stdout, stderr string) {
	t.Helper()
	if strings.Contains(stdout, fixSecret) || strings.Contains(stderr, fixSecret) {
		t.Fatalf("auth key leaked into output\nstdout: %q\nstderr: %q", stdout, stderr)
	}
}

func assertCode(t *testing.T, got, want int, stdout, stderr string) {
	t.Helper()
	if got != want {
		t.Fatalf("exit code %d, want %d\nstdout: %q\nstderr: %q", got, want, stdout, stderr)
	}
}

// shortPoll shrinks the poll interval for the test's duration so polling
// tests are bounded by request counting, not wall-clock waits.
func shortPoll(t *testing.T) {
	t.Helper()
	previous := pollInterval
	pollInterval = time.Millisecond
	t.Cleanup(func() { pollInterval = previous })
}

// capturedClient is what a command passed to the client seam.
type capturedClient struct {
	Endpoint string
	Options  client.Options
	Calls    int
}

// captureClientOptions observes the seam and delegates to the real constructor.
func captureClientOptions(t *testing.T) *capturedClient {
	t.Helper()
	captured := &capturedClient{}
	previous := newClient
	newClient = func(endpoint string, options client.Options) (*client.Client, error) {
		captured.Endpoint = endpoint
		captured.Options = options
		captured.Calls++
		return previous(endpoint, options)
	}
	t.Cleanup(func() { newClient = previous })
	return captured
}

func TestCLICommands(t *testing.T) {
	bg := context.Background()

	t.Run("help exits 0 at both levels", func(t *testing.T) {
		for _, args := range [][]string{{"--help"}, {"-h"}, {"run", "--help"}, {"logs", "-h"}, {"version", "--help"}} {
			code, stdout, stderr := runCLI(bg, args...)
			assertCode(t, code, exitOK, stdout, stderr)
			if !strings.Contains(stdout, "Usage:") {
				t.Errorf("%q: usage missing from stdout: %q", args, stdout)
			}
			if stderr != "" {
				t.Errorf("%q: stderr not empty: %q", args, stderr)
			}
		}
	})

	t.Run("run help declares bandwidth in bits per second", func(t *testing.T) {
		code, stdout, stderr := runCLI(bg, "run", "--help")
		assertCode(t, code, exitOK, stdout, stderr)
		for _, line := range strings.Split(stdout, "\n") {
			if strings.HasPrefix(line, "  --floor-bps N") || strings.HasPrefix(line, "  --ceil-bps N") {
				if !strings.Contains(line, "bits per second") {
					t.Errorf("bandwidth help has incorrect units: %q", line)
				}
			}
		}
		if !strings.Contains(stdout, "  --floor-bps N") || !strings.Contains(stdout, "  --ceil-bps N") {
			t.Fatalf("bandwidth help is missing: %q", stdout)
		}
	})

	t.Run("global flags are recorded and reach the client seam", func(t *testing.T) {
		fx := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, map[string]string{"version": "fixture"})
		}))
		captured := captureClientOptions(t)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--timeout", "7s", "version", "--server")
		assertCode(t, code, exitOK, stdout, stderr)
		if captured.Calls != 1 || captured.Endpoint != fx.endpoint() {
			t.Fatalf("client constructed %d times with endpoint %q", captured.Calls, captured.Endpoint)
		}
		if captured.Options.RequestTimeout != 7*time.Second || captured.Options.AllowRemoteTEST {
			t.Fatalf("explicit --timeout not passed through: %+v", captured.Options)
		}
		code, stdout, stderr = runCLI(bg, "--endpoint", fx.endpoint(), "version", "--server")
		assertCode(t, code, exitOK, stdout, stderr)
		if captured.Options.RequestTimeout != defaultCommandTimeout("version") {
			t.Fatalf("default timeout not applied: %+v", captured.Options)
		}
	})

	t.Run("default endpoint is captured without networking", func(t *testing.T) {
		previous := newClient
		t.Cleanup(func() { newClient = previous })
		calls := 0
		captured := ""
		constructorStopped := errors.New("constructor captured by test")
		newClient = func(endpoint string, _ client.Options) (*client.Client, error) {
			calls++
			captured = endpoint
			return nil, constructorStopped
		}
		code, stdout, stderr := runCLI(bg, "version", "--server")
		assertCode(t, code, exitUsage, stdout, stderr)
		if calls != 1 || captured != defaultEndpoint {
			t.Fatalf("constructor calls %d, endpoint %q; want one call with %q", calls, captured, defaultEndpoint)
		}
		if stdout != "" || !strings.Contains(stderr, constructorStopped.Error()) {
			t.Fatalf("constructor failure not preserved: stdout %q, stderr %q", stdout, stderr)
		}
	})

	t.Run("rejected endpoints omit credentials before any request", func(t *testing.T) {
		fx := unreachableFixture(t)
		wasm := wasmFile(t)
		const username = "CLI-DUMMY-USER"
		for _, tc := range []struct {
			name   string
			set    func(*url.URL)
			reason string
		}{
			{"userinfo", func(u *url.URL) { u.User = url.UserPassword(username, fixSecret) }, "userinfo is not allowed"},
			{"query", func(u *url.URL) { u.RawQuery = "token=" + fixSecret }, "query string is not allowed"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				u, err := url.Parse(fx.endpoint())
				if err != nil {
					t.Fatal(err)
				}
				tc.set(u)
				for _, output := range []string{"human", "json"} {
					for _, command := range [][]string{{"nodes"}, {"run", "--wasm", wasm, "--executor", fixExecutor}} {
						args := append([]string{"--endpoint", u.String(), "--output", output}, command...)
						code, stdout, stderr := runCLI(bg, args...)
						assertCode(t, code, exitUsage, stdout, stderr)
						assertNoSecret(t, stdout, stderr)
						if stdout != "" || !strings.Contains(stderr, tc.reason) || !strings.Contains(stderr, "--endpoint") {
							t.Fatalf("endpoint failure missing its safe reason: stdout %q, stderr %q", stdout, stderr)
						}
						if strings.Contains(stderr, username) || strings.Contains(stderr, fx.endpoint()) {
							t.Fatalf("rejected endpoint was echoed: %q", stderr)
						}
					}
				}
			})
		}
		if n := fx.total(); n != 0 {
			t.Fatalf("%d requests reached the server for rejected endpoints", n)
		}
	})

	t.Run("regular files and symlinks submit the original bytes and bandwidth defaults", func(t *testing.T) {
		path := wasmFile(t)
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "guest-link.wasm")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		for name, path := range map[string]string{"regular": path, "symlink": link} {
			t.Run(name, func(t *testing.T) {
				fx := newFixture(t, dispatcherMux(stateScript(state("RunStateStarted", "")), nil, nil))
				code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "run", "--wasm", path, "--executor", fixExecutor)
				assertCode(t, code, exitOK, stdout, stderr)
				assertNoSecret(t, stdout, stderr)
				if doc := oneJSONDocument(t, stdout); doc["state"] != stateSubmitted {
					t.Fatalf("unexpected receipt: %v", doc)
				}
				for _, route := range []string{"/payment/intent", "/debuglet"} {
					r, ok := fx.last("PUT", route)
					if !ok || fx.count("PUT", route) != 1 {
						t.Fatalf("want exactly one request to %s", route)
					}
					var body struct {
						Debuglets []client.Request `json:"debuglets"`
					}
					if err := json.Unmarshal(r.Body, &body); err != nil {
						t.Fatal(err)
					}
					if len(body.Debuglets) != 1 || !bytes.Equal(body.Debuglets[0].Wasm, want) {
						t.Fatalf("%s: guest file bytes were changed", route)
					}
					if p := body.Debuglets[0].Policy; p.FloorBW != 1048576 || p.CeilBW != 1048576 {
						t.Fatalf("%s: bandwidth defaults changed: %+v", route, p)
					}
				}
			})
		}
	})

	t.Run("oversized file rejected without reading it", func(t *testing.T) {
		fx := unreachableFixture(t)
		path := filepath.Join(t.TempDir(), "huge.wasm")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		const size = 64 << 20 // sparse: far above the 24 MiB bound, no blocks written
		if err := f.Truncate(size); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "huge-link.wasm")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{path, link} {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "run", "--wasm", path, "--executor", fixExecutor)
			runtime.ReadMemStats(&after)
			assertCode(t, code, exitUsage, stdout, stderr)
			if stdout != "" || !strings.Contains(stderr, "24 MiB") {
				t.Fatalf("size limit not reported cleanly: stdout %q, stderr %q", stdout, stderr)
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 4<<20 {
				t.Fatalf("rejecting the file allocated %d bytes; it must not be read", allocated)
			}
		}
		if n := fx.total(); n != 0 {
			t.Fatalf("%d requests sent for an oversized file", n)
		}
	})

	// One table for every invocation the CLI must reject on its own: a usage
	// error, nothing on stdout, and no request to the unreachable fixture.
	t.Run("invalid invocations are usage errors before any request", func(t *testing.T) {
		fx := unreachableFixture(t)
		wasm := wasmFile(t)
		empty := filepath.Join(t.TempDir(), "empty.wasm")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		dangling := filepath.Join(t.TempDir(), "dangling.wasm")
		if err := os.Symlink(filepath.Join(t.TempDir(), "missing.wasm"), dangling); err != nil {
			t.Fatal(err)
		}
		guest := func(extra ...string) []string {
			return append([]string{"run", "--wasm", wasm, "--executor", fixExecutor}, extra...)
		}
		cases := [][]string{
			// Missing, unknown and misplaced commands and global options.
			{}, {"frobnicate"}, {"--bogus", "nodes"}, {"--timeout", "soon", "nodes"},
			{"--output", "yaml", "nodes"}, {"--timeout", "0", "nodes"}, {"--timeout", "-1s", "nodes"},
			{"--endpoint", "", "nodes"},
			{"nodes", "--output", "json"}, // globals must precede the command
			{"nodes", "extra"},
			// run: exactly one guest source, a nonblank executor, whole-millisecond
			// durations, ordered nonnegative bandwidths, guest arguments after --.
			{"run", "--executor", fixExecutor},
			{"run", "--wasm", wasm, "--executor", ""},
			{"run", "--wasm", wasm, "--executor", "   "},
			guest("guest-arg"),
			{"run", "--wasm", wasm, "--executor", "--", "x"},
			{"run", "--sample", "unknown", "--executor", "auto"},
			{"run", "--sample", "hello", "--wasm", wasm, "--executor", "auto"},
			guest("--duration", "0"), guest("--duration", "500us"),
			guest("--duration", "1500us"), guest("--duration", "-1s"),
			guest("--floor-bps", "-1"), guest("--ceil-bps", "-1"),
			guest("--floor-bps", "2", "--ceil-bps", "1"),
			guest("--allow", " "), guest("--verbose"),
			// run: guest files that are absent, empty, a directory or dangling.
			{"run", "--wasm", filepath.Join(t.TempDir(), "absent.wasm"), "--executor", fixExecutor},
			{"run", "--wasm", empty, "--executor", fixExecutor},
			{"run", "--wasm", t.TempDir(), "--executor", fixExecutor},
			{"run", "--wasm", dangling, "--executor", fixExecutor},
			// status, logs, cancel and version reject their arguments first.
			{"status"}, {"status", "not-a-uuid"}, {"status", nilUUID}, {"status", fixJobID, "extra"},
			{"status", "../" + fixJobID}, {"status", "--wait", fixJobID},
			{"cancel"}, {"cancel", "abc"}, {"cancel", nilUUID}, {"cancel", fixJobID, fixJobID},
			{"logs"}, {"logs", "nope"}, {"logs", "--after", "-1", fixJobID}, {"logs", "--limit", "1001", fixJobID},
			{"logs", "--limit", "-5", fixJobID}, {"logs", "--after", "x", fixJobID}, {"logs", fixJobID, fixJobID},
			{"version", "extra"}, {"version", "--bogus"},
			// Selections that contradict each other or are blank.
			{"--endpoint", fx.endpoint(), "--dispatcher", "saved", "nodes"},
			{"--config", "", "nodes"},
		}
		for _, args := range cases {
			code, stdout, stderr := runCLI(bg, append([]string{"--endpoint", fx.endpoint()}, args...)...)
			if code != exitUsage {
				t.Errorf("%q: exit %d, want %d\nstderr: %q", args, code, exitUsage, stderr)
			}
			if stdout != "" {
				t.Errorf("%q: stdout must stay empty: %q", args, stdout)
			}
		}
		// The global selection is checked before any endpoint is considered.
		for _, args := range [][]string{{"--dispatcher", "", "nodes"}, {"--dispatcher", "../invalid", "nodes"}} {
			code, stdout, stderr := runCLI(bg, args...)
			assertCode(t, code, exitUsage, stdout, stderr)
		}
		if n := fx.total(); n != 0 {
			t.Fatalf("%d requests reached the server during validation", n)
		}
	})

	t.Run("guest args only after -- reach the request", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("PUT /payment/intent", intentOK)
		mux.HandleFunc("PUT /debuglet", submitOK)
		fx := newFixture(t, mux)
		wasm := wasmFile(t)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "run",
			"--wasm", wasm, "--executor", fixExecutor, "--allow", "127.0.0.1", "--allow", "10.0.0.1",
			"--duration", "2500ms", "--floor-bps", "1", "--ceil-bps", "2",
			"--", "127.0.0.1:12345", "two words", "--not-a-flag", "--")
		assertCode(t, code, exitOK, stdout, stderr)
		assertNoSecret(t, stdout, stderr)
		req, ok := fx.last("PUT", "/payment/intent")
		if !ok {
			t.Fatal("no intent request recorded")
		}
		var body struct {
			Debuglets []struct {
				OrderID    int64    `json:"order_id"`
				ExecutorID string   `json:"executor_id"`
				Args       []string `json:"args"`
				Wasm       string   `json:"wasm"`
				Policy     struct {
					FloorBW   int64    `json:"floor_bw"`
					CeilBW    int64    `json:"ceil_bw"`
					TimeoutMS int64    `json:"timeout_ms"`
					Addresses []string `json:"addresses"`
				} `json:"policy"`
				StartTime *int64 `json:"start_time"`
			} `json:"debuglets"`
			PaymentMethod string `json:"payment_method"`
		}
		if err := json.Unmarshal(req.Body, &body); err != nil {
			t.Fatalf("intent body: %v", err)
		}
		if len(body.Debuglets) != 1 || body.PaymentMethod != "TEST" {
			t.Fatalf("unexpected intent body: %s", req.Body)
		}
		d := body.Debuglets[0]
		wantArgs := []string{"127.0.0.1:12345", "two words", "--not-a-flag", "--"}
		if strings.Join(d.Args, "\x00") != strings.Join(wantArgs, "\x00") {
			t.Errorf("guest args %q, want %q", d.Args, wantArgs)
		}
		if d.OrderID != 0 || d.ExecutorID != fixExecutor || d.StartTime != nil || d.Wasm == "" {
			t.Errorf("unexpected request fields: %+v", d)
		}
		if d.Policy.TimeoutMS != 2500 || d.Policy.FloorBW != 1 || d.Policy.CeilBW != 2 {
			t.Errorf("unexpected policy: %+v", d.Policy)
		}
		if strings.Join(d.Policy.Addresses, ",") != "127.0.0.1,10.0.0.1" {
			t.Errorf("addresses %q", d.Policy.Addresses)
		}
		submit, ok := fx.last("PUT", "/debuglet")
		if !ok {
			t.Fatal("no submit request recorded")
		}
		if !bytes.Contains(submit.Body, []byte(fixSecret)) {
			t.Fatal("submit request did not carry the auth key back to the server")
		}
	})

	t.Run("allow-remote-test reaches the client seam", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("PUT /payment/intent", intentOK)
		mux.HandleFunc("PUT /debuglet", submitOK)
		fx := newFixture(t, mux)
		captured := captureClientOptions(t)
		wasm := wasmFile(t)
		runCLI(bg, "--endpoint", fx.endpoint(), "run", "--wasm", wasm, "--executor", fixExecutor)
		if captured.Options.AllowRemoteTEST {
			t.Fatal("AllowRemoteTEST set without the flag")
		}
		runCLI(bg, "--endpoint", fx.endpoint(), "run", "--wasm", wasm, "--executor", fixExecutor, "--allow-remote-test")
		if !captured.Options.AllowRemoteTEST {
			t.Fatal("AllowRemoteTEST not set by --allow-remote-test")
		}
	})

	t.Run("deadline maps to 124 without cancellation", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /version", blockUntilGone)
		mux.HandleFunc("DELETE /debuglet", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
		fx := newFixture(t, mux)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--timeout", "300ms", "version", "--server")
		assertCode(t, code, exitDeadline, stdout, stderr)
		if stdout != "" {
			t.Fatalf("stdout must stay empty on a failed --server query: %q", stdout)
		}
		if !strings.Contains(stderr, "timed out") {
			t.Fatalf("deadline not explained: %q", stderr)
		}
		if n := fx.count("DELETE", "/debuglet"); n != 0 {
			t.Fatalf("%d cancellation requests sent on deadline", n)
		}
	})

	t.Run("interruption maps to 130 without cancellation", func(t *testing.T) {
		parent, interrupt := context.WithCancel(bg)
		defer interrupt()
		mux := http.NewServeMux()
		mux.HandleFunc("GET /debuglet/{id}/state", func(w http.ResponseWriter, r *http.Request) {
			interrupt() // the operator presses Ctrl-C while the request is in flight
			blockUntilGone(w, r)
		})
		mux.HandleFunc("DELETE /debuglet", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
		fx := newFixture(t, mux)
		code, stdout, stderr := runCLI(parent, "--endpoint", fx.endpoint(), "status", fixJobID)
		assertCode(t, code, exitInterrupted, stdout, stderr)
		if stdout != "" {
			t.Fatalf("stdout must stay empty: %q", stdout)
		}
		if !strings.Contains(stderr, "interrupted") {
			t.Fatalf("interruption not explained: %q", stderr)
		}
		if n := fx.count("DELETE", "/debuglet"); n != 0 {
			t.Fatalf("%d cancellation requests sent on interruption", n)
		}
	})

	t.Run("exit mapping is decided by the command context", func(t *testing.T) {
		expired, cancel := context.WithDeadline(bg, time.Now().Add(-time.Second))
		defer cancel()
		if got := failureExit(expired); got != exitDeadline {
			t.Errorf("expired context: %d, want %d", got, exitDeadline)
		}
		interrupted, interrupt := context.WithCancel(bg)
		interrupt()
		if got := failureExit(interrupted); got != exitInterrupted {
			t.Errorf("cancelled context: %d, want %d", got, exitInterrupted)
		}
		if got := failureExit(bg); got != exitFailure {
			t.Errorf("live context: %d, want %d", got, exitFailure)
		}

		// waitForExit keeps the latest observation and never invents an outcome.
		r := receipt{ID: fixJobID, State: stateSubmitted, ExecutorID: fixExecutor}
		code, err := waitForExit(expired, func(context.Context) (client.State, error) {
			return client.State{}, context.DeadlineExceeded
		}, &r)
		if code != exitDeadline || err == nil || r.State != stateSubmitted {
			t.Errorf("deadline during wait: code %d err %v receipt %+v", code, err, r)
		}
		polls := 0
		parent, interrupt2 := context.WithCancel(bg)
		defer interrupt2()
		code, err = waitForExit(parent, func(context.Context) (client.State, error) {
			polls++
			interrupt2()
			return client.State{State: "RunStateStarted", ExecutorID: fixExecutor}, nil
		}, &r)
		if code != exitInterrupted || err == nil || r.State != "RunStateStarted" || polls != 1 {
			t.Errorf("interruption during wait: code %d err %v receipt %+v polls %d", code, err, r, polls)
		}
	})

	t.Run("wait polls unknown states until exited", func(t *testing.T) {
		shortPoll(t)
		r := receipt{ID: fixJobID, State: stateSubmitted, ExecutorID: fixExecutor}
		script := []client.State{
			{State: "RunStateUploading", ExecutorID: fixExecutor},
			{State: "RunStateSomethingNew", ExecutorID: fixExecutor},
			{State: client.StateExited, ExecutorID: fixExecutor},
		}
		polls := 0
		code, err := waitForExit(bg, func(context.Context) (client.State, error) {
			st := script[polls]
			polls++
			return st, nil
		}, &r)
		if code != exitOK || err != nil || polls != 3 || r.State != client.StateExited {
			t.Fatalf("code %d err %v polls %d receipt %+v", code, err, polls, r)
		}
		code, err = waitForExit(bg, func(context.Context) (client.State, error) {
			return client.State{State: client.StateExited, Error: "debuglet exited with code 7", ExecutorID: fixExecutor}, nil
		}, &r)
		if code != exitWorkloadFailed || err != nil || r.Error == "" {
			t.Fatalf("workload failure: code %d err %v receipt %+v", code, err, r)
		}
		polls = 0
		code, err = waitForExit(bg, func(context.Context) (client.State, error) {
			polls++
			return client.State{}, errors.New("boom")
		}, &r)
		if code != exitFailure || err == nil || polls != 1 {
			t.Fatalf("transport failure during wait: code %d err %v polls %d", code, err, polls)
		}
	})
}
