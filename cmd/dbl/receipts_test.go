package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// stateScript answers GET debuglet/{id}/state with successive states,
// repeating the last one.
func stateScript(states ...map[string]string) http.HandlerFunc {
	var n atomic.Int64
	return func(w http.ResponseWriter, r *http.Request) {
		i := int(n.Add(1)) - 1
		if i >= len(states) {
			i = len(states) - 1
		}
		writeJSONResponse(w, http.StatusOK, states[i])
	}
}

func state(name, errMsg string) map[string]string {
	return map[string]string{"state": name, "error": errMsg, "executor_id": fixExecutor}
}

// dispatcherMux is a fixture that accepts submissions and serves the given
// state handler; cancellations are acknowledged and recorded. A nil intent
// or submit handler selects the successful default.
func dispatcherMux(stateHandler, intent, submit http.HandlerFunc) *http.ServeMux {
	if intent == nil {
		intent = intentOK
	}
	if submit == nil {
		submit = submitOK
	}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /payment/intent", intent)
	mux.HandleFunc("PUT /debuglet", submit)
	mux.HandleFunc("GET /debuglet/{id}/state", stateHandler)
	mux.HandleFunc("DELETE /debuglet", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	return mux
}

func hasKey(doc map[string]any, key string) bool {
	_, ok := doc[key]
	return ok
}

func TestCLIReceipts(t *testing.T) {
	bg := context.Background()

	t.Run("run emits exactly one submitted receipt", func(t *testing.T) {
		fx := newFixture(t, dispatcherMux(stateScript(state("RunStateStarted", "")), nil, nil))
		wasm := wasmFile(t)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "run", "--wasm", wasm, "--executor", fixExecutor)
		assertCode(t, code, exitOK, stdout, stderr)
		assertNoSecret(t, stdout, stderr)
		doc := oneJSONDocument(t, stdout)
		if doc["id"] != fixJobID || doc["transaction_id"] != fixTxID || doc["executor_id"] != fixExecutor || doc["state"] != stateSubmitted {
			t.Fatalf("unexpected receipt: %v", doc)
		}
		if hasKey(doc, "error") {
			t.Fatalf("submitted receipt must omit error: %v", doc)
		}
		if n := fx.count("GET", "/debuglet/"); n != 0 {
			t.Fatalf("%d state polls without --wait", n)
		}
		code, stdout, stderr = runCLI(bg, "--endpoint", fx.endpoint(), "run", "--wasm", wasm, "--executor", fixExecutor)
		assertCode(t, code, exitOK, stdout, stderr)
		assertNoSecret(t, stdout, stderr)
		for _, want := range []string{"state: submitted\n", "id: " + fixJobID + "\n", "transaction_id: " + fixTxID + "\n", "executor_id: " + fixExecutor + "\n"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("human receipt lacks %q: %q", want, stdout)
			}
		}
	})

	t.Run("wait success emits a single final document", func(t *testing.T) {
		shortPoll(t)
		fx := newFixture(t, dispatcherMux(stateScript(
			state("RunStateUploaded", ""), state("RunStateStarted", ""), state("RunStateExited", "")), nil, nil))
		wasm := wasmFile(t)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "run", "--wait", "--wasm", wasm, "--executor", fixExecutor)
		assertCode(t, code, exitOK, stdout, stderr)
		assertNoSecret(t, stdout, stderr)
		doc := oneJSONDocument(t, stdout)
		if doc["state"] != "RunStateExited" || doc["id"] != fixJobID || doc["transaction_id"] != fixTxID || hasKey(doc, "error") {
			t.Fatalf("unexpected final document: %v", doc)
		}
		if strings.Contains(stdout, stateSubmitted) {
			t.Fatalf("submitted receipt must be buffered under --wait: %q", stdout)
		}
		if n := fx.count("GET", "/debuglet/"); n != 3 {
			t.Fatalf("%d state polls, want 3", n)
		}
		if n := fx.count("DELETE", "/debuglet"); n != 0 {
			t.Fatalf("%d cancellations sent", n)
		}
	})

	t.Run("wait failure emits the error and exits 3", func(t *testing.T) {
		shortPoll(t)
		fx := newFixture(t, dispatcherMux(stateScript(state("RunStateStarted", ""), state("RunStateExited", "debuglet exited with code 7")), nil, nil))
		wasm := wasmFile(t)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "run", "--wait", "--wasm", wasm, "--executor", fixExecutor)
		assertCode(t, code, exitWorkloadFailed, stdout, stderr)
		assertNoSecret(t, stdout, stderr)
		doc := oneJSONDocument(t, stdout)
		if doc["state"] != "RunStateExited" || doc["error"] != "debuglet exited with code 7" || doc["id"] != fixJobID {
			t.Fatalf("unexpected final document: %v", doc)
		}
		if !strings.Contains(stderr, "code 7") {
			t.Fatalf("workload failure not explained on stderr: %q", stderr)
		}
		code, stdout, stderr = runCLI(bg, "--endpoint", fx.endpoint(), "run", "--wait", "--wasm", wasm, "--executor", fixExecutor)
		assertCode(t, code, exitWorkloadFailed, stdout, stderr)
		if strings.Count(stdout, "state: ") != 1 || !strings.Contains(stdout, "state: RunStateExited\n") || !strings.Contains(stdout, "error: debuglet exited with code 7\n") {
			t.Fatalf("human final receipt: %q", stdout)
		}
	})

	t.Run("wait deadline emits the latest receipt once and never cancels", func(t *testing.T) {
		fx := newFixture(t, dispatcherMux(blockUntilGone, nil, nil))
		wasm := wasmFile(t)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "--timeout", "500ms",
			"run", "--wait", "--wasm", wasm, "--executor", fixExecutor)
		assertCode(t, code, exitDeadline, stdout, stderr)
		assertNoSecret(t, stdout, stderr)
		doc := oneJSONDocument(t, stdout)
		if doc["state"] != stateSubmitted || doc["id"] != fixJobID || doc["transaction_id"] != fixTxID {
			t.Fatalf("latest receipt not preserved: %v", doc)
		}
		if !strings.Contains(stderr, "timed out") {
			t.Fatalf("deadline not explained: %q", stderr)
		}
		if n := fx.count("DELETE", "/debuglet"); n != 0 {
			t.Fatalf("%d cancellations sent on deadline", n)
		}
	})

	t.Run("wait interruption emits the latest receipt once and never cancels", func(t *testing.T) {
		parent, interrupt := context.WithCancel(bg)
		defer interrupt()
		fx := newFixture(t, dispatcherMux(func(w http.ResponseWriter, r *http.Request) {
			interrupt()
			writeJSONResponse(w, http.StatusOK, state("RunStateStarted", ""))
		}, nil, nil))
		wasm := wasmFile(t)
		code, stdout, stderr := runCLI(parent, "--endpoint", fx.endpoint(), "--output", "json", "run", "--wait", "--wasm", wasm, "--executor", fixExecutor)
		assertCode(t, code, exitInterrupted, stdout, stderr)
		doc := oneJSONDocument(t, stdout)
		if doc["id"] != fixJobID || doc["transaction_id"] != fixTxID {
			t.Fatalf("known IDs lost: %v", doc)
		}
		if doc["state"] != stateSubmitted && doc["state"] != "RunStateStarted" {
			t.Fatalf("unexpected latest state: %v", doc)
		}
		if n := fx.count("DELETE", "/debuglet"); n != 0 {
			t.Fatalf("%d cancellations sent on interruption", n)
		}
	})

	t.Run("submit-stage rejection keeps the transaction and invents no id", func(t *testing.T) {
		mux := dispatcherMux(stateScript(state("RunStateStarted", "")), nil, func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusBadRequest, map[string]string{"message": "bad request"})
		})
		fx := newFixture(t, mux)
		wasm := wasmFile(t)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "run", "--wasm", wasm, "--executor", fixExecutor)
		assertCode(t, code, exitFailure, stdout, stderr)
		assertNoSecret(t, stdout, stderr)
		doc := oneJSONDocument(t, stdout)
		if doc["state"] != stateSubmissionFailed || doc["transaction_id"] != fixTxID || doc["executor_id"] != fixExecutor || hasKey(doc, "id") {
			t.Fatalf("unexpected receipt: %v", doc)
		}
		if !strings.Contains(stderr, "rejected") {
			t.Fatalf("rejection not explained: %q", stderr)
		}
		code, stdout, stderr = runCLI(bg, "--endpoint", fx.endpoint(), "run", "--wasm", wasm, "--executor", fixExecutor)
		assertCode(t, code, exitFailure, stdout, stderr)
		if !strings.Contains(stdout, "state: submission_failed\n") || !strings.Contains(stdout, "transaction_id: "+fixTxID+"\n") || strings.Contains(stdout, "id: "+fixJobID) {
			t.Fatalf("human receipt: %q", stdout)
		}
	})

	t.Run("submit-stage server failure reports an unknown outcome", func(t *testing.T) {
		mux := dispatcherMux(stateScript(state("RunStateStarted", "")), nil, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		})
		fx := newFixture(t, mux)
		wasm := wasmFile(t)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "run", "--wasm", wasm, "--executor", fixExecutor)
		assertCode(t, code, exitFailure, stdout, stderr)
		assertNoSecret(t, stdout, stderr)
		doc := oneJSONDocument(t, stdout)
		if doc["state"] != stateSubmissionUnknown || doc["transaction_id"] != fixTxID || hasKey(doc, "id") {
			t.Fatalf("unexpected receipt: %v", doc)
		}
		if !strings.Contains(stderr, "outcome unknown") {
			t.Fatalf("uncertainty not explained: %q", stderr)
		}
	})

	t.Run("unexpected submit success statuses preserve uncertainty and one receipt", func(t *testing.T) {
		// The SDK owns status classification; exercise its public result
		// through the CLI rather than duplicating classification here.
		for _, status := range []int{http.StatusCreated, http.StatusAccepted} {
			for _, wait := range []bool{false, true} {
				t.Run(strconv.Itoa(status)+" wait="+strconv.FormatBool(wait), func(t *testing.T) {
					fx := newFixture(t, dispatcherMux(stateScript(state("RunStateExited", "")), nil, func(w http.ResponseWriter, r *http.Request) {
						writeJSONResponse(w, status, []string{fixJobID})
					}))
					args := []string{"--endpoint", fx.endpoint(), "--output", "json", "run", "--wasm", wasmFile(t), "--executor", fixExecutor}
					if wait {
						args = append(args, "--wait")
					}
					code, stdout, stderr := runCLI(bg, args...)
					assertCode(t, code, exitFailure, stdout, stderr)
					assertNoSecret(t, stdout, stderr)
					doc := oneJSONDocument(t, stdout)
					if doc["state"] != stateSubmissionUnknown || doc["transaction_id"] != fixTxID || doc["executor_id"] != fixExecutor || len(doc) != 3 {
						t.Fatalf("unexpected receipt: %v", doc)
					}
					if !strings.Contains(stderr, "outcome unknown") || !strings.Contains(stderr, strconv.Itoa(status)) {
						t.Fatalf("HTTP status and uncertainty not explained: %q", stderr)
					}
					if fx.total() != 2 || fx.count("PUT", "/payment/intent") != 1 || fx.count("PUT", "/debuglet") != 1 {
						t.Fatalf("want one intent and one submission, without retry, polling or cancellation; got %d requests", fx.total())
					}
				})
			}
		}
	})

	t.Run("submit-stage deadline reports an unknown outcome with 124", func(t *testing.T) {
		mux := dispatcherMux(stateScript(state("RunStateStarted", "")), nil, blockUntilGone)
		fx := newFixture(t, mux)
		wasm := wasmFile(t)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "--timeout", "500ms", "run", "--wasm", wasm, "--executor", fixExecutor)
		assertCode(t, code, exitDeadline, stdout, stderr)
		assertNoSecret(t, stdout, stderr)
		doc := oneJSONDocument(t, stdout)
		if doc["state"] != stateSubmissionUnknown || doc["transaction_id"] != fixTxID || hasKey(doc, "id") {
			t.Fatalf("unexpected receipt: %v", doc)
		}
		if !strings.Contains(stderr, "submission outcome unknown") {
			t.Fatalf("uncertainty not explained: %q", stderr)
		}
		if n := fx.count("DELETE", "/debuglet"); n != 0 {
			t.Fatalf("%d cancellations sent", n)
		}
	})

	t.Run("intent-stage failure emits no receipt", func(t *testing.T) {
		mux := dispatcherMux(stateScript(state("RunStateStarted", "")), func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"message": "intent store down"})
		}, nil)
		fx := newFixture(t, mux)
		wasm := wasmFile(t)
		for _, output := range []string{"json", "human"} {
			code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", output, "run", "--wasm", wasm, "--executor", fixExecutor)
			assertCode(t, code, exitFailure, stdout, stderr)
			assertNoSecret(t, stdout, stderr)
			if stdout != "" {
				t.Fatalf("%s: receipt emitted before any transaction was known: %q", output, stdout)
			}
			if !strings.Contains(stderr, "intent") {
				t.Fatalf("%s: stage not explained: %q", output, stderr)
			}
		}
		if n := fx.count("PUT", "/debuglet"); n != 0 {
			t.Fatalf("%d submissions after a failed intent", n)
		}
	})

	t.Run("intent credential errors have safe diagnostics and no receipt", func(t *testing.T) {
		// Sanitization belongs to the SDK. These CLI assertions intentionally
		// require the integrated SDK fix for protocol and HTTP diagnostics.
		for _, tc := range []struct {
			name   string
			status int
			body   any
		}{
			{
				"unexpected intent envelope", http.StatusCreated,
				map[string]any{"method": "TEST", "intent": map[string]string{"transaction_id": fixTxID, "auth_key": fixSecret}},
			},
			{
				"nested intent message", http.StatusCreated,
				map[string]any{"message": map[string]any{"method": "TEST", "intent": map[string]string{"transaction_id": fixTxID, "auth_key": fixSecret}}},
			},
			{
				"wrong payment method equals key", http.StatusOK,
				map[string]any{"method": fixSecret, "intent": map[string]string{"transaction_id": fixTxID, "auth_key": fixSecret}},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				fx := newFixture(t, dispatcherMux(stateScript(state("RunStateStarted", "")), func(w http.ResponseWriter, r *http.Request) {
					writeJSONResponse(w, tc.status, tc.body)
				}, nil))
				wasm := wasmFile(t)
				for _, output := range []string{"json", "human"} {
					code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", output, "run", "--wasm", wasm, "--executor", fixExecutor)
					assertCode(t, code, exitFailure, stdout, stderr)
					assertNoSecret(t, stdout, stderr)
					if stdout != "" || !strings.Contains(stderr, "intent") {
						t.Fatalf("intent failure lacks its safe diagnostic: stdout %q, stderr %q", stdout, stderr)
					}
					if tc.status != http.StatusOK && !strings.Contains(stderr, strconv.Itoa(tc.status)) {
						t.Fatalf("HTTP status missing from safe diagnostic: %q", stderr)
					}
				}
				if fx.count("PUT", "/payment/intent") != 2 || fx.total() != 2 {
					t.Fatalf("want one intent per invocation and no submissions; got %d requests", fx.total())
				}
			})
		}
	})

	t.Run("status and logs complete with 0 for a failed job", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /debuglet/{id}/state", stateScript(state("RunStateExited", "debuglet exited with code 7")))
		mux.HandleFunc("GET /debuglet/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"state": "RunStateExited", "error": "debuglet exited with code 7", "after": 0, "logs": nil, "has_more": false,
			})
		})
		fx := newFixture(t, mux)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "status", fixJobID)
		assertCode(t, code, exitOK, stdout, stderr)
		doc := oneJSONDocument(t, stdout)
		if doc["id"] != fixJobID || doc["state"] != "RunStateExited" || doc["error"] != "debuglet exited with code 7" || doc["executor_id"] != fixExecutor {
			t.Fatalf("unexpected status document: %v", doc)
		}
		code, stdout, stderr = runCLI(bg, "--endpoint", fx.endpoint(), "status", fixJobID)
		assertCode(t, code, exitOK, stdout, stderr)
		if !strings.Contains(stdout, "state: RunStateExited\n") || !strings.Contains(stdout, "error: debuglet exited with code 7\n") {
			t.Fatalf("human status: %q", stdout)
		}
		code, stdout, stderr = runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "logs", fixJobID)
		assertCode(t, code, exitOK, stdout, stderr)
		page := oneJSONDocument(t, stdout)
		if page["state"] != "RunStateExited" || page["has_more"] != false {
			t.Fatalf("unexpected log page: %v", page)
		}
		if _, ok := page["logs"].([]any); !ok {
			t.Fatalf("logs must be a JSON array, got %T", page["logs"])
		}
	})

	t.Run("cancel acknowledgement uses the executor from status", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /debuglet/{id}/state", stateScript(map[string]string{"state": "RunStateStarted", "error": "", "executor_id": "actual-executor"}))
		mux.HandleFunc("DELETE /debuglet", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
		fx := newFixture(t, mux)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "cancel", fixJobID)
		assertCode(t, code, exitOK, stdout, stderr)
		doc := oneJSONDocument(t, stdout)
		if doc["id"] != fixJobID || doc["acknowledged"] != true || len(doc) != 2 {
			t.Fatalf("unexpected acknowledgement: %v", doc)
		}
		del, ok := fx.last("DELETE", "/debuglet")
		if !ok {
			t.Fatal("no cancellation request")
		}
		var body struct {
			DebugletID string `json:"debuglet_id"`
			ExecutorID string `json:"executor_id"`
		}
		if err := json.Unmarshal(del.Body, &body); err != nil || body.DebugletID != fixJobID || body.ExecutorID != "actual-executor" {
			t.Fatalf("cancellation body %s (%v)", del.Body, err)
		}
		code, stdout, stderr = runCLI(bg, "--endpoint", fx.endpoint(), "cancel", fixJobID)
		assertCode(t, code, exitOK, stdout, stderr)
		if stdout != "Cancellation acknowledged\n" {
			t.Fatalf("human acknowledgement %q", stdout)
		}
		if strings.Contains(strings.ToLower(stdout+stderr), "stopped") {
			t.Fatalf("output must not claim the job stopped: %q %q", stdout, stderr)
		}
	})

	t.Run("cancel rejection is a failure", func(t *testing.T) {
		for _, tc := range []struct {
			name          string
			statusCode    int
			deleteCode    int
			wantDeletes   int
			wantStderrHas string
		}{
			{"delete 400", http.StatusOK, http.StatusBadRequest, 1, "400"},
			{"delete 404", http.StatusOK, http.StatusNotFound, 1, "404"},
			{"status 404", http.StatusNotFound, http.StatusNoContent, 0, "404"},
		} {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /debuglet/{id}/state", func(w http.ResponseWriter, r *http.Request) {
				if tc.statusCode != http.StatusOK {
					writeJSONResponse(w, tc.statusCode, map[string]string{"message": "debuglet not found"})
					return
				}
				writeJSONResponse(w, http.StatusOK, state("RunStateExited", ""))
			})
			mux.HandleFunc("DELETE /debuglet", func(w http.ResponseWriter, r *http.Request) {
				if tc.deleteCode == http.StatusNoContent {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				writeJSONResponse(w, tc.deleteCode, map[string]string{"message": "debuglet already finished"})
			})
			fx := newFixture(t, mux)
			for _, output := range []string{"json", "human"} {
				code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", output, "cancel", fixJobID)
				if code != exitFailure {
					t.Errorf("%s/%s: exit %d, want %d\nstdout: %q\nstderr: %q", tc.name, output, code, exitFailure, stdout, stderr)
				}
				if stdout != "" {
					t.Errorf("%s/%s: stdout must stay empty on rejection: %q", tc.name, output, stdout)
				}
				if strings.Contains(strings.ToLower(stdout+stderr), "acknowledged") || strings.Contains(strings.ToLower(stdout+stderr), "stopped") {
					t.Errorf("%s/%s: rejection presented as success: %q %q", tc.name, output, stdout, stderr)
				}
				if !strings.Contains(stderr, tc.wantStderrHas) {
					t.Errorf("%s/%s: stderr lacks %q: %q", tc.name, output, tc.wantStderrHas, stderr)
				}
			}
			if n := fx.count("DELETE", "/debuglet"); n != tc.wantDeletes*2 {
				t.Errorf("%s: %d cancellation requests, want %d", tc.name, n, tc.wantDeletes*2)
			}
		}
	})

	t.Run("version reports local metadata and only queries the server on request", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(w, http.StatusOK, map[string]string{"version": "fixture"})
		})
		fx := newFixture(t, mux)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "version")
		assertCode(t, code, exitOK, stdout, stderr)
		doc := oneJSONDocument(t, stdout)
		for _, key := range []string{"module", "version", "revision"} {
			if _, ok := doc[key].(string); !ok {
				t.Errorf("%s must be a string: %v", key, doc[key])
			}
		}
		if _, ok := doc["modified"].(bool); !ok {
			t.Errorf("modified must be a bool: %v", doc["modified"])
		}
		if hasKey(doc, "server") || len(doc) != 4 {
			t.Errorf("default version document has unexpected keys: %v", doc)
		}
		if n := fx.total(); n != 0 {
			t.Fatalf("default version made %d requests", n)
		}
		code, stdout, stderr = runCLI(bg, "--endpoint", fx.endpoint(), "version")
		assertCode(t, code, exitOK, stdout, stderr)
		for _, want := range []string{"module: ", "version: ", "revision: ", "modified: "} {
			if !strings.Contains(stdout, want) {
				t.Errorf("human version lacks %q: %q", want, stdout)
			}
		}
		if strings.Contains(stdout, "server:") {
			t.Errorf("server line without --server: %q", stdout)
		}

		code, stdout, stderr = runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "version", "--server")
		assertCode(t, code, exitOK, stdout, stderr)
		doc = oneJSONDocument(t, stdout)
		server, _ := doc["server"].(map[string]any)
		if server["version"] != "fixture" {
			t.Fatalf("server version missing: %v", doc)
		}
		code, stdout, stderr = runCLI(bg, "--endpoint", fx.endpoint(), "version", "--server")
		assertCode(t, code, exitOK, stdout, stderr)
		if !strings.Contains(stdout, "server: fixture\n") {
			t.Fatalf("human server version: %q", stdout)
		}
		if n := fx.count("GET", "/version"); n != 2 {
			t.Fatalf("%d version requests, want 2", n)
		}
	})

	t.Run("nodes is always an array", func(t *testing.T) {
		var respond atomic.Value
		respond.Store("null")
		mux := http.NewServeMux()
		mux.HandleFunc("GET /executors", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(respond.Load().(string)))
		})
		fx := newFixture(t, mux)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "nodes")
		assertCode(t, code, exitOK, stdout, stderr)
		if strings.TrimSpace(stdout) != "[]" {
			t.Fatalf("null executors must print an empty array: %q", stdout)
		}
		respond.Store(`[{"id":"fixture-executor","ready":true,"last_seen":1700000000,"version":"fixture","tesla_delay_sec":5,"tesla_anchor_timestamp_ns":1700000000000000000,"tesla_anchor_key":"AQIDBA==","price_per_bw":0,"currency":"TEST"}]`)
		code, stdout, stderr = runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "nodes")
		assertCode(t, code, exitOK, stdout, stderr)
		var nodes []map[string]any
		if err := json.Unmarshal([]byte(stdout), &nodes); err != nil || len(nodes) != 1 || nodes[0]["id"] != fixExecutor {
			t.Fatalf("nodes JSON %q (%v)", stdout, err)
		}
		code, stdout, stderr = runCLI(bg, "--endpoint", fx.endpoint(), "nodes")
		assertCode(t, code, exitOK, stdout, stderr)
		if !strings.Contains(stdout, "ID") || !strings.Contains(stdout, fixExecutor) || !strings.Contains(stdout, "TEST") {
			t.Fatalf("human nodes table: %q", stdout)
		}
	})
}
