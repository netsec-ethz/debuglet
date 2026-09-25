package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

func TestRunAutoExecutor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		nodes    []client.Node
		wantCode int
	}{
		{"sole ready", []client.Node{{ID: "offline"}, {ID: fixExecutor, Ready: true}}, exitOK},
		{"none ready", []client.Node{{ID: fixExecutor}}, exitFailure},
		{"ambiguous", []client.Node{{ID: fixExecutor, Ready: true}, {ID: "second", Ready: true}}, exitFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /executors", func(w http.ResponseWriter, r *http.Request) { writeJSONResponse(w, http.StatusOK, tc.nodes) })
			mux.HandleFunc("PUT /payment/intent", intentOK)
			mux.HandleFunc("PUT /debuglet", submitOK)
			fx := newFixture(t, mux)
			code, stdout, stderr := runCLI(context.Background(), "--endpoint", fx.endpoint(), "--output", "json", "run", "--wasm", wasmFile(t))
			assertCode(t, code, tc.wantCode, stdout, stderr)
			if tc.wantCode != exitOK {
				if fx.count("PUT", "/") != 0 {
					t.Fatal("ambiguous/unready selection attempted submission")
				}
				return
			}
			if oneJSONDocument(t, stdout)["executor_id"] != fixExecutor {
				t.Fatal("receipt does not identify selected executor")
			}
			request, ok := fx.last("PUT", "/payment/intent")
			if !ok {
				t.Fatal("missing intent")
			}
			var body struct {
				Debuglets []client.Request `json:"debuglets"`
			}
			if err := json.Unmarshal(request.Body, &body); err != nil {
				t.Fatal(err)
			}
			if len(body.Debuglets) != 1 || body.Debuglets[0].ExecutorID != fixExecutor {
				t.Fatalf("wrong submitted executor: %+v", body)
			}
		})
	}
}
