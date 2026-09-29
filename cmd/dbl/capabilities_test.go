// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestCapabilitySelectionFailureNeverSubmits(t *testing.T) {
	wasm := wasmFile(t)
	for _, tc := range []struct {
		name, body string
		args       []string
	}{
		{"unknown", `[{"id":"old","ready":true}]`, []string{"--protocol", "icmp"}},
		{"ambiguous", `[{"id":"a","ready":true,"capabilities":{"schema_version":1,"protocols":["tcp"]}},{"id":"b","ready":true,"capabilities":{"schema_version":1,"protocols":["tcp"]}}]`, []string{"--protocol", "tcp"}},
		{"explicit mismatch", `[{"id":"a","ready":true,"capabilities":{"schema_version":1,"protocols":["tcp"]}}]`, []string{"--executor", "a", "--protocol", "scion"}},
		{"insufficient", `[{"id":"a","ready":true,"capabilities":{"schema_version":1,"advertised_capacity_bps":10}}]`, []string{"--min-capacity-bps", "11"}},
		{"unknown capacity at zero", `[{"id":"a","ready":true,"capabilities":{"schema_version":1}}]`, []string{"--min-capacity-bps", "0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /executors", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			})
			fx := newFixture(t, mux)
			args := []string{"--endpoint", fx.endpoint(), "run", "--wasm", wasm}
			args = append(args, tc.args...)
			code, stdout, stderr := runCLI(context.Background(), args...)
			assertCode(t, code, exitFailure, stdout, stderr)
			if !strings.Contains(stderr, "executor") {
				t.Fatalf("missing selection diagnostic: %s", stderr)
			}
			if fx.total() != 1 || fx.count("GET", "/executors") != 1 {
				t.Fatal("selection failure issued a submission or another request")
			}
		})
	}
}

func TestCapabilitySelectionCarriesICMPIntoSubmission(t *testing.T) {
	mux := dispatcherMux(stateScript(state("RunStateStarted", "")), nil, nil)
	mux.HandleFunc("GET /executors", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"plain","ready":true,"capabilities":{"schema_version":1,"protocols":["tcp"],"enforcement_mode":"fallback"}},{"id":"icmp-node","ready":true,"capabilities":{"schema_version":1,"protocols":["icmp"],"enforcement_mode":"fallback","advertised_capacity_bps":100}}]`))
	})
	fx := newFixture(t, mux)
	code, stdout, stderr := runCLI(context.Background(), "--endpoint", fx.endpoint(), "--output", "json", "run", "--wasm", wasmFile(t), "--protocol", "icmp", "--enforcement", "fallback", "--min-capacity-bps", "10")
	assertCode(t, code, exitOK, stdout, stderr)
	if oneJSONDocument(t, stdout)["executor_id"] != "icmp-node" {
		t.Fatal("receipt names a different executor")
	}
	request, ok := fx.last("PUT", "/payment/intent")
	if !ok {
		t.Fatal("missing submission intent")
	}
	var body struct {
		Debuglets []struct {
			ExecutorID string `json:"executor_id"`
			Policy     struct {
				RequireICMP bool `json:"require_icmp"`
			} `json:"policy"`
		} `json:"debuglets"`
	}
	if err := json.Unmarshal(request.Body, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Debuglets) != 1 || body.Debuglets[0].ExecutorID != "icmp-node" || !body.Debuglets[0].Policy.RequireICMP {
		t.Fatal("requested ICMP capability was not carried into normal admission")
	}
	code, stdout, stderr = runCLI(context.Background(), "--endpoint", fx.endpoint(), "--output", "json", "nodes", "--protocol", "icmp")
	assertCode(t, code, exitOK, stdout, stderr)
	var nodes []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(stdout), &nodes); err != nil || len(nodes) != 1 || nodes[0].ID != "icmp-node" {
		t.Fatalf("filtered nodes: %s %v", stdout, err)
	}
}
