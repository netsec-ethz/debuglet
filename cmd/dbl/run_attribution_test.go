// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestRunAttributionNoticeUsesSelectedReport(t *testing.T) {
	for _, tc := range []struct {
		name, report, attribution, tagging string
		filtered                           bool
	}{
		{"legacy", `null`, "unknown", "packet tagging is unknown", false},
		{"unknown schema", `{"schema_version":2,"attribution":{"state":"available"}}`, "unknown", "packet tagging is unknown", false},
		{"untagged", `{"schema_version":1,"attribution":{"state":"unavailable","reason":"untagged"},"tagging":{"ipv4":"none","ipv6":"none"}}`, "unavailable(untagged)", "IPv4 and IPv6 packets are untagged", false},
		{"unavailable filtered", `{"schema_version":1,"protocols":["tcp"],"attribution":{"state":"unavailable","reason":"clock_unready"},"tagging":{"ipv4":"ebpf","ipv6":"none"}}`, "unavailable(clock_unready)", "IPv6 packets are untagged", true},
		{"remote details withheld", `{"schema_version":1,"attribution":{"state":"unavailable","reason":"\u001b[31m","refresh_error":"PRIVATE-DETAIL"}}`, "unavailable", "packet tagging is unknown", false},
		{"userspace limited", `{"schema_version":1,"attribution":{"state":"available"},"tagging":{"ipv4":"userspace","ipv6":"none"}}`, "available", "IPv4 userspace tagging covers UDP/ICMP only; IPv4 TCP/TLS are untagged", false},
		{"available", `{"schema_version":1,"attribution":{"state":"available"},"tagging":{"ipv4":"ebpf","ipv6":"none"}}`, "available", "IPv4 tagging is reported; IPv6 packets are untagged", false},
		{"unknown tagging", `{"schema_version":1,"attribution":{"state":"available"},"tagging":{"ipv4":"\u001b[31m","ipv6":"future"}}`, "available", "packet tagging is unknown", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := dispatcherMux(stateScript(state("RunStateStarted", "")), nil, nil)
			mux.HandleFunc("GET /executors", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `[{"id":%q,"ready":true,"capabilities":%s}]`, fixExecutor, tc.report)
			})
			fx := newFixture(t, mux)
			args := []string{"--endpoint", fx.endpoint(), "--output", "json", "run", "--wasm", wasmFile(t)}
			if tc.filtered {
				args = append(args, "--executor", fixExecutor, "--protocol", "tcp")
			}
			code, stdout, stderr := runCLI(context.Background(), args...)
			assertCode(t, code, exitOK, stdout, stderr)
			for _, want := range []string{"dbl run: notice: executor reports attribution " + tc.attribution + ";", tc.tagging, "Reports do not prove packet attribution for this run; see dbl nodes."} {
				if !strings.Contains(stderr, want) {
					t.Fatalf("notice lacks %q: %q", want, stderr)
				}
			}
			if strings.Count(stderr, "\n") != 1 || strings.ContainsAny(stderr, "\x1b") || strings.Contains(stderr, "PRIVATE-DETAIL") {
				t.Fatalf("unsafe or repeated notice: %q", stderr)
			}
			wantReceipt := fmt.Sprintf("{\"id\":%q,\"transaction_id\":%q,\"executor_id\":%q,\"state\":\"submitted\"}\n", fixJobID, fixTxID, fixExecutor)
			if stdout != wantReceipt {
				t.Fatalf("receipt changed: %q", stdout)
			}
			if fx.total() != 3 || fx.count("GET", "/executors") != 1 || fx.count("PUT", "/payment/intent") != 1 || fx.count("PUT", "/debuglet") != 1 {
				t.Fatalf("notice changed submission requests: %+v", fx.requests)
			}
		})
	}
}

func TestRunAttributionNoticeWithoutDiscovery(t *testing.T) {
	const parentID = "9a8ddf26-205a-48a4-8c93-42e384f1e611"
	const requestID = "c47d58ce-a87f-476f-b453-d3cb53528496"
	for _, command := range []string{"run", "retry"} {
		t.Run(command, func(t *testing.T) {
			intent := intentOK
			if command == "retry" {
				intent = func(w http.ResponseWriter, _ *http.Request) {
					writeJSONResponse(w, http.StatusOK, map[string]any{
						"method": "TEST",
						"intent": map[string]string{"transaction_id": fixTxID, "auth_key": fixSecret},
						"retry":  map[string]string{"parent_run_id": parentID, "request_id": requestID},
					})
				}
			}
			fx := newFixture(t, dispatcherMux(stateScript(state("RunStateStarted", "")), intent, nil))
			args := []string{"--endpoint", fx.endpoint(), "--output", "json", command}
			if command == "retry" {
				args = append(args, parentID, "--request-id", requestID)
			}
			args = append(args, "--wasm", wasmFile(t), "--executor", fixExecutor)
			code, stdout, stderr := runCLI(context.Background(), args...)
			assertCode(t, code, exitOK, stdout, stderr)
			if stderr != "dbl "+command+": notice: packet attribution was not checked for this executor; see dbl nodes for its report.\n" {
				t.Fatalf("unchecked report notice: %q", stderr)
			}
			doc := oneJSONDocument(t, stdout)
			if doc["id"] != fixJobID || doc["state"] != stateSubmitted || doc["executor_id"] != fixExecutor || doc["transaction_id"] != fixTxID {
				t.Fatalf("receipt changed: %v", doc)
			}
			if fx.total() != 2 || fx.count("GET", "/") != 0 || fx.count("PUT", "/payment/intent") != 1 || fx.count("PUT", "/debuglet") != 1 {
				t.Fatalf("explicit selection discovered or resubmitted: %+v", fx.requests)
			}
			if command == "retry" {
				want := map[string]any{"parent_run_id": parentID, "request_id": requestID}
				for _, path := range []string{"/payment/intent", "/debuglet"} {
					req, _ := fx.last("PUT", path)
					var body map[string]any
					if err := json.Unmarshal(req.Body, &body); err != nil {
						t.Fatal(err)
					}
					link, ok := body["retry"].(map[string]any)
					if !ok || link["parent_run_id"] != want["parent_run_id"] || link["request_id"] != want["request_id"] {
						t.Fatalf("retry identity changed: %v", body)
					}
				}
			}
			assertNoSecret(t, stdout, stderr)
		})
	}
}
