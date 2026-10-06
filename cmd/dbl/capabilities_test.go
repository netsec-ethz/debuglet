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

func TestNodesShowsVantageColumnsAndFiltersISDAS(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /executors", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"old","ready":true},
{"id":"lab","ready":true,"admission":"maintenance","is_public":false,"address_v4":null,"address_v6":null,"asn_v4":64500,
 "display":{"display_name":{"value":"ETH lab","source":"operator"},"city":{"value":"Zurich","source":"operator"},"country":{"value":"CH","source":"operator"},"network":{"value":null,"source":null}},
 "scion_isd_as":{"value":"1-ff00:0:110","source":"executor-reported","observed_at":1},
 "listeners":{"value":["udp","scion"],"source":"executor-reported","observed_at":1}}]`))
	})
	fx := newFixture(t, mux)
	code, stdout, stderr := runCLI(context.Background(), "--endpoint", fx.endpoint(), "nodes")
	assertCode(t, code, exitOK, stdout, stderr)
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	const header = "ID READY NAME LOCATION ISD_AS ASN ADDRESS_V4 ADDRESS_V6 LOCATION_SOURCE LAST_SEEN VERSION PRICE_PER_BW CURRENCY PROTOCOLS ENFORCEMENT CAPACITY_BPS ATTRIBUTION IPV4 IPV6 TCP_LISTENER UDP_LISTENER"
	if len(lines) != 3 || strings.Join(strings.Fields(lines[0]), " ") != header {
		t.Fatalf("table: %q", stdout)
	}
	if fields := strings.Fields(lines[1]); fields[0] != "old" || fields[2] != "-" || fields[3] != "-" || fields[4] != "unknown" {
		t.Fatalf("legacy row: %q", lines[1])
	}
	if !strings.Contains(lines[2], "ETH lab  Zurich,CH  1-ff00:0:110") {
		t.Fatalf("vantage row: %q", lines[2])
	}
	if fields := strings.Fields(lines[1]); fields[6] != "-" || fields[7] != "-" {
		t.Fatalf("legacy addresses: %q", lines[1])
	}
	if fields := strings.Fields(lines[2]); fields[7] != "private" || fields[8] != "private" {
		t.Fatalf("private addresses: %q", lines[2])
	}
	// The default table stays compact; admission, network and listeners are
	// in --output json only.
	for _, hidden := range []string{"ADMISSION", "NETWORK", "LISTENERS", "maintenance", "udp,scion"} {
		if strings.Contains(stdout, hidden) {
			t.Fatalf("default table shows %q: %q", hidden, stdout)
		}
	}
	code, stdout, stderr = runCLI(context.Background(), "--endpoint", fx.endpoint(), "--output", "json", "nodes", "--isd-as", "1-ff00:0:0110")
	assertCode(t, code, exitOK, stdout, stderr)
	var nodes []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(stdout), &nodes); err != nil || len(nodes) != 0 {
		t.Fatalf("filtered nodes: %s %v", stdout, err)
	}
	requests := fx.total()
	code, stdout, stderr = runCLI(context.Background(), "--endpoint", fx.endpoint(), "nodes", "--isd-as", "1-0")
	if code == exitOK || !strings.Contains(stderr, "ISD-AS") || fx.total() != requests {
		t.Fatalf("invalid filter: %d %q %q", code, stdout, stderr)
	}
}

// The human table names the attribution state and only its documented reasons;
// the JSON output carries the refresh details unchanged.
func TestNodesShowAttribution(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /executors", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"old","ready":true,"capabilities":{"schema_version":1,"protocols":["tcp"]}},` +
			`{"id":"ok","ready":true,"capabilities":{"schema_version":1,"protocols":["tcp"],"attribution":{"state":"available","reason":"","epoch":3}}},` +
			`{"id":"failing","ready":true,"capabilities":{"schema_version":1,"protocols":["tcp"],"attribution":{"state":"unavailable","reason":"refresh_failing","epoch":3,"installed_epoch":2,"refresh_error":"put failed","disclosure_held_since":1700000000}}},` +
			`{"id":"odd","ready":true,"capabilities":{"schema_version":1,"protocols":["tcp"],"attribution":{"state":"unavailable","reason":"\u001b[31m"}}}]`))
	})
	fx := newFixture(t, mux)
	code, stdout, stderr := runCLI(context.Background(), "--endpoint", fx.endpoint(), "nodes")
	assertCode(t, code, exitOK, stdout, stderr)
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 5 || !strings.HasSuffix(strings.TrimSpace(lines[0]), "UDP_LISTENER") {
		t.Fatalf("nodes table:\n%s", stdout)
	}
	for i, want := range []string{"unknown", "available", "unavailable(refresh_failing)", "unavailable"} {
		if fields := strings.Fields(lines[i+1]); fields[len(fields)-5] != want {
			t.Errorf("row %d attribution %q, want %q", i, fields[len(fields)-5], want)
		}
	}
	code, stdout, stderr = runCLI(context.Background(), "--endpoint", fx.endpoint(), "--output", "json", "nodes")
	assertCode(t, code, exitOK, stdout, stderr)
	if !strings.Contains(stdout, `"refresh_error":"put failed"`) || !strings.Contains(stdout, `"disclosure_held_since":1700000000`) {
		t.Fatalf("JSON dropped attribution details: %s", stdout)
	}
}
