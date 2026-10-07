// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func TestAllowanceUsesSelectedAccountAndExactUnits(t *testing.T) {
	const token = "allowance-private-credential"
	want := client.Allowance{Currency: "TEST", Granted: "9007199254740993", Reserved: "4", Consumed: "9007199254740991", Remaining: "-2", PricingRule: "bw-s-ceil-ms-v1"}
	for _, mode := range []string{outputHuman, outputJSON} {
		t.Run(mode, func(t *testing.T) {
			fx := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/me/allowance" || r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Debuglet-API-Version") != "1.15" {
					t.Errorf("wrong allowance request: %s %s", r.Method, r.URL.Path)
				}
				writeJSONResponse(w, http.StatusOK, want)
			}))
			path := filepath.Join(t.TempDir(), "connections.json")
			if err := connections.Save(path, connections.Profile{Name: "selected", Endpoint: fx.endpoint()}, true); err != nil {
				t.Fatal(err)
			}
			if err := connections.SaveCredential(path, "selected", connections.Credential{Endpoint: fx.endpoint(), Token: token}); err != nil {
				t.Fatal(err)
			}
			code, out, errout := runCLI(context.Background(), "--config", path, "--dispatcher", "selected", "--output", mode, "allowance")
			assertCode(t, code, exitOK, out, errout)
			if strings.Contains(out+errout, token) || errout != "" || fx.total() != 1 {
				t.Fatalf("unexpected allowance output or requests: %q / %q / %d", out, errout, fx.total())
			}
			if mode == outputJSON {
				got := oneJSONDocument(t, out)
				if got["granted"] != want.Granted || got["remaining"] != want.Remaining || got["currency"] != "TEST" {
					t.Fatalf("allowance values lost: %s", out)
				}
			} else if !strings.Contains(out, "granted: "+want.Granted) || !strings.Contains(out, "remaining: -2") || !strings.Contains(out, "non-monetary") {
				t.Fatalf("allowance values or units missing: %s", out)
			}
		})
	}
}

func TestAllowanceFailureDoesNotPrintABalance(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    any
		message string
	}{
		{"disabled", http.StatusNotFound, map[string]string{"code": "not_found", "message": "allowances are not enabled"}, "allowances are not enabled"},
		{"unauthenticated", http.StatusUnauthorized, map[string]string{"code": "unauthorized", "message": "authentication required"}, "dbl login"},
		{"incomplete", http.StatusOK, client.Allowance{Currency: "TEST"}, "incomplete allowance"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeJSONResponse(w, tc.status, tc.body) }))
			code, out, errout := runCLI(context.Background(), "--endpoint", fx.endpoint(), "allowance")
			assertCode(t, code, exitFailure, out, errout)
			if out != "" || !strings.Contains(errout, tc.message) {
				t.Fatalf("invented balance or missing diagnostic: %q / %q", out, errout)
			}
		})
	}
}
