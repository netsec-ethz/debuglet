// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func TestBrowserLoginHeadlessStoresOnlyLocalCredential(t *testing.T) {
	for _, storage := range []string{"file", "system"} {
		t.Run(storage, func(t *testing.T) {
			if storage == "system" {
				cliSecretToolFixture(t)
			}
			const accountID = "c4d022cb-5bdf-47f9-ab0f-314bb8f0c7c2"
			const deviceSecret = "dbd_selector.DEVICE-SECRET"
			const accessSecret = "dbt_selector.ACCESS-SECRET"
			config := filepath.Join(t.TempDir(), "config.json")
			mux := http.NewServeMux()
			var endpoint string
			scopes := []string{"account:read", "executors:read", "measurements:read", "measurements:write"}
			mux.HandleFunc("POST /auth/device/start", func(w http.ResponseWriter, r *http.Request) {
				writeJSONResponse(w, 201, client.DeviceLogin{DeviceCode: deviceSecret, UserCode: "ABCDE-F2345", VerificationURI: endpoint + "/device", Audience: endpoint, Scopes: scopes, ExpiresAt: time.Now().Add(10 * time.Minute).Unix(), Interval: 5})
			})
			mux.HandleFunc("POST /auth/device/poll", func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					DeviceCode string `json:"device_code"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				if req.DeviceCode != deviceSecret {
					t.Error("poll secret missing")
				}
				writeJSONResponse(w, 200, client.DeviceLoginPoll{State: "authorized", Credential: &client.APICredential{Token: accessSecret, CredentialID: "selector", Audience: endpoint, Scopes: scopes, ExpiresAt: time.Now().Add(time.Hour).Unix(), ID: accountID, Name: "Alice", Role: "user"}})
			})
			fx := newFixture(t, mux)
			endpoint = fx.endpoint()
			if err := connections.Save(config, connections.Profile{Name: "saved", Endpoint: endpoint}, true); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			code, out, errout := runCLI(ctx, "--config", config, "--output", outputJSON, "login", "--no-browser", "--credential-store", storage)
			assertCode(t, code, exitOK, out, errout)
			if !strings.Contains(errout, "ABCDE-F2345") || !strings.Contains(errout, endpoint+"/device") {
				t.Fatal("headless instructions missing")
			}
			for _, secret := range []string{deviceSecret, accessSecret} {
				if strings.Contains(out+errout, secret) {
					t.Fatal("credential in CLI output")
				}
			}
			saved, err := connections.CredentialFor(t.Context(), config, "saved", endpoint)
			if err != nil || saved.Token != accessSecret || saved.AccountID != accountID {
				t.Fatalf("saved credential %v", err)
			}
		})
	}
}

func TestBrowserLoginInterruptionCancelsTransaction(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config.json")
	mux := http.NewServeMux()
	var endpoint string
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cancelled := make(chan struct{}, 1)
	mux.HandleFunc("POST /auth/device/start", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, 201, client.DeviceLogin{DeviceCode: "dbd_selector.secret", UserCode: "ABCDE-F2345", VerificationURI: endpoint + "/device", Audience: endpoint, Scopes: []string{"account:read", "executors:read", "measurements:read", "measurements:write"}, ExpiresAt: time.Now().Add(time.Minute).Unix(), Interval: 5})
	})
	mux.HandleFunc("POST /auth/device/cancel", func(w http.ResponseWriter, r *http.Request) { cancelled <- struct{}{}; w.WriteHeader(204) })
	fx := newFixture(t, mux)
	endpoint = fx.endpoint()
	if err := connections.Save(config, connections.Profile{Name: "saved", Endpoint: endpoint}, true); err != nil {
		t.Fatal(err)
	}
	// Cancel when instructions have been written, after the transaction exists.
	options := globalOptions{ConfigPath: config}
	c, err := client.New(endpoint, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	code := browserLoginCommand(ctx, c, connections.Profile{Name: "saved", Endpoint: endpoint}, options, []string{"account:read", "executors:read", "measurements:read", "measurements:write"}, true, "file", cancelLoginWriter{cancel}, &strings.Builder{})
	if code == exitOK {
		t.Fatal("interrupted login succeeded")
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("transaction not cancelled")
	}
	saved, err := connections.CredentialFor(t.Context(), config, "saved", endpoint)
	if err != nil || saved.Token != "" {
		t.Fatal("interruption saved a credential")
	}
}

type cancelLoginWriter struct{ cancel context.CancelFunc }

func (w cancelLoginWriter) Write(p []byte) (int, error) { w.cancel(); return len(p), nil }

func TestScopedLoginCannotSilentlyIssueLegacySession(t *testing.T) {
	code, out, errout := runCLI(t.Context(), "login", "--account-key-file", "unused", "--scopes", "account:read")
	if code != exitUsage || !strings.Contains(errout, "cannot be combined") {
		t.Fatalf("scoped account-key login accepted: %d %s %s", code, out, errout)
	}
}
