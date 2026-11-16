// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func tokenFileFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api-token")
	if err := os.WriteFile(path, []byte(fixSecret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoginTokenImportsVerifiedCredentialAndBindsEndpoint(t *testing.T) {
	t.Setenv(accountKeyEnv, "")
	var audience string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/credential", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+fixSecret {
			t.Error("import did not verify the supplied credential")
		}
		writeJSONResponse(w, 200, client.CredentialStatus{ID: "credential-id", Kind: "api", Audience: audience, Scopes: []string{"account:read", "measurements:read"}, ExpiresAt: time.Now().Add(time.Hour).Unix()})
	})
	fx := newFixture(t, mux)
	audience = fx.endpoint()
	config := filepath.Join(t.TempDir(), "config.json")
	profile := connections.Profile{Name: "ci", Endpoint: audience}
	if err := connections.Save(config, profile, true); err != nil {
		t.Fatal(err)
	}
	code, out, errout := runCLI(t.Context(), "--config", config, "--output", "json", "login", "--token-file", tokenFileFixture(t), "--credential-store", "file")
	assertCode(t, code, exitOK, out, errout)
	if strings.Contains(out+errout, fixSecret) || oneJSONDocument(t, out)["credential_id"] != "credential-id" {
		t.Fatal("import output missing metadata or exposed secret")
	}
	credential, err := connections.CredentialFor(t.Context(), config, profile.Name, profile.Endpoint)
	if err != nil || credential.Token != fixSecret {
		t.Fatalf("credential not saved: %v", err)
	}
	profile.Endpoint = "https://other.invalid"
	if _, err := connections.CredentialFor(t.Context(), config, profile.Name, profile.Endpoint); !errors.Is(err, connections.ErrCredentialEndpointMismatch) {
		t.Fatalf("imported credential was not endpoint-bound: %v", err)
	}
}

func TestLoginTokenRejectsUnusableCredentialsWithoutReplacingStore(t *testing.T) {
	t.Setenv(accountKeyEnv, "")
	for _, scenario := range []string{"revoked", "missing-scope", "expired", "audience", "session", "echoed-secret"} {
		t.Run(scenario, func(t *testing.T) {
			var audience string
			mux := http.NewServeMux()
			mux.HandleFunc("GET /auth/credential", func(w http.ResponseWriter, r *http.Request) {
				status := client.CredentialStatus{ID: "credential-id", Kind: "api", Audience: audience, Scopes: []string{"account:read", "measurements:read"}, ExpiresAt: time.Now().Add(time.Hour).Unix()}
				switch scenario {
				case "revoked":
					writeJSONResponse(w, 401, map[string]string{"message": "revoked " + fixSecret})
					return
				case "missing-scope":
					writeJSONResponse(w, 403, map[string]string{"message": "insufficient scope"})
					return
				case "expired":
					status.ExpiresAt = time.Now().Add(-time.Hour).Unix()
				case "audience":
					status.Audience = "https://other.invalid"
				case "session":
					status.Kind = "session"
				case "echoed-secret":
					status.ID = fixSecret
				}
				writeJSONResponse(w, 200, status)
			})
			fx := newFixture(t, mux)
			audience = fx.endpoint()
			config := filepath.Join(t.TempDir(), "config.json")
			profile := connections.Profile{Name: "ci", Endpoint: audience}
			if err := connections.Save(config, profile, true); err != nil {
				t.Fatal(err)
			}
			if err := connections.SaveCredential(config, profile.Name, connections.Credential{Endpoint: audience, Token: "previous-token"}); err != nil {
				t.Fatal(err)
			}
			code, out, errout := runCLI(t.Context(), "--config", config, "login", "--token-file", tokenFileFixture(t), "--credential-store", "file")
			if code == exitOK || strings.Contains(out+errout, fixSecret) {
				t.Fatalf("bad import result: code=%d", code)
			}
			if scenario == "missing-scope" && !strings.Contains(errout, "account:read") {
				t.Fatal("missing-scope error omitted import requirement")
			}
			saved, err := connections.CredentialFor(t.Context(), config, profile.Name, profile.Endpoint)
			if err != nil || saved.Token != "previous-token" {
				t.Fatal("failed import replaced existing credential")
			}
		})
	}
}

func TestLoginTokenPersistenceFailureDoesNotRevokeExistingCredential(t *testing.T) {
	t.Setenv(accountKeyEnv, "")
	dir := cliSecretToolFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "secret-tool"), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	var audience string
	revoked := false
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/credential", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, 200, client.CredentialStatus{ID: "credential-id", Kind: "api", Audience: audience, Scopes: []string{"account:read", "measurements:read"}, ExpiresAt: time.Now().Add(time.Hour).Unix()})
	})
	mux.HandleFunc("POST /auth/logout", func(w http.ResponseWriter, r *http.Request) { revoked = true; w.WriteHeader(204) })
	fx := newFixture(t, mux)
	audience = fx.endpoint()
	config := filepath.Join(t.TempDir(), "config.json")
	if err := connections.Save(config, connections.Profile{Name: "ci", Endpoint: audience}, true); err != nil {
		t.Fatal(err)
	}
	code, out, errout := runCLI(t.Context(), "--config", config, "login", "--token-file", tokenFileFixture(t), "--credential-store", "system")
	if code == exitOK || revoked || strings.Contains(out+errout, fixSecret) {
		t.Fatalf("import persistence failure: code=%d revoked=%v", code, revoked)
	}
}

func TestReadAPITokenRejectsUnsafeFiles(t *testing.T) {
	for _, scenario := range []string{"missing", "directory", "symlink", "public", "oversize", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			path := tokenFileFixture(t)
			switch scenario {
			case "missing":
				path += "-missing"
			case "directory":
				path = t.TempDir()
			case "symlink":
				link := path + "-link"
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "public":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(path, []byte(strings.Repeat("x", maxAccountKeyFile+1)), 0600); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err := os.WriteFile(path, []byte(" \n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := readAPIToken(path); err == nil {
				t.Fatal("unsafe token file accepted")
			}
		})
	}
}

func TestLoginTokenRejectsMixedAuthenticationModes(t *testing.T) {
	t.Setenv(accountKeyEnv, "")
	code, out, errout := runCLI(t.Context(), "login", "--token-file", "")
	assertCode(t, code, exitUsage, out, errout)
	for _, flags := range [][]string{{"--browser"}, {"--no-browser"}, {"--register", "Alice"}, {"--account-key-file", "key"}, {"--scopes", "measurements:read"}, {"--recovery-file", "recovery"}} {
		args := append([]string{"login", "--token-file", "unused"}, flags...)
		code, out, errout := runCLI(t.Context(), args...)
		assertCode(t, code, exitUsage, out, errout)
	}
	t.Setenv(accountKeyEnv, fixSecret)
	code, out, errout = runCLI(t.Context(), "login", "--token-file", "unused")
	assertCode(t, code, exitUsage, out, errout)
	if strings.Contains(out+errout, fixSecret) {
		t.Fatal("environment key leaked")
	}
}
