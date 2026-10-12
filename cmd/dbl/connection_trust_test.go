// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func TestConnectPrivateCAPersistsForLaterCommands(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			writeJSONResponse(w, 200, client.ServerVersion{Version: "trust-fixture"})
		case "/executors":
			writeJSONResponse(w, 200, []client.Node{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "authority.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"explicit", "environment"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("SSL_CERT_FILE", "")
			config := filepath.Join(t.TempDir(), "config.json")
			invoke := func(args ...string) (int, string, string) {
				return runCLI(context.Background(), append([]string{"--config", config}, args...)...)
			}
			code, out, errout := invoke("connect", server.URL)
			if code == exitOK {
				t.Fatal("accepted private server without trust")
			}
			args := []string{"connect", server.URL}
			if mode == "explicit" {
				args = append(args, "--ca-file", ca)
			} else {
				t.Setenv("SSL_CERT_FILE", ca)
			}
			code, out, errout = invoke(args...)
			assertCode(t, code, exitOK, out, errout)
			profile, err := connections.Resolve(config, "")
			if err != nil {
				t.Fatal(err)
			}
			if mode == "explicit" && profile.CAFile != ca {
				t.Fatalf("CA path not saved: %+v", profile)
			}
			code, out, errout = invoke("nodes")
			assertCode(t, code, exitOK, out, errout)
			// Login uses the credential-free profile constructor and needs the same trust.
			c, _, code, ok := connectProfileWithoutCredential("test", globalOptions{ConfigPath: config}, os.Stderr)
			if !ok || code != exitOK {
				t.Fatalf("credential-free client: %d", code)
			}
			if _, err := c.Version(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConnectInvalidCAIsNotSaved(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(ca, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "config.json")
	code, _, _ := runCLI(context.Background(), "--config", config, "connect", "https://example.invalid", "--ca-file", ca)
	if code == exitOK {
		t.Fatal("accepted invalid CA")
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatalf("saved failed connection: %v", err)
	}
}

func TestLogoutForgetsCredentialWhenCATrustIsUnavailable(t *testing.T) {
	for _, source := range []string{"saved", "environment"} {
		t.Run(source, func(t *testing.T) {
			for _, state := range []string{"missing", "invalid"} {
				t.Run(state, func(t *testing.T) {
					t.Setenv("SSL_CERT_FILE", "")
					var requests atomic.Int32
					server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusNoContent) }))
					defer server.Close()
					config := filepath.Join(t.TempDir(), "config.json")
					ca := filepath.Join(t.TempDir(), "authority.pem")
					if state == "invalid" {
						if err := os.WriteFile(ca, []byte("not a certificate"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					profile := connections.Profile{Name: "saved", Endpoint: server.URL}
					if source == "saved" {
						profile.CAFile = ca
					} else {
						t.Setenv("SSL_CERT_FILE", ca)
					}
					if err := connections.Save(config, profile, true); err != nil {
						t.Fatal(err)
					}
					for _, name := range []string{"saved", "other"} {
						if err := connections.SaveCredential(config, name, connections.Credential{Endpoint: server.URL, Token: fixSecret}); err != nil {
							t.Fatal(err)
						}
					}
					code, out, errout := runCLI(context.Background(), "--config", config, "logout")
					assertCode(t, code, exitFailure, out, errout)
					if !strings.Contains(errout, "remote credential revocation") || !strings.Contains(errout, "console Credentials page") {
						t.Fatalf("missing remote revocation guidance: %s", errout)
					}
					if strings.Contains(out+errout, fixSecret) {
						t.Fatal("logout leaked credential")
					}
					if requests.Load() != 0 {
						t.Fatal("logout contacted server without usable CA trust")
					}
					credentials, err := connections.LoadCredentials(config)
					if err != nil {
						t.Fatal(err)
					}
					if _, ok := credentials.Credentials["saved"]; ok {
						t.Fatal("logout kept local credential after trust failed")
					}
					if _, ok := credentials.Credentials["other"]; !ok {
						t.Fatal("logout removed another profile's credential")
					}
				})
			}
		})
	}
}
