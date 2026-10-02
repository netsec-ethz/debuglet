// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func cliSecretToolFixture(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Secret Service is supported on Linux")
	}
	dir := t.TempDir()
	tool := `#!/bin/sh
set -eu
case "$1" in
  store) cat > "$CLI_SECRET_FIXTURE/item" ;;
  lookup) cat "$CLI_SECRET_FIXTURE/item" ;;
  clear) rm -f "$CLI_SECRET_FIXTURE/item" ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "secret-tool"), []byte(tool), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/test-owned-session")
	t.Setenv("CLI_SECRET_FIXTURE", dir)
	return dir
}

func TestLoginSystemStorageAndLogout(t *testing.T) {
	dir := cliSecretToolFixture(t)
	config := filepath.Join(t.TempDir(), "config.json")
	revoked := false
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, 200, client.Session{Token: fixSecret, Name: "Alice", Role: "user"})
	})
	mux.HandleFunc("POST /auth/logout", func(w http.ResponseWriter, r *http.Request) {
		revoked = r.Header.Get("Authorization") == "Bearer "+fixSecret
		w.WriteHeader(204)
	})
	fx := newFixture(t, mux)
	if err := connections.Save(config, connections.Profile{Name: "saved", Endpoint: fx.endpoint()}, true); err != nil {
		t.Fatal(err)
	}
	code, out, errout := runCLI(t.Context(), "--config", config, "--output", "json", "login", "--credential-store", "system")
	assertCode(t, code, exitOK, out, errout)
	if oneJSONDocument(t, out)["credential_store"] != "system" || strings.Contains(out+errout, fixSecret) {
		t.Fatal("login output omitted backend or exposed secret")
	}
	file, _ := connections.CredentialPath(config)
	data, _ := os.ReadFile(file)
	if strings.Contains(string(data), fixSecret) {
		t.Fatal("system credential copied to disk metadata")
	}
	code, out, errout = runCLI(t.Context(), "--config", config, "logout")
	assertCode(t, code, exitOK, out, errout)
	if !revoked {
		t.Fatal("logout did not revoke system credential")
	}
	if _, err := os.Stat(filepath.Join(dir, "item")); !os.IsNotExist(err) {
		t.Fatal("logout did not remove system credential")
	}
}

func TestLoginRevokesCredentialWhenPersistenceFails(t *testing.T) {
	dir := cliSecretToolFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "secret-tool"), []byte("#!/bin/sh\nprintf 'secret-error' >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "config.json")
	revoked := false
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, 200, client.Session{Token: fixSecret, Name: "Alice", Role: "user"})
	})
	mux.HandleFunc("POST /auth/logout", func(w http.ResponseWriter, r *http.Request) {
		revoked = r.Header.Get("Authorization") == "Bearer "+fixSecret
		w.WriteHeader(204)
	})
	fx := newFixture(t, mux)
	if err := connections.Save(config, connections.Profile{Name: "saved", Endpoint: fx.endpoint()}, true); err != nil {
		t.Fatal(err)
	}
	code, out, errout := runCLI(t.Context(), "--config", config, "login", "--credential-store", "auto")
	if code == exitOK || !revoked || strings.Contains(out+errout, "secret-error") || strings.Contains(out+errout, fixSecret) {
		t.Fatalf("failed persistence was not safely revoked: code=%d revoked=%v", code, revoked)
	}
	credential, err := connections.CredentialFor(t.Context(), config, "saved", fx.endpoint())
	if err != nil || credential.Token != "" {
		t.Fatal("failed system write fell back to file")
	}
}

func TestLogoutForgetsUnavailableSystemCredential(t *testing.T) {
	dir := cliSecretToolFixture(t)
	config := filepath.Join(t.TempDir(), "config.json")
	const endpoint = "http://127.0.0.1:1"
	if err := connections.Save(config, connections.Profile{Name: "saved", Endpoint: endpoint}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := connections.SaveCredentialWithStorage(t.Context(), config, "saved", connections.Credential{Endpoint: endpoint, Token: fixSecret}, "system"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "item")); err != nil {
		t.Fatal(err)
	}
	code, out, errout := runCLI(t.Context(), "--config", config, "logout")
	if code == exitOK || !strings.Contains(errout, "revoke it from the console") {
		t.Fatalf("unconfirmed revocation reported as success: %d %s %s", code, out, errout)
	}
	credential, err := connections.CredentialFor(t.Context(), config, "saved", endpoint)
	if err != nil || credential.Token != "" {
		t.Fatal("logout left stale system metadata")
	}
}

func TestConnectionKeyringCancellationUsesCommandExitCode(t *testing.T) {
	cliSecretToolFixture(t)
	config := filepath.Join(t.TempDir(), "config.json")
	const endpoint = "http://127.0.0.1:1"
	if err := connections.Save(config, connections.Profile{Name: "saved", Endpoint: endpoint}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := connections.SaveCredentialWithStorage(t.Context(), config, "saved", connections.Credential{Endpoint: endpoint, Token: fixSecret}, "system"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, code, ok := connect(ctx, "dbl nodes", globalOptions{ConfigPath: config}, false, &strings.Builder{})
	if ok || code != 130 {
		t.Fatalf("cancelled keyring lookup returned %d, want 130", code)
	}
}
