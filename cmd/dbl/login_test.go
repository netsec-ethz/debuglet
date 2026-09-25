package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func TestLoginRegisterOutput(t *testing.T) {
	const recovery = "SECRET-RECOVERY-DO-NOT-PRINT"
	const token = "SECRET-SESSION-DO-NOT-PRINT"
	for _, output := range []string{outputHuman, outputJSON} {
		t.Run(output, func(t *testing.T) {
			config := filepath.Join(t.TempDir(), "config.json")
			mux := http.NewServeMux()
			mux.HandleFunc("PUT /user", func(w http.ResponseWriter, r *http.Request) {
				writeJSONResponse(w, http.StatusOK, client.Account{
					Name: "Alice", AccountKey: fixSecret, RecoveryCode: recovery,
				})
			})
			mux.HandleFunc("POST /auth/login", func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					AccountKey string `json:"account_key"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AccountKey != fixSecret {
					t.Error("login did not use the registered account key")
				}
				writeJSONResponse(w, http.StatusOK, client.Session{Name: "Alice", Role: "user", Token: token})
			})
			fx := newFixture(t, mux)
			if err := connections.Save(config, connections.Profile{Name: "saved", Endpoint: fx.endpoint()}, true); err != nil {
				t.Fatal(err)
			}
			code, out, errout := runCLI(context.Background(), "--config", config, "--output", output, "login", "--register", "Alice")
			assertCode(t, code, exitOK, out, errout)
			notice := out
			if output == outputJSON {
				if doc := oneJSONDocument(t, out); doc["account"] != "Alice" || doc["dispatcher"] != "saved" {
					t.Fatalf("unexpected login result: %v", doc)
				}
				notice = errout
			} else if errout != "" || !strings.Contains(out, "Logged in to saved") {
				t.Fatalf("unexpected human output: stdout=%q stderr=%q", out, errout)
			}
			for _, secret := range []string{fixSecret, recovery, token} {
				if strings.Contains(out, secret) || strings.Contains(errout, secret) {
					t.Fatal("credential leaked into command output")
				}
			}
			for name, secret := range map[string]string{"account-key-saved.txt": fixSecret, "recovery-saved.txt": recovery} {
				path := filepath.Join(filepath.Dir(config), name)
				if !strings.Contains(notice, path) {
					t.Fatalf("registration notice missing credential path %s: %q", path, notice)
				}
				if _, err := writeIssuedCredential(config, name, "", "replacement"); err == nil {
					t.Fatal("existing credential was overwritten")
				}
				data, err := os.ReadFile(path)
				if err != nil || string(data) != secret+"\n" {
					t.Fatalf("credential file contents changed: %v", err)
				}
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != connections.CredentialFileMode {
					t.Fatalf("credential file is not owner-only: %v", err)
				}
			}
			credential, err := connections.CredentialFor(config, "saved", fx.endpoint())
			if err != nil || credential.Token != token {
				t.Fatalf("session was not stored: %v", err)
			}
		})
	}
}

func TestLoginRegisterReservesBothCredentialFilesBeforeCreatingAccount(t *testing.T) {
	for _, existing := range []string{"account-key-saved.txt", "recovery-saved.txt"} {
		t.Run(existing, func(t *testing.T) {
			config := filepath.Join(t.TempDir(), "config.json")
			created := 0
			mux := http.NewServeMux()
			mux.HandleFunc("PUT /user", func(w http.ResponseWriter, r *http.Request) {
				created++
				writeJSONResponse(w, http.StatusOK, client.Account{
					Name: "Alice", AccountKey: fixSecret, RecoveryCode: "recovery",
				})
			})
			fx := newFixture(t, mux)
			if err := connections.Save(config, connections.Profile{Name: "saved", Endpoint: fx.endpoint()}, true); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(filepath.Dir(config), existing)
			if err := os.WriteFile(path, []byte("keep\n"), connections.CredentialFileMode); err != nil {
				t.Fatal(err)
			}

			code, out, errout := runCLI(context.Background(), "--config", config, "login", "--register", "Alice")
			if code != exitFailure || created != 0 || out != "" || !strings.Contains(errout, "already exists") {
				t.Fatalf("registration was not stopped before account creation: code=%d created=%d stdout=%q stderr=%q", code, created, out, errout)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "keep\n" {
				t.Fatalf("existing credential changed: data=%q err=%v", data, err)
			}
			other := "account-key-saved.txt"
			if existing == other {
				other = "recovery-saved.txt"
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(config), other)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unused reservation was not removed: %v", err)
			}
		})
	}
}

func TestLoginReplacesCredentialAfterProfileEndpointChanges(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config.json")
	keyFile := filepath.Join(t.TempDir(), "account-key.txt")
	if err := os.WriteFile(keyFile, []byte(fixSecret+"\n"), connections.CredentialFileMode); err != nil {
		t.Fatal(err)
	}
	loginCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/login", func(w http.ResponseWriter, r *http.Request) {
		loginCalls++
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("login presented the old endpoint's credential: %q", got)
		}
		writeJSONResponse(w, http.StatusOK, client.Session{Name: "Alice", Role: "user", Token: "new-session"})
	})
	fx := newFixture(t, mux)
	if err := connections.Save(config, connections.Profile{Name: "saved", Endpoint: fx.endpoint()}, true); err != nil {
		t.Fatal(err)
	}
	if err := connections.SaveCredential(config, "saved", connections.Credential{Endpoint: "http://127.0.0.1:1", Token: "old-session"}); err != nil {
		t.Fatal(err)
	}

	code, out, errout := runCLI(context.Background(), "--config", config, "login", "--account-key-file", keyFile)
	assertCode(t, code, exitOK, out, errout)
	if loginCalls != 1 {
		t.Fatalf("login requests=%d, want 1", loginCalls)
	}
	credential, err := connections.CredentialFor(config, "saved", fx.endpoint())
	if err != nil || credential.Token != "new-session" {
		t.Fatalf("new endpoint credential was not stored: credential=%+v err=%v", credential, err)
	}
}

func TestLogoutForgetsCredentialAfterProfileEndpointChanges(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config.json")
	requests := 0
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/logout", func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	})
	fx := newFixture(t, mux)
	if err := connections.Save(config, connections.Profile{Name: "saved", Endpoint: fx.endpoint()}, true); err != nil {
		t.Fatal(err)
	}
	if err := connections.SaveCredential(config, "saved", connections.Credential{Endpoint: "http://127.0.0.1:1", Token: "old-session"}); err != nil {
		t.Fatal(err)
	}

	code, out, errout := runCLI(context.Background(), "--config", config, "logout")
	assertCode(t, code, exitOK, out, errout)
	if requests != 0 {
		t.Fatalf("logout sent the old endpoint's credential to the new endpoint: requests=%d", requests)
	}
	store, err := connections.LoadCredentials(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := store.Credentials["saved"]; found {
		t.Fatal("mismatched local credential was not forgotten")
	}
}
