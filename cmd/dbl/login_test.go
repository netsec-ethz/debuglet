package main

import (
	"context"
	"encoding/json"
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
