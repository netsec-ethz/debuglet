package main

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func TestWhoamiSavedSession(t *testing.T) {
	const token = "whoami-session-secret"
	for _, mode := range []string{outputHuman, outputJSON} {
		for _, state := range []string{"valid", "missing", "expired", "revoked"} {
			t.Run(mode+"/"+state, func(t *testing.T) {
				mux := http.NewServeMux()
				mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer "+token {
						t.Error("saved session was not presented")
					}
					if state == "revoked" {
						writeJSONResponse(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "unauthorized", "message": token}})
						return
					}
					writeJSONResponse(w, http.StatusOK, client.User{ID: "account-123", Name: "Alice", Role: "user"})
				})
				fx := newFixture(t, mux)
				path := filepath.Join(t.TempDir(), "config.json")
				if err := connections.Save(path, connections.Profile{Name: "saved", Endpoint: fx.endpoint()}, true); err != nil {
					t.Fatal(err)
				}
				if state != "missing" {
					expiry := time.Now().Add(time.Hour).Unix()
					if state == "expired" {
						expiry = 1
					}
					if err := connections.SaveCredential(path, "saved", connections.Credential{Endpoint: fx.endpoint(), Token: token, ExpiresAt: expiry}); err != nil {
						t.Fatal(err)
					}
				}
				code, out, errout := runCLI(context.Background(), "--config", path, "--output", mode, "whoami")
				if strings.Contains(out+errout, token) {
					t.Fatal("credential appeared in output")
				}
				if state == "valid" {
					assertCode(t, code, exitOK, out, errout)
					if !strings.Contains(out, "account-123") || !strings.Contains(out, "Alice") {
						t.Fatalf("missing identity: %s", out)
					}
					if mode == outputJSON {
						oneJSONDocument(t, out)
					}
				} else {
					assertCode(t, code, exitFailure, out, errout)
					if out != "" || !strings.Contains(errout, "dbl login") {
						t.Fatalf("missing login hint: stdout=%q stderr=%q", out, errout)
					}
				}
				if (state == "missing" || state == "expired") && fx.total() != 0 {
					t.Fatal("request made without a usable saved session")
				}
			})
		}
	}
}
