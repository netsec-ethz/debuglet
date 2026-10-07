// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	dconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/api"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"go.uber.org/zap"
)

// The drill uses ordinary account creation, authentication and authorization.
// The loopback development authentication bypass is deliberately disabled.
type abuseDrillAPI struct {
	server  *httptest.Server
	client  *client.Client
	account client.Account
	session client.Session
}

func newAbuseDrillAPI(t *testing.T, d *dispatcher.Dispatcher, db *sql.DB) *abuseDrillAPI {
	t.Helper()
	e := echo.New()
	s := httptest.NewServer(e)
	t.Cleanup(s.Close)
	api.NewHandler(d, db, zap.NewNop(), api.Authentication(s.URL, s.URL+"/device")).RegisterRoutes(e)
	c, err := client.New(s.URL, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	account, err := c.CreateAccount(t.Context(), "owned drill operator")
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.Login(t.Context(), account.AccountKey)
	if err != nil {
		t.Fatal(err)
	}
	return &abuseDrillAPI{server: s, client: c, account: account, session: session}
}

func (a *abuseDrillAPI) request(ctx context.Context, method, path, token string, browser bool, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.server.URL+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if browser {
		req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
		req.Header.Set("X-Debuglet-CSRF", a.session.CSRFToken)
	} else if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := a.server.Client().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	return response.StatusCode, data, err
}

func (a *abuseDrillAPI) expect(t *testing.T, method, path, token string, browser bool, body any, want int) []byte {
	t.Helper()
	status, data, err := a.request(t.Context(), method, path, token, browser, body)
	if err != nil || status != want {
		t.Fatalf("%s %s: HTTP %d, want %d (transport error: %v)", method, path, status, want, err)
	}
	return data
}

// TestCredentialCompromiseDrill runs the copied-credential and account-key
// recovery procedure against a real local API and SQLite database. Logs retain
// only credential identifiers and observed HTTP outcomes, never secrets.
func TestCredentialCompromiseDrill(t *testing.T) {
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "dispatcher.sqlite"), sqlitedb.Create())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatal(err)
	}
	payments, err := payments.NewPaymentHandler(db, &dconfig.DispatcherConfig{Sui: dconfig.SuiConfig{Disabled: true}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	d, err := dispatcher.New(zap.NewNop(), db, "abuse-drill", time.Second, time.Second, payments)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	a := newAbuseDrillAPI(t, d, db)
	issued := api.IssuedCredential{}
	data := a.expect(t, http.MethodPost, "/me/credentials", a.session.Token, true,
		api.CredentialRequest{Audience: a.server.URL, Scopes: []string{"account:read"}, Label: "owned compromise drill"}, http.StatusCreated)
	if err := json.Unmarshal(data, &issued); err != nil {
		t.Fatal(err)
	}
	a.expect(t, http.MethodGet, "/me", issued.Token, false, nil, http.StatusOK)
	a.expect(t, http.MethodDelete, "/me/credentials/"+issued.CredentialID, a.session.Token, true, nil, http.StatusNoContent)
	a.expect(t, http.MethodGet, "/me", issued.Token, false, nil, http.StatusUnauthorized)
	t.Logf("incident=copied-credential at=%s account=%s credential_id=%s actions=revoke observed=200->401", time.Now().UTC().Format(time.RFC3339Nano), a.account.ID, issued.CredentialID)
	// A separately retained account recovery code is the recovery route when
	// the legacy account key itself is exposed. It invalidates old sessions.
	recovered, err := a.client.Recover(t.Context(), a.account.RecoveryCode)
	if err != nil {
		t.Fatal(err)
	}
	a.expect(t, http.MethodGet, "/me", a.session.Token, false, nil, http.StatusUnauthorized)
	a.expect(t, http.MethodPost, "/auth/login", "", false, api.LoginRequest{AccountKey: a.account.AccountKey}, http.StatusUnauthorized)
	newSession, err := a.client.Login(t.Context(), recovered.AccountKey)
	if err != nil {
		t.Fatal(err)
	}
	a.expect(t, http.MethodGet, "/me", newSession.Token, false, nil, http.StatusOK)
	t.Logf("incident=account-key at=%s account=%s actions=recover observed=old-key-401,old-session-401,new-session-200", time.Now().UTC().Format(time.RFC3339Nano), a.account.ID)
}

func (a *abuseDrillAPI) deny(ctx context.Context) error {
	status, _, err := a.request(ctx, http.MethodPatch, "/destination", a.session.Token, false,
		api.DestinationLimitRequest{Destination: "127.0.0.1", Denied: true, Reason: "owned destination operator opt-out drill"})
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("deny answered HTTP %d", status)
	}
	return nil
}
