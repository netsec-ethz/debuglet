package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/api"

	"github.com/google/uuid"
)

// The local development profile serves every request without a credential as
// this dispatcher's operator, so it is never inferred. It needs both the
// operator's explicit opt-in and an environment this daemon recognises as
// local; a deployment that merely happens to bind loopback behind a proxy,
// with the TLS listener disabled because the proxy terminates and payments
// disabled because it is wallet-free, keeps authentication enforced.
func TestLocalDevelopmentProfileNeedsTheExplicitOptIn(t *testing.T) {
	local := &connectionMetadata{SchemaVersion: 1, Mode: "local-test", GRPCAddress: "127.0.0.1:9001", YamuxAddress: "127.0.0.1:9000"}
	for _, tc := range []struct {
		name      string
		optIn     bool
		metadata  *connectionMetadata
		developed bool
	}{
		{name: "loopback, TLS off and payments off but no opt-in", metadata: local},
		{name: "opt-in on a deployment this daemon does not call local", optIn: true},
		{name: "neither", developed: false},
		{name: "both", optIn: true, metadata: local, developed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dispatcherConfig(filepath.Join(t.TempDir(), "dispatcher.sqlite"))
			cfg.Server.LocalDevelopment = tc.optIn
			if got := localDevelopmentProfile(cfg, tc.metadata); got != tc.developed {
				t.Fatalf("localDevelopmentProfile = %t, want %t", got, tc.developed)
			}
		})
	}
}

// TestConfigurationRefusesTheProfileOutsideALocalEnvironment keeps the opt-in
// from being usable where it would expose a reachable deployment. The static
// keys are checked when the configuration is read; the listener addresses are
// checked once they are bound.
func TestConfigurationRefusesTheProfileOutsideALocalEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*config.DispatcherConfig)
		names  string
	}{
		{name: "TLS listener enabled", change: func(c *config.DispatcherConfig) { c.TLS.Disable = false }, names: "tls.disable"},
		{name: "payments enabled", change: func(c *config.DispatcherConfig) { c.Sui.Disabled = false }, names: "sui.disabled"},
		{name: "every interface", change: func(c *config.DispatcherConfig) { c.Server.BindHost = "" }, names: "server.bind_host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dispatcherConfig(filepath.Join(t.TempDir(), "dispatcher.sqlite"))
			cfg.Server.LocalDevelopment = true
			tc.change(cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.names) {
				t.Fatalf("validate: %v, want a refusal naming %s", err, tc.names)
			}
		})
	}
	// The configuration the local role commands generate is accepted.
	cfg := dispatcherConfig(filepath.Join(t.TempDir(), "dispatcher.sqlite"))
	cfg.Server.LocalDevelopment = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a local environment with the opt-in was refused: %v", err)
	}
}

// TestOperatorRoleIsAdministeredOnTheHost covers the only way to obtain the
// operator role: on the dispatcher host, against the configured database, with
// no HTTP route involved.
func TestOperatorRoleIsAdministeredOnTheHost(t *testing.T) {
	// A fresh database is only created in a private directory of its own.
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "dispatcher.sqlite")
	if err := demo.BootstrapFresh(context.Background(), demo.DispatcherSchema, path); err != nil {
		t.Fatalf("bootstrap database: %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	account := uuid.New()
	if _, err := database.New(db).CreateUser(context.Background(), database.CreateUserParams{Uuid: account, Name: "researcher"}); err != nil {
		t.Fatalf("create account: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := dispatcherConfig(path)

	read := func() string {
		t.Helper()
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		user, err := database.New(db).GetUserByUUID(context.Background(), account)
		if err != nil {
			t.Fatalf("read account: %v", err)
		}
		return user.Role
	}
	if role := read(); role != api.RoleUser {
		t.Fatalf("a new account has role %q, want %q", role, api.RoleUser)
	}
	if err := administerRole(context.Background(), cfg, account.String(), ""); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if role := read(); role != api.RoleOperator {
		t.Fatalf("after granting, role = %q, want %q", role, api.RoleOperator)
	}
	if err := administerRole(context.Background(), cfg, "", account.String()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if role := read(); role != api.RoleUser {
		t.Fatalf("after revoking, role = %q, want %q", role, api.RoleUser)
	}

	// An identifier that names no account is reported, never created.
	if err := administerRole(context.Background(), cfg, uuid.NewString(), ""); err == nil || !strings.Contains(err.Error(), "no account") {
		t.Fatalf("unknown account: %v", err)
	}
	if err := administerRole(context.Background(), cfg, "not-a-uuid", ""); err == nil || !strings.Contains(err.Error(), "not a UUID") {
		t.Fatalf("malformed identifier: %v", err)
	}
	if err := administerRole(context.Background(), cfg, account.String(), account.String()); err == nil {
		t.Fatal("granting and revoking at once was accepted")
	}
	// The same storage checks the daemon applies before serving.
	absent := dispatcherConfig(filepath.Join(dir, "absent.sqlite"))
	if err := administerRole(context.Background(), absent, account.String(), ""); err == nil {
		t.Fatal("an absent database was accepted")
	}
}
