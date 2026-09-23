//go:build linux

package demo

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connections"
)

// TestLocalStartupRefusesUnsupportedSchema keeps a local environment from
// starting a service on state it cannot serve.
func TestLocalStartupRefusesUnsupportedSchema(t *testing.T) {
	f := newSupervisorFixture(t, "unsupported schema")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := up(ctx, f.assets, LocalOptions{StateDir: filepath.Join(t.TempDir(), "state")}, f.deps, time.Second)
	if err == nil || !strings.Contains(err.Error(), "dispatcher database: dispatcher schema sentinel") {
		t.Fatalf("unsupported schema: %v", err)
	}
	if len(f.children) != 0 {
		t.Fatalf("started %d services on an unsupported database", len(f.children))
	}
}

// TestRoleStartupRefusesUnsupportedSchema keeps a separately started role from
// serving or queueing work on state it cannot serve.
func TestRoleStartupRefusesUnsupportedSchema(t *testing.T) {
	f := newSupervisorFixture(t, "unsupported schema")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := upRole(ctx, DispatcherSchema, f.assets, RoleOptions{Name: "service", StateDir: filepath.Join(t.TempDir(), "service"),
		Dispatcher: connections.Profile{Endpoint: f.server.URL},
		Ready:      func(RoleEnvironment) error { t.Error("role reported readiness"); return nil }}, f.deps, time.Second)
	if err == nil || !strings.Contains(err.Error(), "dispatcher database: dispatcher schema sentinel") {
		t.Fatalf("unsupported schema: %v", err)
	}
	if len(f.children) != 0 {
		t.Fatalf("started %d services on an unsupported database", len(f.children))
	}
}
