//go:build linux

package demo

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

// A refusal that depends only on the local state directory is reported
// before the dispatcher is contacted; a usable directory still reports an
// unreachable dispatcher.
func TestRoleUpReportsLocalRefusalBeforeDiscovery(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	foreign := func(t *testing.T, role storagecheck.Role) string {
		dir := filepath.Join(t.TempDir(), "service")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(RoleState{SchemaVersion: 1, Version: "other-version", Identity: "0b6e2f4c-3f65-4c52-9a53-6d0f4f7f3c11", Role: role})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "role-state.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	up := func(t *testing.T, role storagecheck.Role, dir string) error {
		f := newSupervisorFixture(t, "success")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := upRole(ctx, role, f.assets, RoleOptions{Name: "service", StateDir: dir,
			Dispatcher: connections.Profile{Endpoint: unreachable}}, f.deps, 2*time.Second)
		if len(f.children) != 0 {
			t.Fatalf("%d children started before the refusal", len(f.children))
		}
		return err
	}
	const versionRefusal = "state belongs to another installed version"
	const discoveryFailure = "dispatcher connection metadata unavailable"
	for _, tc := range []struct {
		name string
		role storagecheck.Role
		dir  func(*testing.T) string
		want string
	}{
		{"executor with another version", storagecheck.Executor, func(t *testing.T) string { return foreign(t, storagecheck.Executor) }, versionRefusal},
		{"executor with a fresh directory", storagecheck.Executor, func(t *testing.T) string { return filepath.Join(t.TempDir(), "service") }, discoveryFailure},
		{"dispatcher with another version", storagecheck.Dispatcher, func(t *testing.T) string { return foreign(t, storagecheck.Dispatcher) }, versionRefusal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := up(t, tc.role, tc.dir(t))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("up: %v, want %q", err, tc.want)
			}
		})
	}
}
