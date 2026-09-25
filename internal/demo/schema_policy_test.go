//go:build linux || darwin

package demo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

// TestBootstrappedDatabaseMatchesSchemaPolicy keeps the databases this package
// creates and the schema versions the daemons serve describing the same state.
func TestBootstrappedDatabaseMatchesSchemaPolicy(t *testing.T) {
	ctx := context.Background()
	for _, role := range []SchemaRole{DispatcherSchema, ExecutorSchema} {
		t.Run(string(role), func(t *testing.T) {
			path := filepath.Join(privateSchemaDir(t), string(role)+".sqlite")
			if err := BootstrapFresh(ctx, role, path); err != nil {
				t.Fatalf("bootstrap: %v", err)
			}
			if err := CheckSchema(ctx, role, path); err != nil {
				t.Fatalf("freshly created database refused: %v", err)
			}
		})
	}
	if err := CheckSchema(ctx, SchemaRole("client"), "unused"); err == nil {
		t.Fatal("unknown role accepted")
	}
}

// TestSchemaCheckRefusesUnusableState reports an absent or unusable database
// instead of starting a service on it.
func TestSchemaCheckRefusesUnusableState(t *testing.T) {
	dir := t.TempDir()
	err := CheckSchema(context.Background(), DispatcherSchema, filepath.Join(dir, "dispatcher.sqlite"))
	if err == nil || !strings.Contains(err.Error(), storagecheck.ErrAbsent.Error()) {
		t.Fatalf("absent database: %v", err)
	}
	empty := filepath.Join(dir, "executor.sqlite")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckSchema(context.Background(), ExecutorSchema, empty); err == nil {
		t.Fatal("empty file accepted as a database")
	}
}
