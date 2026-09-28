//go:build linux || darwin

package demo

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

// A database is created in an empty directory this administrator owns, which
// is what an installation has just made or was interrupted while filling, and
// adopted wherever one is already there. An entry that is not a database file
// is refused rather than resolved, so nothing is ever created through it.
func TestPrepareRoleDatabaseCreatesOnceAndAdoptsAfterwards(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path, created, err := PrepareRoleDatabase(ctx, storagecheck.Executor, dir)
	if err != nil || !created {
		t.Fatalf("first use = (%v, %v), want a created database", created, err)
	}
	made, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	again, createdAgain, err := PrepareRoleDatabase(ctx, storagecheck.Executor, dir)
	if err != nil || again != path || createdAgain {
		t.Fatalf("second use = (%q, %v, %v), want the same database, adopted", again, createdAgain, err)
	}
	adopted, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(made, adopted) {
		t.Fatal("the second call replaced the database the first one made")
	}

	// A link where the database belongs names a file this call must not
	// create: it is refused, and nothing appears at the other end.
	other := t.TempDir()
	if err := os.Chmod(other, 0700); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(t.TempDir(), "elsewhere.sqlite")
	if err := os.Symlink(elsewhere, RoleDatabase(other, storagecheck.Executor)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PrepareRoleDatabase(ctx, storagecheck.Executor, other); err == nil {
		t.Fatal("a link in place of the database was accepted")
	}
	if _, err := os.Lstat(elsewhere); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a database was created through the link: %v", err)
	}
}
