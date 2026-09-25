package executor

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"
	_ "modernc.org/sqlite"
)

// newFixtureDatabase opens one private file-backed executor database per test,
// limited to a single connection, and applies the checked-in executor
// migrations. Closing the database is registered before the caller builds
// anything on it, so cleanup the caller registers afterwards joins its own work
// before the database goes away.
func newFixtureDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "executor.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	testutil.ApplyMigrations(t, db, "database/migrations")
	return db
}
