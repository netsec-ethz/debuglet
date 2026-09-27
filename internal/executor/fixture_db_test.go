package executor

import (
	"database/sql"
	"path/filepath"
	"testing"

	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

// newFixtureDatabase opens one private file-backed executor database per test,
// limited to a single connection, and applies the checked-in executor
// migrations. Closing the database is registered before the caller builds
// anything on it, so cleanup the caller registers afterwards joins its own work
// before the database goes away.
func newFixtureDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "executor.sqlite"), sqlitedb.Create())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := sqlitedb.Migrate(t.Context(), db, executordb.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}
