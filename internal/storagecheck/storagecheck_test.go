package storagecheck

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

var packagedMigrations = map[Role]fs.FS{Dispatcher: dispatcherdb.MigrationFS(), Executor: executordb.MigrationFS()}

// fixture applies the packaged migrations of a role to a new database, up to
// version when it is nonzero, and returns the path of the closed file.
func fixture(t *testing.T, role Role, version int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), string(role)+".sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	db.SetMaxOpenConns(1)
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, packagedMigrations[role],
		goose.WithDisableGlobalRegistry(true), goose.WithLogger(goose.NopLogger()))
	if err != nil {
		db.Close()
		t.Fatalf("create fixture provider: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if version == 0 {
		_, err = provider.Up(ctx)
	} else {
		_, err = provider.UpTo(ctx, version)
	}
	if closeErr := provider.Close(); closeErr != nil {
		t.Fatalf("close fixture: %v", closeErr)
	}
	if err != nil {
		t.Fatalf("apply fixture migrations: %v", err)
	}
	return path
}

// modify runs statements against a fixture with a separate connection that is
// closed again before the database is checked.
func modify(t *testing.T, path string, statements ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("modify fixture with %q: %v", statement, err)
		}
	}
}

func digest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read database: %v", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// unchangedBytes verifies that a check left the database itself exactly as it
// was, so a refused database can still be inspected or restored.
func unchangedBytes(t *testing.T, path, before string) {
	t.Helper()
	if after := digest(t, path); after != before {
		t.Fatalf("check modified the database: %s became %s", before, after)
	}
}

// unchanged additionally requires that no companion file was created, which is
// what a database in the default rollback-journal mode must show.
func unchanged(t *testing.T, path, before string) {
	t.Helper()
	unchangedBytes(t, path, before)
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read state directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("check left extra files: %v", entries)
	}
}

// unchangedInWAL is unchanged for a database in WAL mode, where SQLite itself
// may maintain the -wal and -shm companions but nothing else may appear.
func unchangedInWAL(t *testing.T, path, before string) {
	t.Helper()
	unchangedBytes(t, path, before)
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read state directory: %v", err)
	}
	name := filepath.Base(path)
	for _, entry := range entries {
		switch entry.Name() {
		case name, name + "-wal", name + "-shm":
		default:
			t.Fatalf("check left %q next to the database", entry.Name())
		}
	}
}

func schemaVersionOf(t *testing.T, path string) int64 {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer db.Close()
	version, err := schemaVersion(context.Background(), db)
	if err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	return version
}

// TestPolicyMatchesPackagedMigrations keeps the stated policy and the packaged
// migrations describing the same schema.
func TestPolicyMatchesPackagedMigrations(t *testing.T) {
	for _, role := range []Role{Dispatcher, Executor} {
		policy, err := PolicyFor(role)
		if err != nil {
			t.Fatalf("%s policy: %v", role, err)
		}
		if policy.Current <= 0 || policy.Minimum <= 0 || policy.Minimum > policy.Current || len(policy.Tables) == 0 ||
			!policy.Supports(policy.Current) || policy.Supports(policy.Current+1) || policy.Supports(policy.Minimum-1) {
			t.Fatalf("%s policy: %+v", role, policy)
		}
	}
	if _, err := PolicyFor(Role("client")); err == nil {
		t.Fatal("unknown role accepted")
	}
}

// TestFreshDatabaseIsSupported checks that the database the packaged
// migrations produce is exactly what the daemons accept.
func TestFreshDatabaseIsSupported(t *testing.T) {
	for _, role := range []Role{Dispatcher, Executor} {
		t.Run(string(role), func(t *testing.T) {
			policy, err := PolicyFor(role)
			if err != nil {
				t.Fatal(err)
			}
			path := fixture(t, role, 0)
			before := digest(t, path)
			if err := Check(context.Background(), role, path); err != nil {
				t.Fatalf("fresh database refused: %v", err)
			}
			if got := schemaVersionOf(t, path); got != policy.Current {
				t.Fatalf("fresh schema version %d, policy %d", got, policy.Current)
			}
			unchanged(t, path, before)
		})
	}
}

// TestPreviousSupportedSchemaIsServed checks that acceptance follows the stated
// range and not the newest migration: a policy that still supports the previous
// version serves it without applying anything.
func TestPreviousSupportedSchemaIsServed(t *testing.T) {
	current, err := PolicyFor(Dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	previous := current.Current - 1
	if previous < 1 {
		t.Skip("only one packaged migration")
	}
	path := fixture(t, Dispatcher, previous)
	before := digest(t, path)

	policy := Policy{Role: Dispatcher, Minimum: previous, Current: current.Current, Tables: map[string][]string{
		"debuglets":     {"uuid", "state"},
		"debuglet_logs": {"debuglet_id", "output"},
	}}
	if err := policy.Check(context.Background(), path); err != nil {
		t.Fatalf("previous supported schema refused: %v", err)
	}
	if got := schemaVersionOf(t, path); got != previous {
		t.Fatalf("accepted database was migrated to %d", got)
	}
	unchanged(t, path, before)

	// The packaged policy no longer supports it and says so.
	err = Check(context.Background(), Dispatcher, path)
	if !errors.Is(err, ErrOutdated) {
		t.Fatalf("outdated schema: %v", err)
	}
	unchanged(t, path, before)
}

// TestIncompatibleSchemasAreRefused covers the states a supplied database can
// be in, and keeps its bytes unchanged in every refusal.
func TestIncompatibleSchemasAreRefused(t *testing.T) {
	current, err := PolicyFor(Executor)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		version int64
		change  []string
		want    error
	}{
		{
			name:   "future schema",
			change: []string{"INSERT INTO goose_db_version (version_id, is_applied) VALUES (" + strconv.FormatInt(current.Current+1, 10) + ", 1)"},
			want:   ErrNewer,
		},
		{
			name:   "missing table",
			change: []string{"DROP TABLE debuglet_logs"},
			want:   ErrIncomplete,
		},
		{
			name:    "partially applied migration",
			version: current.Current - 1,
			change:  []string{"INSERT INTO goose_db_version (version_id, is_applied) VALUES (" + strconv.FormatInt(current.Current, 10) + ", 1)"},
			want:    ErrIncomplete,
		},
		{
			name:   "no applied migration",
			change: []string{"DELETE FROM goose_db_version"},
			want:   ErrIncomplete,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := fixture(t, Executor, tc.version)
			modify(t, path, tc.change...)
			before := digest(t, path)
			err := Check(context.Background(), Executor, path)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error %v, want %v", err, tc.want)
			}
			unchanged(t, path, before)
		})
	}
}

// TestAbsentStorageIsDistinguished separates a database that does not exist
// from one that exists but cannot be served.
func TestAbsentStorageIsDistinguished(t *testing.T) {
	dir := t.TempDir()
	err := Check(context.Background(), Dispatcher, filepath.Join(dir, "dispatcher.sqlite"))
	if !errors.Is(err, ErrAbsent) {
		t.Fatalf("absent database: %v", err)
	}
	if err := Check(context.Background(), Dispatcher, ""); !errors.Is(err, ErrAbsent) {
		t.Fatalf("unconfigured path: %v", err)
	}
	if err := Check(context.Background(), Dispatcher, dir); !errors.Is(err, ErrUnknown) {
		t.Fatalf("directory as database: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("check created files: %v %v", entries, err)
	}
}

// TestUnknownDatabaseIsRefused covers a file that is not a Debuglet database.
func TestUnknownDatabaseIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "other.sqlite")
	modify(t, path, "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
	before := digest(t, path)
	if err := Check(context.Background(), Executor, path); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unrelated database: %v", err)
	}
	unchanged(t, path, before)

	text := filepath.Join(t.TempDir(), "dispatcher.sqlite")
	if err := os.WriteFile(text, []byte("not a database"), 0600); err != nil {
		t.Fatal(err)
	}
	beforeText := digest(t, text)
	if err := Check(context.Background(), Dispatcher, text); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("file that is not a database: %v", err)
	}
	unchanged(t, text, beforeText)
}

// TestRoleDatabasesAreNotInterchangeable keeps a daemon from serving the other
// role's database, and reports the path rather than a version to change.
func TestRoleDatabasesAreNotInterchangeable(t *testing.T) {
	for _, tc := range []struct {
		served Role
		stored Role
	}{
		{served: Dispatcher, stored: Executor},
		{served: Executor, stored: Dispatcher},
	} {
		t.Run(string(tc.served)+" reading "+string(tc.stored), func(t *testing.T) {
			path := fixture(t, tc.stored, 0)
			before := digest(t, path)
			err := Check(context.Background(), tc.served, path)
			if !errors.Is(err, ErrUnknown) {
				t.Fatalf("other role database: %v", err)
			}
			if !strings.Contains(err.Error(), "is not a "+string(tc.served)+" database") {
				t.Fatalf("error does not name the role: %v", err)
			}
			unchanged(t, path, before)
		})
	}
}

// TestWALDatabaseKeepsItsBytes documents what a check does to a database in
// WAL mode: SQLite may create its -wal and -shm companions, and the database
// itself is still returned unchanged, accepted or refused.
func TestWALDatabaseKeepsItsBytes(t *testing.T) {
	// SQLite records WAL mode in the database header and keeps it across
	// connections, so the fixture stays in WAL mode for the checks below.
	path := fixture(t, Executor, 0)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal mode %q: %v", mode, err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	before := digest(t, path)
	if err := Check(context.Background(), Executor, path); err != nil {
		t.Fatalf("WAL database refused: %v", err)
	}
	unchangedInWAL(t, path, before)

	modify(t, path, "DROP TABLE debuglet_logs")
	before = digest(t, path)
	if err := Check(context.Background(), Executor, path); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("incomplete WAL database: %v", err)
	}
	unchangedInWAL(t, path, before)
}

// TestSymlinkedDatabaseIsFollowed keeps a linked database path usable, as
// SQLite itself follows it.
func TestSymlinkedDatabaseIsFollowed(t *testing.T) {
	path := fixture(t, Executor, 0)
	link := filepath.Join(t.TempDir(), "linked.sqlite")
	if err := os.Symlink(path, link); err != nil {
		t.Fatalf("link database: %v", err)
	}
	before := digest(t, path)
	if err := Check(context.Background(), Executor, link); err != nil {
		t.Fatalf("linked database refused: %v", err)
	}
	unchangedBytes(t, path, before)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := Check(context.Background(), Executor, link); !errors.Is(err, ErrAbsent) {
		t.Fatalf("dangling link: %v", err)
	}
}
