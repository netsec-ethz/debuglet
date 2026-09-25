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
	migrate(t, role, path, version)
	return path
}

// migrate applies the packaged migrations of a role to the database at path,
// up to version when it is nonzero, and closes it again.
func migrate(t *testing.T, role Role, path string, version int64) {
	t.Helper()
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

// count runs a query returning one number against a closed fixture.
func count(t *testing.T, path, query string) int64 {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer db.Close()
	var n int64
	if err := db.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n
}

// populatedDatabase is a schema version just before a migration that changes
// existing tables, one row for every table of that version, and what the rows
// look like once the remaining migrations have been applied.
type populatedDatabase struct {
	name    string
	role    Role
	version int64
	rows    []string
	after   map[string]int64
}

var populated = []populatedDatabase{
	{
		name:    "dispatcher version 7",
		role:    Dispatcher,
		version: 7,
		rows: []string{
			"INSERT INTO transactions (id, auth_key, price, method, expires_at, hash, currency, status) " +
				"VALUES ('tx1', 'key', 10, 'TEST', '2026-01-01 00:00:00', 'hash', 'TEST', 1)",
			"INSERT INTO transaction_states (key, value) VALUES ('checkpoint', '1')",
			"INSERT INTO earnings (executor_id, currency, total_income, current_balance, sui_wallet_address) " +
				"VALUES ('node1', 'TEST', 5, 5, '')",
			"INSERT INTO debuglet_order (transaction_id, order_id, executor_id, price, currency, state, refund_address) " +
				"VALUES ('tx1', 1, 'node1', 5, 'TEST', 1, '')",
			"INSERT INTO debuglet_order (transaction_id, order_id, executor_id, price, currency, state, refund_address) " +
				"VALUES ('tx1', 2, 'node1', 5, 'TEST', 0, '')",
			"INSERT INTO users (uuid, name, role) VALUES (x'00000000000000000000000000000001', 'alice', 'user')",
			"INSERT INTO debuglets (uuid, start_time, end_time, usage, ceil_bw, executor_id, addresses, state, " +
				"transaction_id, order_id, dispatcher_incarnation, session_id) VALUES (x'00000000000000000000000000000002', " +
				"'2026-01-01 00:00:00', '2026-01-01 00:01:00', 1, 1, 'node1', '', 5, 'tx1', 1, 'inc', 'session')",
			"INSERT INTO debuglets (uuid, start_time, end_time, usage, ceil_bw, executor_id, addresses, state, " +
				"transaction_id, order_id, dispatcher_incarnation, session_id) VALUES (x'00000000000000000000000000000003', " +
				"'2026-01-01 00:00:00', '2026-01-01 00:01:00', 1, 1, 'node1', '', 0, 'tx1', 1, 'inc', 'session')",
			"INSERT INTO debuglet_logs (debuglet_id, timestamp, output) VALUES (1, '2026-01-01 00:00:30', x'6869')",
			"INSERT INTO debuglet_users (debuglet_id, user_id) VALUES (1, 1)",
			"INSERT INTO user_credentials (user_id, kind, selector, secret_hash, created_at) " +
				"VALUES (1, 'api', 'sel1', x'00', '2026-01-01 00:00:00')",
			"INSERT INTO sessions (selector, verifier_hash, csrf_hash, user_id, created_at, expires_at) " +
				"VALUES ('sel2', x'00', x'00', 1, '2026-01-01 00:00:00', '2026-01-02 00:00:00')",
			"INSERT INTO transaction_users (transaction_id, user_id) VALUES ('tx1', 1)",
			"INSERT INTO executor_enrollments (executor_id, fingerprint, enrolled_at) VALUES ('node1', 'fp', '2026-01-01 00:00:00')",
			"INSERT INTO executor_enrollment_tokens (selector, executor_id, secret_hash, created_at, expires_at) " +
				"VALUES ('sel3', 'node2', x'00', '2026-01-01 00:00:00', '2026-01-02 00:00:00')",
		},
		// An order that already has runs records the earliest one, and the
		// runs themselves are not changed.
		after: map[string]int64{
			"SELECT COUNT(*) FROM debuglet_order WHERE order_id = 1 AND debuglet_id = 1":                   1,
			"SELECT COUNT(*) FROM debuglet_order WHERE order_id = 2 AND debuglet_id IS NULL":               1,
			"SELECT COUNT(*) FROM debuglets WHERE transaction_id = 'tx1' AND order_id = 1":                 2,
			"SELECT COUNT(*) FROM debuglets WHERE id = 1 AND state = 5 AND session_id = 'session'":         1,
			"SELECT COUNT(*) FROM debuglets WHERE id = 2 AND state = 0 AND dispatcher_incarnation = 'inc'": 1,
			"SELECT COUNT(*) FROM debuglet_logs":                                                           1,
			"SELECT COUNT(*) FROM debuglet_users":                                                          1,
			"SELECT COUNT(*) FROM user_credentials":                                                        1,
			"SELECT COUNT(*) FROM sessions":                                                                1,
			"SELECT COUNT(*) FROM transaction_users":                                                       1,
			"SELECT COUNT(*) FROM executor_enrollments":                                                    1,
			"SELECT COUNT(*) FROM executor_enrollment_tokens":                                              1,
			"SELECT COUNT(*) FROM earnings":                                                                1,
			"SELECT COUNT(*) FROM transactions":                                                            1,
			"SELECT COUNT(*) FROM transaction_states":                                                      1,
		},
	},
	{
		name:    "dispatcher version 3",
		role:    Dispatcher,
		version: 3,
		rows: []string{
			"INSERT INTO transactions (id, auth_key, price, method, expires_at, hash, currency, status) " +
				"VALUES ('tx1', 'key', 10, 'free', '2026-01-01 00:00:00', 'hash', 'SUI', 0)",
			"INSERT INTO transaction_states (key, value) VALUES ('checkpoint', '1')",
			"INSERT INTO earnings (executor_id, currency, total_income, current_balance) VALUES ('node1', 'SUI', 5, 5)",
			"INSERT INTO debuglet_order (transaction_id, order_id, executor_id, price, currency) " +
				"VALUES ('tx1', 1, 'node1', 10, 'SUI')",
			"INSERT INTO users (uuid, name) VALUES (x'00000000000000000000000000000001', 'alice')",
			"INSERT INTO debuglets (uuid, start_time, end_time, usage, ceil_bw, executor_id, addresses, state) " +
				"VALUES (x'00000000000000000000000000000002', '2026-01-01 00:00:00', '2026-01-01 00:01:00', 1, 1, 'node1', '', 0)",
			"INSERT INTO debuglet_logs (debuglet_id, timestamp, output) VALUES (1, '2026-01-01 00:00:30', x'6869')",
			"INSERT INTO debuglet_users (debuglet_id, user_id) VALUES (1, 1)",
		},
		after: map[string]int64{
			"SELECT COUNT(*) FROM debuglets WHERE transaction_id = '' AND order_id = 0 AND session_id = ''": 1,
			"SELECT COUNT(*) FROM debuglet_logs":                                          1,
			"SELECT COUNT(*) FROM debuglet_users":                                         1,
			"SELECT COUNT(*) FROM debuglet_order WHERE state = 0 AND refund_address = ''": 1,
			"SELECT COUNT(*) FROM earnings WHERE sui_wallet_address = ''":                 1,
			"SELECT COUNT(*) FROM users WHERE role = 'user'":                              1,
			"SELECT COUNT(*) FROM transactions":                                           1,
			"SELECT COUNT(*) FROM transaction_states":                                     1,
		},
	},
	{
		name:    "dispatcher version 2",
		role:    Dispatcher,
		version: 2,
		rows: []string{
			"INSERT INTO transactions (id, auth_key, price, method, expires_at, hash, currency, status) " +
				"VALUES ('tx1', 'key', 10, 'free', '2026-01-01 00:00:00', 'hash', 'SUI', 0)",
			"INSERT INTO transaction_states (key, value) VALUES ('checkpoint', '1')",
			"INSERT INTO earnings (executor_id, currency, total_income, current_balance) VALUES ('node1', 'SUI', 5, 5)",
			"INSERT INTO debuglet_order (transaction_id, order_id, executor_id, price, currency) " +
				"VALUES ('tx1', 1, 'node1', 10, 'SUI')",
			"INSERT INTO debuglets (id, start_time, end_time, usage, executor_id, addresses, state) " +
				"VALUES ('run1', '2026-01-01 00:00:00', '2026-01-01 00:01:00', 1, 'node1', '', 0)",
			"INSERT INTO debuglet_logs (debuglet_id, timestamp, output) VALUES ('run1', '2026-01-01 00:00:30', x'6869')",
		},
		// The third dispatcher migration recreates the run tables, so the
		// runs a version 2 database recorded do not survive an upgrade.
		after: map[string]int64{
			"SELECT COUNT(*) FROM debuglets":                                              0,
			"SELECT COUNT(*) FROM debuglet_logs":                                          0,
			"SELECT COUNT(*) FROM debuglet_order WHERE state = 0 AND refund_address = ''": 1,
			"SELECT COUNT(*) FROM earnings WHERE sui_wallet_address = ''":                 1,
			"SELECT COUNT(*) FROM transactions":                                           1,
			"SELECT COUNT(*) FROM transaction_states":                                     1,
		},
	},
	{
		name:    "executor version 1",
		role:    Executor,
		version: 1,
		rows: []string{
			"INSERT INTO debuglets (id, wasm, transaction_id, floor_bw, ceil_bw, timeout_ms, require_icmp, " +
				"listen_udp, listen_tcp, listen_icmp, listen_scion) VALUES ('run1', x'00', 'tx1', 1, 1, 1000, 0, 0, 0, 0, 0)",
			"INSERT INTO debuglet_logs (debuglet_id, timestamp, output) VALUES ('run1', '2026-01-01 00:00:30', x'6869')",
		},
		// The second executor migration recreates both tables, so the runs
		// a version 1 database recorded do not survive an upgrade.
		after: map[string]int64{
			"SELECT COUNT(*) FROM debuglets":     0,
			"SELECT COUNT(*) FROM debuglet_logs": 0,
		},
	},
	{
		name:    "executor version 4",
		role:    Executor,
		version: 4,
		rows: []string{
			"INSERT INTO debuglets (uuid, wasm, transaction_id, floor_bw, ceil_bw, timeout_ms, require_icmp, " +
				"listen_udp, listen_tcp, listen_scion, dispatcher_incarnation, session_id) " +
				"VALUES (x'00000000000000000000000000000001', x'00', 'tx1', 1, 1, 1000, 0, 0, 0, 0, 'incarnation', 'session')",
			"INSERT INTO debuglet_logs (debuglet_id, timestamp, output) VALUES (1, '2026-01-01 00:00:30', x'6869')",
			"INSERT INTO debuglet_exits (debuglet_id, dispatcher_incarnation, session_id, exit_code, recorded_at) " +
				"VALUES ('run1', 'incarnation', 'session', 0, '2026-01-01 00:01:00')",
		},
		// The fifth executor migration only adds the chain record, so the
		// rows of a version 4 database survive and no chain is recorded yet.
		after: map[string]int64{
			"SELECT COUNT(*) FROM debuglets WHERE session_id = 'session'": 1,
			"SELECT COUNT(*) FROM debuglet_logs":                          1,
			"SELECT COUNT(*) FROM debuglet_exits":                         1,
			"SELECT COUNT(*) FROM tesla_chains":                           0,
		},
	},
}

// fixture returns the database at its version, with one row in every table.
// Its daemon refuses it as outdated rather than as another file.
func (d populatedDatabase) fixture(t *testing.T) string {
	t.Helper()
	path := fixture(t, d.role, d.version)
	modify(t, path, d.rows...)
	if err := Check(context.Background(), d.role, path); !errors.Is(err, ErrOutdated) {
		t.Fatalf("%s refused as %v, want %v", d.name, err, ErrOutdated)
	}
	return path
}

func (d populatedDatabase) checkRows(t *testing.T, path string) {
	t.Helper()
	for query, want := range d.after {
		if got := count(t, path, query); got != want {
			t.Errorf("%s: %d, want %d", query, got, want)
		}
	}
}

// TestPackagedMigrationsApplyToPopulatedTables applies the packaged migrations
// to a database that already holds rows, which is the database an upgrade is
// for, and not only to the empty one a new state directory starts with.
func TestPackagedMigrationsApplyToPopulatedTables(t *testing.T) {
	for _, database := range populated {
		t.Run(database.name, func(t *testing.T) {
			policy, err := PolicyFor(database.role)
			if err != nil {
				t.Fatal(err)
			}
			path := database.fixture(t)
			migrate(t, database.role, path, 0)
			if err := Check(context.Background(), database.role, path); err != nil {
				t.Fatalf("upgraded database refused: %v", err)
			}
			if got := schemaVersionOf(t, path); got != policy.Current {
				t.Fatalf("upgraded schema version %d, want %d", got, policy.Current)
			}
			database.checkRows(t, path)
		})
	}
}

// TestOutdatedSchemaNamesTheUpgradeStep keeps the refusal of an older database
// pointing at the step that upgrades it.
func TestOutdatedSchemaNamesTheUpgradeStep(t *testing.T) {
	for _, role := range []Role{Dispatcher, Executor} {
		t.Run(string(role), func(t *testing.T) {
			policy, err := PolicyFor(role)
			if err != nil {
				t.Fatal(err)
			}
			path := fixture(t, role, policy.Minimum-1)
			before := digest(t, path)
			err = Check(context.Background(), role, path)
			if !errors.Is(err, ErrOutdated) {
				t.Fatalf("outdated schema: %v", err)
			}
			for _, want := range []string{path, "debuglet-" + string(role) + " -config", "-upgrade-database", "upgrade-database.yml"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal does not name %q: %v", want, err)
				}
			}
			unchanged(t, path, before)
		})
	}
}

// TestUpgradeBringsAnOlderDatabaseToTheCurrentVersion keeps the rows of an
// older database while the upgrade adds the columns later versions carry, and
// applies the migrations with foreign keys enforced.
func TestUpgradeBringsAnOlderDatabaseToTheCurrentVersion(t *testing.T) {
	for _, database := range populated {
		t.Run(database.name, func(t *testing.T) {
			policy, err := PolicyFor(database.role)
			if err != nil {
				t.Fatal(err)
			}
			path := database.fixture(t)
			version, err := Upgrade(context.Background(), database.role, path)
			if err != nil {
				t.Fatalf("upgrade: %v", err)
			}
			if version != policy.Current || schemaVersionOf(t, path) != policy.Current {
				t.Fatalf("upgraded to %d, recorded %d, want %d", version, schemaVersionOf(t, path), policy.Current)
			}
			if err := Check(context.Background(), database.role, path); err != nil {
				t.Fatalf("upgraded database refused: %v", err)
			}
			database.checkRows(t, path)
		})
	}
}

// TestFailedUpgradeKeepsTheLastCompletedVersion covers a migration that cannot
// apply: the second dispatcher migration adds required columns without a
// default, so a version 1 database holding transactions stays at version 1.
func TestFailedUpgradeKeepsTheLastCompletedVersion(t *testing.T) {
	path := fixture(t, Dispatcher, 1)
	modify(t, path, "INSERT INTO transactions (id, auth_key, price, method, expires_at, paid, hash) "+
		"VALUES ('tx1', 'key', 10, 'free', '2026-01-01 00:00:00', 0, 'hash')")
	if err := Check(context.Background(), Dispatcher, path); !errors.Is(err, ErrOutdated) {
		t.Fatalf("version 1 database: %v", err)
	}
	_, err := Upgrade(context.Background(), Dispatcher, path)
	if err == nil {
		t.Fatal("upgrade of a version 1 database with transactions succeeded")
	}
	for _, want := range []string{"version:2", "records version 1", "run the upgrade again"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("upgrade error does not name %q: %v", want, err)
		}
	}
	if got := schemaVersionOf(t, path); got != 1 {
		t.Fatalf("failed upgrade left version %d, want 1", got)
	}
	if err := Check(context.Background(), Dispatcher, path); !errors.Is(err, ErrOutdated) {
		t.Fatalf("database after a failed upgrade: %v", err)
	}
}

// TestUpgradeIsANoOpOnACurrentDatabase leaves a current database as it is.
func TestUpgradeIsANoOpOnACurrentDatabase(t *testing.T) {
	for _, role := range []Role{Dispatcher, Executor} {
		t.Run(string(role), func(t *testing.T) {
			policy, err := PolicyFor(role)
			if err != nil {
				t.Fatal(err)
			}
			path := fixture(t, role, 0)
			before := digest(t, path)
			version, err := Upgrade(context.Background(), role, path)
			if err != nil || version != policy.Current {
				t.Fatalf("upgrade of a current database: version %d, %v", version, err)
			}
			if got := schemaVersionOf(t, path); got != policy.Current {
				t.Fatalf("schema version %d, want %d", got, policy.Current)
			}
			unchangedBytes(t, path, before)
		})
	}
}

// TestUpgradeRefusesWhatCheckRefuses never migrates a file that is not this
// role's Debuglet database or that a newer build wrote.
func TestUpgradeRefusesWhatCheckRefuses(t *testing.T) {
	policy, err := PolicyFor(Dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(t.TempDir(), "dispatcher.sqlite")
	if _, err := Upgrade(context.Background(), Dispatcher, absent); !errors.Is(err, ErrAbsent) {
		t.Fatalf("absent database: %v", err)
	}
	if _, err := os.Stat(absent); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("upgrade created the absent database: %v", err)
	}

	unrelated := filepath.Join(t.TempDir(), "other.sqlite")
	modify(t, unrelated, "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
	text := filepath.Join(t.TempDir(), "dispatcher.sqlite")
	if err := os.WriteFile(text, []byte("not a database"), 0600); err != nil {
		t.Fatal(err)
	}
	newer := fixture(t, Dispatcher, 0)
	modify(t, newer, "INSERT INTO goose_db_version (version_id, is_applied) VALUES ("+
		strconv.FormatInt(policy.Current+1, 10)+", 1)")
	for _, tc := range []struct {
		name string
		path string
		want error
	}{
		{name: "unrelated database", path: unrelated, want: ErrUnknown},
		{name: "file that is not a database", path: text, want: ErrUnreadable},
		{name: "executor database", path: fixture(t, Executor, 0), want: ErrUnknown},
		{name: "older executor database", path: fixture(t, Executor, 1), want: ErrUnknown},
		{name: "newer schema", path: newer, want: ErrNewer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := digest(t, tc.path)
			if _, err := Upgrade(context.Background(), Dispatcher, tc.path); !errors.Is(err, tc.want) {
				t.Fatalf("error %v, want %v", err, tc.want)
			}
			unchanged(t, tc.path, before)
		})
	}
}
