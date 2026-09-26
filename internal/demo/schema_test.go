//go:build linux || darwin

package demo

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
)

func TestBootstrapFresh(t *testing.T) {
	for _, role := range []SchemaRole{DispatcherSchema, ExecutorSchema} {
		t.Run(string(role), func(t *testing.T) {
			// '?' must remain part of the filename, never a DSN option delimiter.
			parent := privateSchemaDir(t)
			path := filepath.Join(parent, "demo space ?mode=ro&x=#%.sqlite")
			if err := BootstrapFresh(t.Context(), role, path); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				t.Fatalf("database mode: info=%v err=%v", info, err)
			}
			db := openSchemaDB(t, path)
			if role == DispatcherSchema {
				assertSchema(t, db, map[string]string{
					"debuglets":                  "id uuid start_time end_time usage ceil_bw executor_id addresses state error transaction_id order_id dispatcher_incarnation session_id",
					"debuglet_logs":              "id debuglet_id timestamp output",
					"transactions":               "id auth_key price method expires_at hash currency status",
					"transaction_states":         "key value",
					"earnings":                   "executor_id currency total_income current_balance sui_wallet_address",
					"debuglet_order":             "transaction_id order_id executor_id price currency state refund_address debuglet_id",
					"users":                      "id uuid name role",
					"debuglet_users":             "debuglet_id user_id",
					"user_credentials":           "user_id kind selector secret_hash created_at",
					"sessions":                   "id selector verifier_hash csrf_hash user_id created_at expires_at revoked",
					"transaction_users":          "transaction_id user_id",
					"executor_enrollments":       "executor_id fingerprint enrolled_at",
					"executor_enrollment_tokens": "selector executor_id secret_hash created_at expires_at",
					"oauth_identities":           "provider subject user_id login created_at updated_at",
				}, []string{"debuglets_uuid_idx", "executor_enrollment_tokens_executor_idx", "sessions_user_idx", "users_uuid_idx"}, []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
				dispatcherSchemaRoundTrip(t, db)
			} else {
				assertSchema(t, db, map[string]string{
					"debuglets":      "id uuid start_time args wasm transaction_id floor_bw ceil_bw timeout_ms addresses require_icmp listen_udp listen_tcp listen_scion started_at dispatcher_incarnation session_id",
					"debuglet_logs":  "id debuglet_id timestamp output",
					"debuglet_exits": "debuglet_id dispatcher_incarnation session_id exit_code error_message recorded_at attempts last_attempt_at last_error rejected",
					"tesla_chains":   "generation anchor epoch_base delay_ns chain_length created_at",
				}, []string{"debuglet_exits_binding_idx", "debuglets_uuid_idx"}, []int64{0, 1, 2, 3, 4, 5})
				executorSchemaRoundTrip(t, db)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := BootstrapFresh(t.Context(), role, path); !errors.Is(err, fs.ErrExist) {
				t.Fatalf("second bootstrap must reject existing database: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("existing migrated database changed: %v", err)
			}
			assertSchemaFiles(t, parent, filepath.Base(path))
		})
	}

	t.Run("invalid role before filesystem work", func(t *testing.T) {
		parent := privateSchemaDir(t)
		path := filepath.Join(parent, "missing", "demo.sqlite")
		if err := BootstrapFresh(t.Context(), "invalid", path); err == nil || !strings.Contains(err.Error(), "unknown demo schema role") {
			t.Fatalf("role validation: %v", err)
		}
		assertSchemaFiles(t, parent)
	})

	for _, contents := range []string{"", "unrelated existing data"} {
		t.Run("existing path "+contents, func(t *testing.T) {
			parent := privateSchemaDir(t)
			path := filepath.Join(parent, "existing.sqlite")
			writeSchemaFile(t, path, contents)
			if err := BootstrapFresh(t.Context(), DispatcherSchema, path); !errors.Is(err, fs.ErrExist) {
				t.Fatalf("existing file accepted: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != contents {
				t.Fatalf("existing file changed: %q, %v", got, err)
			}
			assertSchemaFiles(t, parent, "existing.sqlite")
		})
	}

	for _, dangling := range []bool{false, true} {
		name := "symlink"
		if dangling {
			name = "dangling symlink"
		}
		t.Run(name, func(t *testing.T) {
			parent := privateSchemaDir(t)
			target := filepath.Join(privateSchemaDir(t), "target")
			if !dangling {
				writeSchemaFile(t, target, "keep target")
			}
			path := filepath.Join(parent, "demo.sqlite")
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			if err := BootstrapFresh(t.Context(), ExecutorSchema, path); !errors.Is(err, fs.ErrExist) {
				t.Fatalf("symlink accepted: %v", err)
			}
			if got, err := os.Readlink(path); err != nil || got != target {
				t.Fatalf("symlink changed: %q, %v", got, err)
			}
			got, err := os.ReadFile(target)
			if dangling && !errors.Is(err, fs.ErrNotExist) || !dangling && (err != nil || string(got) != "keep target") {
				t.Fatalf("symlink target changed: %q, %v", got, err)
			}
			assertSchemaFiles(t, parent, "demo.sqlite")
		})
	}

	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		t.Run("existing sidecar "+suffix, func(t *testing.T) {
			parent := privateSchemaDir(t)
			path := filepath.Join(parent, "demo.sqlite")
			writeSchemaFile(t, path+suffix, "unrelated sidecar")
			if err := BootstrapFresh(t.Context(), ExecutorSchema, path); !errors.Is(err, fs.ErrExist) {
				t.Fatalf("existing sidecar accepted: %v", err)
			}
			got, err := os.ReadFile(path + suffix)
			if err != nil || string(got) != "unrelated sidecar" {
				t.Fatalf("existing sidecar changed: %q, %v", got, err)
			}
			assertSchemaFiles(t, parent, "demo.sqlite"+suffix)
		})
	}

	t.Run("private real parent required", func(t *testing.T) {
		parent := privateSchemaDir(t)
		public := filepath.Join(parent, "public")
		if err := os.Mkdir(public, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(public, 0755); err != nil {
			t.Fatal(err)
		}
		linked := filepath.Join(parent, "linked")
		if err := os.Symlink(privateSchemaDir(t), linked); err != nil {
			t.Fatal(err)
		}
		for _, dir := range []string{public, linked, filepath.Join(parent, "missing")} {
			if err := BootstrapFresh(t.Context(), ExecutorSchema, filepath.Join(dir, "db")); err == nil {
				t.Fatalf("invalid parent accepted: %s", dir)
			}
			if _, err := os.Lstat(filepath.Join(dir, "db")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("created file under invalid parent: %v", err)
			}
		}
	})

	t.Run("provider parse failure cleanup", func(t *testing.T) {
		parent := privateSchemaDir(t)
		writeSchemaFile(t, filepath.Join(parent, "keep"), "unrelated")
		migrations := fstest.MapFS{"00001_invalid.sql": {Data: []byte("not a goose migration")}}
		if err := bootstrapFresh(t.Context(), filepath.Join(parent, "demo.sqlite"), migrations); err == nil {
			t.Fatal("invalid migration succeeded")
		}
		assertSchemaFiles(t, parent, "keep")
	})

	t.Run("failed SQL and WAL cleanup", func(t *testing.T) {
		parent := privateSchemaDir(t)
		writeSchemaFile(t, filepath.Join(parent, "keep"), "unrelated")
		migrations := fstest.MapFS{
			"00001_wal.sql":  {Data: []byte("-- +goose NO TRANSACTION\n-- +goose Up\nPRAGMA journal_mode=WAL;\nCREATE TABLE applied(id INTEGER);\nINSERT INTO applied VALUES (1);\n")},
			"00002_fail.sql": {Data: []byte("-- +goose Up\nINSERT INTO missing_table VALUES (1);\n")},
		}
		err := bootstrapFresh(t.Context(), filepath.Join(parent, "demo.sqlite"), migrations)
		if err == nil || !strings.Contains(err.Error(), "missing_table") {
			t.Fatalf("did not reach failing SQL after WAL migration: %v", err)
		}
		assertSchemaFiles(t, parent, "keep")
	})

	t.Run("connection pragmas", func(t *testing.T) {
		parent := privateSchemaDir(t)
		migrations := fstest.MapFS{"00001_pragmas.sql": {Data: []byte(`-- +goose Up
CREATE TABLE pragma_check(value INTEGER NOT NULL CHECK (value = 1000));
INSERT INTO pragma_check SELECT timeout FROM pragma_busy_timeout;
CREATE TABLE parent(id INTEGER PRIMARY KEY);
CREATE TABLE child(parent_id INTEGER REFERENCES parent(id));
INSERT INTO child VALUES (123);
`)}}
		err := bootstrapFresh(t.Context(), filepath.Join(parent, "demo.sqlite"), migrations)
		if err == nil || !strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
			t.Fatalf("busy timeout/foreign key enforcement: %v", err)
		}
		assertSchemaFiles(t, parent)
	})

	t.Run("cancel before creation", func(t *testing.T) {
		parent := privateSchemaDir(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := BootstrapFresh(ctx, DispatcherSchema, filepath.Join(parent, "db")); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
		assertSchemaFiles(t, parent)
	})

	t.Run("cancel running SQLite migration", func(t *testing.T) {
		parent := privateSchemaDir(t)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		migrations := fstest.MapFS{"00001_slow.sql": {Data: []byte(`-- +goose NO TRANSACTION
-- +goose Up
CREATE TABLE running(value INTEGER);
INSERT INTO running WITH RECURSIVE slow(value) AS (
  VALUES (0) UNION ALL SELECT value + 1 FROM slow WHERE value < 1000000000
) SELECT sum(value) FROM slow;
`)}}
		path := filepath.Join(parent, "demo.sqlite")
		done := make(chan error, 1)
		go func() { done <- bootstrapFresh(ctx, path, migrations) }()
		// Observe the first committed statement through a second real SQLite
		// connection. Cancellation must happen after migration execution starts.
		observer := openSchemaDB(t, path)
		observed := false
		for !observed && ctx.Err() == nil {
			var count int
			err := observer.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE name='running'").Scan(&count)
			observed = err == nil && count == 1
			if !observed {
				select {
				case err := <-done:
					t.Fatalf("migration ended before cancellation: %v", err)
				case <-time.After(time.Millisecond):
				}
			}
		}
		if err := observer.Close(); err != nil {
			t.Error(err)
		}
		start := time.Now()
		cancel()
		var err error
		select {
		case err = <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("running SQL did not stop within two seconds of cancellation")
		}
		if !observed {
			t.Fatal("did not observe the migration executing before deadline")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("running SQL cancellation: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("SQL cancellation took %s", elapsed)
		}
		assertSchemaFiles(t, parent)
	})
}

func privateSchemaDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeSchemaFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func assertSchemaFiles(t *testing.T, parent string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(entries))
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("files after bootstrap = %q; want %q", got, want)
	}
}

func openSchemaDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=rw"}
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

func assertSchema(t *testing.T, db *sql.DB, tables map[string]string, indexes []string, versions []int64) {
	t.Helper()
	wantTables := []string{"goose_db_version"}
	for table, columns := range tables {
		wantTables = append(wantTables, table)
		// The table name is a fixture constant, not caller input.
		got := schemaStrings(t, db, "SELECT name FROM pragma_table_info('"+table+"') ORDER BY cid")
		if !slices.Equal(got, strings.Fields(columns)) {
			t.Errorf("%s columns = %v; want %s", table, got, columns)
		}
	}
	slices.Sort(wantTables)
	if got := schemaStrings(t, db, "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"); !slices.Equal(got, wantTables) {
		t.Errorf("tables = %v; want %v", got, wantTables)
	}
	if got := schemaStrings(t, db, "SELECT name FROM sqlite_schema WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY name"); !slices.Equal(got, indexes) {
		t.Errorf("indexes = %v; want %v", got, indexes)
	}
	rows, err := db.QueryContext(t.Context(), "SELECT version_id FROM goose_db_version WHERE is_applied = 1 ORDER BY version_id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var gotVersions []int64
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			t.Fatal(err)
		}
		gotVersions = append(gotVersions, version)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(gotVersions, versions) {
		t.Errorf("applied migration versions = %v; want %v", gotVersions, versions)
	}
}

func schemaStrings(t *testing.T, db *sql.DB, query string) []string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return values
}

func dispatcherSchemaRoundTrip(t *testing.T, db *sql.DB) {
	t.Helper()
	q := dispatcherdb.New(db)
	ctx := t.Context()
	now := models.NewUTCTime(time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC))
	tx, err := q.CreateTransaction(ctx, dispatcherdb.CreateTransactionParams{ID: "test-tx", AuthKey: "test-key", Method: "TEST", ExpiresAt: now, Status: int64(models.Paid)})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := q.GetTransactionByID(ctx, tx.ID); err != nil || !reflect.DeepEqual(got, tx) {
		t.Fatalf("transaction read: got=%+v want=%+v err=%v", got, tx, err)
	}
	order, err := q.CreateDebugletOrder(ctx, dispatcherdb.CreateDebugletOrderParams{TransactionID: tx.ID, OrderID: 1, ExecutorID: "executor", Price: 960000, Currency: "TEST", RefundAddress: "", State: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := q.GetDebugletOrder(ctx, dispatcherdb.GetDebugletOrderParams{TransactionID: tx.ID, OrderID: 1}); err != nil || got != order {
		t.Fatalf("order read: got=%+v want=%+v err=%v", got, order, err)
	}
	earning, err := q.CreateEarnings(ctx, dispatcherdb.CreateEarningsParams{ExecutorID: "executor", Currency: "TEST", SuiWalletAddress: "wallet"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := q.GetEarningsOf(ctx, "executor"); err != nil || len(got) != 1 || got[0] != earning {
		t.Fatalf("earnings read: got=%+v err=%v", got, err)
	}
	state, err := q.UpdateTransactionState(ctx, dispatcherdb.UpdateTransactionStateParams{Key: "cursor", Value: "opaque-value"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := q.GetTransactionState(ctx, "cursor"); err != nil || got != state {
		t.Fatalf("transaction state read: got=%+v err=%v", got, err)
	}
	run, err := q.CreateDebuglet(ctx, dispatcherdb.CreateDebugletParams{DispatcherIncarnation: uuid.NewString(), SessionID: uuid.NewString(), Uuid: uuid.New(), StartTime: now, EndTime: now, Usage: 12, CeilBw: 1000000, ExecutorID: "executor", Addresses: models.CommaSeparatedList{"127.0.0.1"}, State: models.RunStateInitializing, TransactionID: tx.ID, OrderID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := q.GetDebugletByUUID(ctx, run.Uuid); err != nil || !reflect.DeepEqual(got, run) {
		t.Fatalf("debuglet read: got=%+v want=%+v err=%v", got, run, err)
	}
	log, err := q.CreateDebugletLog(ctx, dispatcherdb.CreateDebugletLogParams{DispatcherIncarnation: run.DispatcherIncarnation, SessionID: run.SessionID, ExecutorID: run.ExecutorID, Uuid: run.Uuid, Timestamp: now, Output: []byte("nonce marker\n")})
	if err != nil {
		t.Fatal(err)
	}
	var output []byte
	if err := db.QueryRowContext(ctx, "SELECT output FROM debuglet_logs WHERE id = ? AND debuglet_id = ?", log.ID, run.ID).Scan(&output); err != nil || !bytes.Equal(output, log.Output) {
		t.Fatalf("log read: %q, %v", output, err)
	}
	user, err := q.CreateUser(ctx, dispatcherdb.CreateUserParams{Uuid: uuid.New(), Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := q.GetUserByUUID(ctx, user.Uuid); err != nil || got != user {
		t.Fatalf("user read: got=%+v err=%v", got, err)
	}
	if err := q.InsertDebugletUser(ctx, dispatcherdb.InsertDebugletUserParams{DebUuid: run.Uuid, UserUuid: user.Uuid}); err != nil {
		t.Fatal(err)
	}
	if got, err := q.ListDebugletsByUserUUID(ctx, dispatcherdb.ListDebugletsByUserUUIDParams{Uuid: user.Uuid, Limit: 10}); err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], run) {
		t.Fatalf("user debuglet read: got=%+v err=%v", got, err)
	}
}

func executorSchemaRoundTrip(t *testing.T, db *sql.DB) {
	t.Helper()
	q := executordb.New(db)
	ctx := t.Context()
	now := executordb.NewUTCTime(time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC))
	input := executordb.CreateDebugletParams{Uuid: uuid.New(), StartTime: now, Args: executordb.CommaSeparatedList{"127.0.0.1:1234", "nonce,with punctuation"}, Wasm: []byte{0, 'a', 's', 'm'}, TransactionID: "test-tx", FloorBw: 64000, CeilBw: 1000000, TimeoutMs: 15000, Addresses: executordb.CommaSeparatedList{"127.0.0.1"}, ListenTcp: true}
	if err := q.CreateDebuglet(ctx, input); err != nil {
		t.Fatal(err)
	}
	runs, err := q.ListDebuglets(ctx, executordb.ListDebugletsParams{Limit: 10})
	if err != nil || len(runs) != 1 {
		t.Fatalf("list debuglets: %+v, %v", runs, err)
	}
	run := runs[0]
	if run.ID <= 0 || run.Uuid != input.Uuid || !run.StartTime.Equal(now.Time) || !reflect.DeepEqual(run.Args, input.Args) || !bytes.Equal(run.Wasm, input.Wasm) || run.TransactionID != input.TransactionID || run.FloorBw != input.FloorBw || run.CeilBw != input.CeilBw || run.TimeoutMs != input.TimeoutMs || !reflect.DeepEqual(run.Addresses, input.Addresses) || run.RequireIcmp || run.ListenUdp || !run.ListenTcp || run.ListenScion || !run.StartedAt.IsZero() {
		t.Fatalf("debuglet round trip: got=%+v input=%+v", run, input)
	}
	if _, err := q.UpdateDebugletStarted(ctx, executordb.UpdateDebugletStartedParams{StartedAt: now, Uuid: input.Uuid}); err != nil {
		t.Fatal(err)
	}
	if started, err := q.GetDebugletStarted(ctx, input.Uuid); err != nil || !started.Equal(now.Time) {
		t.Fatalf("started read: %v, %v", started, err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO debuglet_logs(debuglet_id,timestamp,output) VALUES(?,?,?)", run.ID, now, []byte("guest output")); err != nil {
		t.Fatal(err)
	}
	var output []byte
	if err := db.QueryRowContext(ctx, "SELECT output FROM debuglet_logs WHERE debuglet_id = ?", run.ID).Scan(&output); err != nil || string(output) != "guest output" {
		t.Fatalf("executor log read: %q, %v", output, err)
	}
}

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
	path, created, err := PrepareRoleDatabase(ctx, ExecutorSchema, dir)
	if err != nil || !created {
		t.Fatalf("first use = (%v, %v), want a created database", created, err)
	}
	made, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	again, createdAgain, err := PrepareRoleDatabase(ctx, ExecutorSchema, dir)
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
	if err := os.Symlink(elsewhere, RoleDatabase(other, ExecutorSchema)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PrepareRoleDatabase(ctx, ExecutorSchema, other); err == nil {
		t.Fatal("a link in place of the database was accepted")
	}
	if _, err := os.Lstat(elsewhere); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a database was created through the link: %v", err)
	}
}
