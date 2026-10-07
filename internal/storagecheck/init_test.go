//go:build linux || darwin

package storagecheck

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io/fs"
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
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func TestBootstrapFresh(t *testing.T) {
	for _, role := range []Role{Dispatcher, Executor} {
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
			if role == Dispatcher {
				assertSchema(t, db, map[string]string{
					"account_recovery_audit":     "selector user_id case_reference issued_by_uid issued_at expires_at consumed_at revoked_at revoked_by_uid revocation_reference",
					"attribution_chains":         "executor_id chain_id anchor t0_ns interval_ns delay_epochs chain_length tag_spec first_seen_ns last_seen_ns",
					"attribution_keys":           "executor_id chain_id epoch key disclosed_at_ns",
					"attribution_runs":           "debuglet_id chain_id source_ip source_ip_observed active_from_ns active_to_ns",
					"attribution_retention":      "singleton retained_from_ns",
					"attribution_verify_budget":  "executor_id chain_id epoch used",
					"attribution_receipt_keys":   "key_id public_key valid_from_ns valid_to_ns",
					"measurement_profiles":       "id user_id document",
					"measurement_requests":       "debuglet_id document",
					"measurement_execution":      "debuglet_id started_observed_ns terminal_observed_ns exit_code tcp_endpoint",
					"retry_requests":             "caller_scope request_id parent_run_id transaction_id request_hash intent_metadata",
					"experiment_barriers":        "transaction_id deadline_ns start_time_ns",
					"experiment_readiness":       "debuglet_id metadata ready_at_ns",
					"allocation_reclamations":    "debuglet_id reclaimed_at",
					"allowance_grants":           "id user_id amount currency granted_by reason idempotency_key granted_at",
					"probe_status":               "executor_id first_connected last_connected connected status_since total_uptime is_public host_tags version",
					"probe_addresses":            "executor_id family address via first_observed last_observed",
					"payment_receipts":           "tx_digest event_seq nonce disposition amount coin_type receiver checkpoint observed_at detail",
					"chain_transfers":            "id kind executor_id transaction_id order_id amount currency receiver state digest signed_transaction signature detail created_at updated_at",
					"account_run_reservations":   "debuglet_id account_id queued_bytes retired_at last_retirement_check",
					"payload_tombstones":         "debuglet_id deleted_at reason workload_sha256 certificate_sha256",
					"debuglets":                  "id uuid start_time end_time usage ceil_bw executor_id addresses state error transaction_id order_id dispatcher_incarnation session_id",
					"debuglet_logs":              "id debuglet_id timestamp output source_sequence",
					"debuglet_output":            "debuglet_id output_version owner_fingerprint account_id committed_sequence byte_count frame_count last_log_id final_sequence final_cursor status reason",
					"debuglet_cancellations":     "debuglet_id request_id reason requested_at attempted_at acknowledged_at failure terminal_recorded_at",
					"debuglet_provenance":        "debuglet_id document",
					"order_settlements":          "transaction_id order_id kind amount currency executor_id debuglet_id recorded_at",
					"output_account_usage":       "account_id charged_bytes frame_count",
					"output_node_usage":          "singleton charged_bytes frame_count",
					"transactions":               "id auth_key price method expires_at hash currency status pricing_rule",
					"transaction_states":         "key value",
					"earnings":                   "executor_id currency total_income current_balance sui_wallet_address",
					"debuglet_order":             "transaction_id order_id executor_id price currency state refund_address debuglet_id",
					"destination_policy_events":  "id destination kind limit_bps reason actor requested_at_ns expires_at_ns revision",
					"users":                      "id uuid name role",
					"debuglet_users":             "debuglet_id user_id",
					"user_credentials":           "user_id kind selector secret_hash created_at",
					"sessions":                   "id selector verifier_hash csrf_hash user_id created_at expires_at revoked kind audience scopes label authenticated_at",
					"transaction_users":          "transaction_id user_id",
					"executor_enrollments":       "executor_id fingerprint enrolled_at",
					"executor_enrollment_tokens": "selector executor_id secret_hash created_at expires_at",
					"owned_executors":            "executor_id user_id name created_at",
					"oauth_identities":           "provider issuer subject user_id login created_at updated_at",
					"oauth_login_attempts":       "state_hash provider verifier nonce purpose session_selector expires_at",
					"pending_identity_links":     "user_id provider issuer subject login session_selector expires_at",
					"device_logins":              "selector verifier_hash user_code_hash audience scopes label expires_at next_poll_at poll_interval state approver_session user_id",
				}, []string{"account_recovery_pending", "account_run_reservations_live", "attribution_runs_source_idx", "chain_transfers_executor_idx", "debuglet_logs_sequence_idx", "debuglets_uuid_idx", "device_logins_expiry", "executor_enrollment_tokens_executor_idx", "measurement_profiles_owner", "oauth_login_expiry", "owned_executors_user_idx", "payment_receipts_nonce_idx", "sessions_user_idx", "users_uuid_idx"}, []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28})
				dispatcherSchemaRoundTrip(t, db)
			} else {
				assertSchema(t, db, map[string]string{
					"debuglets":             "id uuid start_time args wasm transaction_id floor_bw ceil_bw timeout_ms addresses require_icmp listen_udp listen_tcp listen_scion started_at dispatcher_incarnation session_id",
					"debuglet_logs":         "id debuglet_id timestamp output",
					"debuglet_exits":        "debuglet_id dispatcher_incarnation session_id exit_code error_message recorded_at attempts last_attempt_at last_error rejected",
					"tesla_chains":          "generation anchor epoch_base delay_ns chain_length created_at disclosure_delay",
					"output_runs":           "run_id dispatcher_incarnation session_id output_version last_sequence acknowledged_sequence emitted_bytes queued_bytes queued_frames status reason end_acknowledged receipt_sequence receipt_reason",
					"output_frames":         "run_id sequence timestamp_ns output",
					"output_usage":          "singleton charged_bytes",
					"operator_dispositions": "run_id recorded_at_ns reason",
				}, []string{"debuglet_exits_binding_idx", "debuglets_uuid_idx"}, []int64{0, 1, 2, 3, 4, 5, 6, 7, 8})
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
		if err := BootstrapFresh(t.Context(), "invalid", path); err == nil || !strings.Contains(err.Error(), "unknown database role") {
			t.Fatalf("role validation: %v", err)
		}
		assertSchemaFiles(t, parent)
	})

	for _, contents := range []string{"", "unrelated existing data"} {
		t.Run("existing path "+contents, func(t *testing.T) {
			parent := privateSchemaDir(t)
			path := filepath.Join(parent, "existing.sqlite")
			writeSchemaFile(t, path, contents)
			if err := BootstrapFresh(t.Context(), Dispatcher, path); !errors.Is(err, fs.ErrExist) {
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
			if err := BootstrapFresh(t.Context(), Executor, path); !errors.Is(err, fs.ErrExist) {
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
			if err := BootstrapFresh(t.Context(), Executor, path); !errors.Is(err, fs.ErrExist) {
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
			if err := BootstrapFresh(t.Context(), Executor, filepath.Join(dir, "db")); err == nil {
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
		if err := BootstrapFresh(ctx, Dispatcher, filepath.Join(parent, "db")); !errors.Is(err, context.Canceled) {
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
	db, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
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
