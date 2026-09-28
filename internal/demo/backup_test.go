// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package demo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/pelletier/go-toml/v2"
)

func backupFixture(t *testing.T, layout string) (string, Manifest) {
	t.Helper()
	dir := privateSchemaDir(t)
	m := Manifest{Version: "v0.1.0", SourceSHA: strings.Repeat("a", 40)}
	roles := []SchemaRole{DispatcherSchema, ExecutorSchema}
	var id string
	if layout == "local" {
		state, err := readLocalState(dir, m)
		if err != nil {
			t.Fatal(err)
		}
		id = state.ExecutorID
	} else {
		roles = []SchemaRole{SchemaRole(layout)}
		state, err := readRoleState(dir, roles[0], m)
		if err != nil {
			t.Fatal(err)
		}
		id = state.Identity
	}
	for _, role := range roles {
		db := RoleDatabase(dir, role)
		if err := BootstrapFresh(t.Context(), role, db); err != nil {
			t.Fatal(err)
		}
		config := dispatcherConfiguration(m.Version, db)
		if role == ExecutorSchema {
			config = executorConfiguration(m.Version, id, db, readiness.Record{GRPCAddr: "127.0.0.1:9001", HTTPAddr: "127.0.0.1:9000"})
		}
		name := "service.toml"
		if layout == "local" {
			name = string(role) + ".toml"
		}
		if err := writeConfig(filepath.Join(dir, name), config); err != nil {
			t.Fatal(err)
		}
	}
	if err := recordStoppedState(dir, m); err != nil {
		t.Fatal(err)
	}
	return dir, m
}

func TestBackupRestoreOfflineState(t *testing.T) {
	for _, layout := range []string{"local", "dispatcher", "executor"} {
		t.Run(layout, func(t *testing.T) {
			source, m := backupFixture(t, layout)
			if layout != "dispatcher" {
				seedBackupRuns(t, RoleDatabase(source, ExecutorSchema))
			}
			parent := privateSchemaDir(t)
			backup, restored := filepath.Join(parent, "snapshot"), filepath.Join(parent, "restored")
			before := backupFiles(t, source)
			manifest, err := BackupState(t.Context(), BackupOptions{StateDir: source, Destination: backup, Offline: true, Package: m})
			if err != nil {
				t.Fatal(err)
			}
			if manifest.Layout != layout || manifest.ObservedAt.IsZero() || len(manifest.Files) == 0 {
				t.Fatalf("manifest: %+v", manifest)
			}
			// The lifetime lock can be created; database, WAL, identity and config bytes cannot change.
			delete(before, ".lock")
			after := backupFiles(t, source)
			delete(after, ".lock")
			if !reflect.DeepEqual(before, after) {
				t.Fatal("backup mutated source state")
			}
			if _, err := RestoreState(t.Context(), RestoreOptions{BackupDir: backup, StateDir: restored, Package: m}); err != nil {
				t.Fatal(err)
			}
			for name, data := range before {
				if strings.HasSuffix(name, ".toml") || name == OfflineStateFile {
					continue
				}
				got, err := os.ReadFile(filepath.Join(restored, name))
				if err != nil || !bytes.Equal(data, got) {
					t.Fatalf("restored %s differs: %v", name, err)
				}
			}
			if layout != "dispatcher" {
				assertBackupRuns(t, RoleDatabase(restored, ExecutorSchema))
			}
			for _, role := range manifest.Roles {
				if role.SchemaVersion <= 0 {
					t.Fatal("missing schema version")
				}
				if _, err := backupConfig(restored, restored, layout, role, "", m.Version); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := BackupState(t.Context(), BackupOptions{StateDir: restored, Destination: filepath.Join(parent, "again"), Offline: true, Package: m}); err != nil {
				t.Fatalf("restored stopped state cannot be backed up: %v", err)
			}
			assertPrivateBackup(t, backup)
			assertPrivateBackup(t, restored)
		})
	}
}

// A real writer leaves a committed transaction only in WAL. Copying its stable
// files into a separate fixture models a stopped process that retained its WAL.
func TestBackupIncludesOfflineWALWithoutChangingSource(t *testing.T) {
	source, m := backupFixture(t, "executor")
	original := RoleDatabase(source, ExecutorSchema)
	db, err := sqlitedb.Open(original)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(t.Context(), "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), "INSERT INTO tesla_chains VALUES(1,x'010203','2026-09-28T12:00:00Z',1000000000,100,'2026-09-28T12:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	offline := privateSchemaDir(t)
	for name, data := range backupFiles(t, source) {
		if strings.HasSuffix(name, "-shm") {
			continue
		}
		if err := os.WriteFile(filepath.Join(offline, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if info, err := os.Stat(RoleDatabase(offline, ExecutorSchema) + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("no real WAL: %v", err)
	}
	// Rebase only the copied fixture config, keeping the committed WAL untouched.
	if _, err := backupConfig(offline, "", "executor", BackupRole{Role: ExecutorSchema, Identity: readBackupIdentity(t, source, m)}, offline, m.Version); err != nil {
		t.Fatal(err)
	}
	before := backupFiles(t, offline)
	parent := privateSchemaDir(t)
	backup := filepath.Join(parent, "wal-backup")
	if _, err := BackupState(t.Context(), BackupOptions{StateDir: offline, Destination: backup, Offline: true, Package: m}); err != nil {
		t.Fatal(err)
	}
	after := backupFiles(t, offline)
	delete(after, ".lock")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("offline source main/WAL changed")
	}
	restored := filepath.Join(parent, "restored")
	if _, err := RestoreState(t.Context(), RestoreOptions{BackupDir: backup, StateDir: restored, Package: m}); err != nil {
		t.Fatal(err)
	}
	check := openSchemaDB(t, RoleDatabase(restored, ExecutorSchema))
	defer check.Close()
	var count int
	if err := check.QueryRow("SELECT count(*) FROM tesla_chains WHERE generation=1").Scan(&count); err != nil || count != 1 {
		t.Fatalf("WAL-only commit lost: %d %v", count, err)
	}
}

func TestBackupRefusesUnownedOrIncompleteShutdown(t *testing.T) {
	for _, kind := range []string{"offline omitted", "missing receipt", "identity changed", "runtime record", "held lock", "external database", "external key", "system profile", "linked database"} {
		t.Run(kind, func(t *testing.T) {
			source, m := backupFixture(t, "dispatcher")
			options := BackupOptions{StateDir: source, Destination: filepath.Join(privateSchemaDir(t), "backup"), Offline: true, Package: m}
			switch kind {
			case "offline omitted":
				options.Offline = false
			case "missing receipt":
				if err := os.Remove(filepath.Join(source, OfflineStateFile)); err != nil {
					t.Fatal(err)
				}
			case "identity changed":
				state, err := readRoleState(source, DispatcherSchema, m)
				if err != nil {
					t.Fatal(err)
				}
				state.Identity = uuid.NewString()
				if err := writeLocalJSON(filepath.Join(source, "role-state.json"), state); err != nil {
					t.Fatal(err)
				}
			case "runtime record":
				writeSchemaFile(t, filepath.Join(source, "child-ready.json"), "{}")
			case "held lock":
				unlock, err := lockLocalState(source)
				if err != nil {
					t.Fatal(err)
				}
				defer unlock()
			case "external database", "external key", "system profile":
				path := filepath.Join(source, "service.toml")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var cfg map[string]map[string]any
				if err := toml.Unmarshal(data, &cfg); err != nil {
					t.Fatal(err)
				}
				if kind == "external database" {
					cfg["database"]["path"] = "/unowned/db.sqlite"
				} else if kind == "external key" {
					cfg["tls"]["key_file"] = "/unowned/key.pem"
				} else {
					cfg["server"]["local_development"] = false
				}
				encoded, err := toml.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, encoded, 0600); err != nil {
					t.Fatal(err)
				}
			case "linked database":
				original := RoleDatabase(source, DispatcherSchema)
				target := filepath.Join(privateSchemaDir(t), "db")
				if err := os.Rename(original, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, original); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := BackupState(t.Context(), options); err == nil {
				t.Fatal("unsafe backup accepted")
			}
			if _, err := os.Stat(options.Destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed backup published: %v", err)
			}
			assertNoBackupStaging(t, filepath.Dir(options.Destination))
		})
	}
}

func TestRestoreRejectsDamageBeforePublication(t *testing.T) {
	for _, kind := range []string{"corrupt", "missing", "extra", "schema", "identity", "package", "destination exists"} {
		t.Run(kind, func(t *testing.T) {
			source, m := backupFixture(t, "executor")
			parent := privateSchemaDir(t)
			backup := filepath.Join(parent, "backup")
			manifest, err := BackupState(t.Context(), BackupOptions{StateDir: source, Destination: backup, Offline: true, Package: m})
			if err != nil {
				t.Fatal(err)
			}
			restored := filepath.Join(parent, "restored")
			switch kind {
			case "corrupt":
				writeSchemaFile(t, RoleDatabase(backup, ExecutorSchema), "corrupt")
			case "missing":
				if err := os.Remove(filepath.Join(backup, "service.toml")); err != nil {
					t.Fatal(err)
				}
			case "extra":
				writeSchemaFile(t, filepath.Join(backup, "executor.sqlite-wal"), "unexpected journal")
			case "schema":
				db := openSchemaDB(t, RoleDatabase(backup, ExecutorSchema))
				if _, err := db.Exec("INSERT INTO goose_db_version(version_id,is_applied) VALUES(999,1)"); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				manifest.Files["executor.sqlite"], err = hashBackupFile(t.Context(), RoleDatabase(backup, ExecutorSchema))
				if err != nil {
					t.Fatal(err)
				}
				if err := writeLocalJSON(filepath.Join(backup, backupManifestFile), manifest); err != nil {
					t.Fatal(err)
				}
			case "identity":
				manifest.Roles[0].Identity = uuid.NewString()
				if err := writeLocalJSON(filepath.Join(backup, backupManifestFile), manifest); err != nil {
					t.Fatal(err)
				}
			case "package":
				m.SourceSHA = strings.Repeat("b", 40)
			case "destination exists":
				if err := os.Mkdir(restored, 0700); err != nil {
					t.Fatal(err)
				}
				writeSchemaFile(t, filepath.Join(restored, "keep"), "original")
			}
			before := backupFiles(t, source)
			if _, err := RestoreState(t.Context(), RestoreOptions{BackupDir: backup, StateDir: restored, Package: m}); err == nil {
				t.Fatal("invalid restore accepted")
			}
			if kind == "destination exists" {
				data, err := os.ReadFile(filepath.Join(restored, "keep"))
				if err != nil || string(data) != "original" {
					t.Fatal("existing destination modified")
				}
			} else if _, err := os.Stat(restored); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid restore published: %v", err)
			}
			if !reflect.DeepEqual(before, backupFiles(t, source)) {
				t.Fatal("original source changed")
			}
			assertNoBackupStaging(t, parent)
		})
	}
}

func TestBackupWriteFailurePreservesPrevious(t *testing.T) {
	// Restrict only a subprocess, so the real filesystem rejects a write with
	// EFBIG without changing the test runner's limits or filling a shared disk.
	if os.Getenv("DEBUGLET_BACKUP_WRITE_LIMIT") == "1" {
		signal.Ignore(syscall.SIGXFSZ)
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 4096, Max: 4096}); err != nil {
			t.Fatal(err)
		}
		var m Manifest
		if err := json.Unmarshal([]byte(os.Getenv("DEBUGLET_BACKUP_PACKAGE")), &m); err != nil {
			t.Fatal(err)
		}
		_, err := BackupState(t.Context(), BackupOptions{StateDir: os.Getenv("DEBUGLET_BACKUP_SOURCE"), Destination: os.Getenv("DEBUGLET_BACKUP_DESTINATION"), Offline: true, Package: m})
		if !errors.Is(err, syscall.EFBIG) {
			t.Fatalf("wanted actual filesystem write failure: %v", err)
		}
		return
	}
	source, m := backupFixture(t, "executor")
	parent := privateSchemaDir(t)
	first := filepath.Join(parent, "first")
	if _, err := BackupState(t.Context(), BackupOptions{StateDir: source, Destination: first, Offline: true, Package: m}); err != nil {
		t.Fatal(err)
	}
	before := backupFiles(t, first)
	second := filepath.Join(parent, "second")
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestBackupWriteFailurePreservesPrevious$")
	cmd.Env = append(os.Environ(), "DEBUGLET_BACKUP_WRITE_LIMIT=1", "DEBUGLET_BACKUP_SOURCE="+source, "DEBUGLET_BACKUP_DESTINATION="+second, "DEBUGLET_BACKUP_PACKAGE="+string(encoded))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("write failure subprocess: %v\n%s", err, output)
	}
	if _, err := os.Stat(second); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed write published: %v", err)
	}
	if !reflect.DeepEqual(before, backupFiles(t, first)) {
		t.Fatal("last good backup changed")
	}
	assertNoBackupStaging(t, parent)
}

func TestBackupCanceledPreservesPrevious(t *testing.T) {
	source, m := backupFixture(t, "executor")
	parent := privateSchemaDir(t)
	first := filepath.Join(parent, "first")
	if _, err := BackupState(t.Context(), BackupOptions{StateDir: source, Destination: first, Offline: true, Package: m}); err != nil {
		t.Fatal(err)
	}
	before := backupFiles(t, first)
	// A large real database makes cancellation observe copying in progress.
	db := openSchemaDB(t, RoleDatabase(source, ExecutorSchema))
	if _, err := db.Exec("CREATE TABLE cancellation_payload(data BLOB); INSERT INTO cancellation_payload VALUES(zeroblob(67108864))"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	finished := make(chan struct{})
	second := filepath.Join(parent, "second")
	go func() {
		defer close(finished)
		_, err := BackupState(ctx, BackupOptions{StateDir: source, Destination: second, Offline: true, Package: m})
		done <- err
	}()
	defer func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("backup did not join after cancellation")
		}
	}()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	observed := false
	for !observed {
		select {
		case err := <-done:
			t.Fatalf("backup finished before cancellation observation: %v", err)
		case <-deadline.C:
			t.Fatal("copy did not begin")
		case <-ticker.C:
			entries, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".debuglet-backup-") {
					info, err := os.Stat(filepath.Join(parent, entry.Name(), "executor.sqlite"))
					observed = err == nil && info.Size() > 0
					if observed {
						break
					}
				}
			}
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted backup: %v", err)
	}
	if _, err := os.Stat(second); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interruption published: %v", err)
	}
	if !reflect.DeepEqual(before, backupFiles(t, first)) {
		t.Fatal("last good backup changed")
	}
	assertNoBackupStaging(t, parent)
}

func seedBackupRuns(t *testing.T, path string) {
	t.Helper()
	db := openSchemaDB(t, path)
	defer db.Close()
	q := executordb.New(db)
	now := executordb.NewUTCTime(time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC))
	for i := 0; i < 3; i++ {
		id := uuid.New()
		if err := q.CreateDebuglet(t.Context(), executordb.CreateDebugletParams{Uuid: id, StartTime: now, Wasm: []byte{0, 97, 115, 109}, TransactionID: "retained", FloorBw: 1, CeilBw: 10, TimeoutMs: 1000, DispatcherIncarnation: "old-dispatcher", SessionID: "old-session"}); err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			if _, err := q.UpdateDebugletStarted(t.Context(), executordb.UpdateDebugletStartedParams{Uuid: id, StartedAt: now}); err != nil {
				t.Fatal(err)
			}
		}
		if i == 2 {
			if _, err := db.Exec("INSERT INTO debuglet_exits(debuglet_id,dispatcher_incarnation,session_id,exit_code,recorded_at) VALUES(?,?,?,?,?)", id.String(), "old-dispatcher", "old-session", 0, now); err != nil {
				t.Fatal(err)
			}
		}
	}
}
func assertBackupRuns(t *testing.T, path string) {
	t.Helper()
	db := openSchemaDB(t, path)
	defer db.Close()
	var total, started, terminal int
	if err := db.QueryRow("SELECT count(*),count(started_at) FROM debuglets WHERE dispatcher_incarnation='old-dispatcher' AND session_id='old-session'").Scan(&total, &started); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM debuglet_exits WHERE dispatcher_incarnation='old-dispatcher' AND session_id='old-session'").Scan(&terminal); err != nil {
		t.Fatal(err)
	}
	if total != 3 || started != 2 || terminal != 1 {
		t.Fatalf("retained queued/started/terminal records: %d/%d/%d", total, started, terminal)
	}
}
func readBackupIdentity(t *testing.T, dir string, m Manifest) string {
	t.Helper()
	state, err := readRoleState(dir, ExecutorSchema, m)
	if err != nil {
		t.Fatal(err)
	}
	return state.Identity
}
func backupFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string][]byte{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = data
	}
	return result
}
func assertPrivateBackup(t *testing.T, dir string) {
	t.Helper()
	if err := privateBackupDir(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("unprotected backup entry %s: %v", entry.Name(), err)
		}
	}
}
func assertNoBackupStaging(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".debuglet-backup-") {
			t.Fatalf("owned staging left behind: %s", entry.Name())
		}
	}
}

func TestBackupReceiptRequiresJoinedForegroundShutdown(t *testing.T) {
	for _, mode := range []string{"success", "forced cleanup"} {
		t.Run(mode, func(t *testing.T) {
			f := newSupervisorFixture(t, mode)
			dir := privateSchemaDir(t)
			f.dir = dir
			writeSchemaFile(t, filepath.Join(dir, OfflineStateFile), "old receipt")
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			err := up(ctx, f.assets, LocalOptions{StateDir: dir, Ready: func(LocalEnvironment) error {
				if _, err := os.Stat(filepath.Join(dir, OfflineStateFile)); !errors.Is(err, os.ErrNotExist) {
					t.Error("start retained old shutdown receipt")
				}
				cancel()
				return nil
			}}, f.deps, time.Second)
			_, receiptErr := os.Stat(filepath.Join(dir, OfflineStateFile))
			if mode == "success" {
				if err != nil || receiptErr != nil {
					t.Fatalf("joined shutdown: %v; receipt: %v", err, receiptErr)
				}
			} else if !errors.Is(err, ErrForcedKill) || !errors.Is(receiptErr, os.ErrNotExist) {
				t.Fatalf("failed shutdown produced receipt: %v; %v", err, receiptErr)
			}
		})
	}
}
