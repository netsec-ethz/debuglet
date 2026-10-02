// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package storagecheck

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// The child writes ordinary fixture rows in an uncommitted transaction. A
// small SQLite page cache spills them to disk before the parent kills it,
// leaving the same rollback journal as an interrupted daemon write.
func TestStartupInterruptedWriter(t *testing.T) {
	path := os.Getenv("DEBUGLET_TEST_RECOVERY_WRITER")
	if path == "" {
		return
	}
	db, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range []string{
		"PRAGMA journal_mode = DELETE", "PRAGMA cache_size = 5", "PRAGMA cache_spill = ON",
		"BEGIN IMMEDIATE", "UPDATE startup_recovery SET marker = 2, payload = zeroblob(16384)",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Println("writer ready")
	time.Sleep(time.Minute)
	t.Fatal("writer was not stopped by its parent")
}

func interruptedWriter(t *testing.T, path string) {
	t.Helper()
	modify(t, path,
		"CREATE TABLE startup_recovery (id INTEGER PRIMARY KEY, marker INTEGER NOT NULL, payload BLOB)",
		"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<32) INSERT INTO startup_recovery SELECT i, 1, zeroblob(8192) FROM n")
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStartupInterruptedWriter$", "-test.count=1")
	cmd.Env = append(os.Environ(), "DEBUGLET_TEST_RECOVERY_WRITER="+path)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	killErr := cmd.Process.Kill()
	waitErr := cmd.Wait()
	if err != nil || line != "writer ready\n" || killErr != nil || waitErr == nil {
		t.Fatalf("writer readiness=%q, read=%v, kill=%v, wait=%v, stderr=%s", line, err, killErr, waitErr, stderr.String())
	}
}

func TestServiceStartupRecoversInterruptedWriter(t *testing.T) {
	for _, role := range []Role{Dispatcher, Executor} {
		t.Run(string(role), func(t *testing.T) {
			path := fixture(t, role, 0)
			interruptedWriter(t, path)
			before, journalBefore := digest(t, path), digest(t, path+"-journal")
			err := Check(t.Context(), role, path)
			var sqliteErr *sqlite.Error
			if !errors.As(err, &sqliteErr) || sqliteErr.Code() != sqlite3.SQLITE_READONLY_ROLLBACK {
				t.Fatalf("read-only check=%v; want rollback recovery required", err)
			}
			unchangedBytes(t, path, before)
			unchangedBytes(t, path+"-journal", journalBefore)
			if err := CheckForService(t.Context(), role, path); err != nil {
				t.Fatalf("launcher preflight refused recoverable state: %v", err)
			}
			unchangedBytes(t, path, before)
			unchangedBytes(t, path+"-journal", journalBefore)
			assertNoRecoveryCopy(t, path)
			db, err := OpenForService(t.Context(), role, path)
			if err != nil {
				t.Fatal(err)
			}
			var count int
			err = db.QueryRow("SELECT count(*) FROM startup_recovery WHERE marker = 1 AND length(payload) = 8192").Scan(&count)
			closeErr := db.Close()
			if err != nil || closeErr != nil || count != 32 {
				t.Fatalf("committed rows=%d, query=%v, close=%v", count, err, closeErr)
			}
			if err := Check(t.Context(), role, path); err != nil {
				t.Fatalf("recovered database=%v", err)
			}
			assertNoRecoveryCopy(t, path)
		})
	}
}

func TestServiceStartupRefusesInterruptedUnsupportedDatabase(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change string
		want   error
	}{
		{"unknown", "DROP TABLE goose_db_version", ErrUnknown},
		{"newer", "INSERT INTO goose_db_version(version_id,is_applied) VALUES(99999,1)", ErrNewer},
		{"incomplete", "DROP TABLE debuglet_cancellations", ErrIncomplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := fixture(t, Dispatcher, 0)
			modify(t, path, tc.change)
			interruptedWriter(t, path)
			before, journalBefore := digest(t, path), digest(t, path+"-journal")
			if err := CheckForService(t.Context(), Dispatcher, path); !errors.Is(err, tc.want) {
				t.Fatalf("launcher preflight=%v; want %v", err, tc.want)
			}
			unchangedBytes(t, path, before)
			unchangedBytes(t, path+"-journal", journalBefore)
			db, err := OpenForService(t.Context(), Dispatcher, path)
			if db != nil {
				db.Close()
				t.Fatal("unsupported database opened for service")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("startup=%v; want %v", err, tc.want)
			}
			unchangedBytes(t, path, before)
			unchangedBytes(t, path+"-journal", journalBefore)
			assertNoRecoveryCopy(t, path)
		})
	}
}

func TestRecoveryCopyIsFiniteAndCancelable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := copyRecoveryFile(ctx, path, filepath.Join(dir, "cancelled"), before); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled copy=%v", err)
	}
	if err := os.WriteFile(path, []byte("original and growing"), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "bounded")
	if err := copyRecoveryFile(t.Context(), path, target, before); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed copy=%v", err)
	}
	info, err := os.Stat(target)
	if err != nil || info.Size() != before.Size() {
		t.Fatalf("copy grew beyond initial %s bytes: %v, %v", strconv.FormatInt(before.Size(), 10), info, err)
	}
	if err := copyRecoveryFile(t.Context(), path, target, before); !errors.Is(err, os.ErrExist) {
		t.Fatalf("copy write refusal=%v", err)
	}
}

func assertNoRecoveryCopy(t *testing.T, path string) {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".debuglet-recovery-*"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary recovery files remain: %v, %v", entries, err)
	}
}
