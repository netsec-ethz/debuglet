package sqlite

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

// newTestStorage builds the backend with guards that always commit, which is
// how a core behaves while its session binding stays eligible. The admission
// cases construct their own guards instead.
func newTestStorage(t *testing.T, db *sql.DB, eligibility scheduler.RestoreEligibility) *SqliteStorage {
	t.Helper()
	s, err := NewStorage(db, eligibility, scheduler.Admission{Insert: admissionPass, Start: admissionPass})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// newBootstrappedDatabase bootstraps a fresh executor database inside a private
// directory it owns and returns its path with nothing connected to it.
func newBootstrappedDatabase(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "executor.sqlite")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := demo.BootstrapFresh(ctx, demo.ExecutorSchema, path); err != nil {
		t.Fatal(err)
	}
	return path
}

// Callers join their loops and complete SQLite callbacks before cleanup closes
// this database. The schema comes from the same canonical source as the demo.
func newSchedulerTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(newBootstrappedDatabase(t))}
	dsn.RawQuery = url.Values{"mode": {"rw"}, "_pragma": {"foreign_keys(1)", "busy_timeout(5000)"}}.Encode()
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	return db
}
