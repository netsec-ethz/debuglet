package demo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"time"

	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

type SchemaRole string

const (
	DispatcherSchema SchemaRole = "dispatcher"
	ExecutorSchema   SchemaRole = "executor"
)

// BootstrapFresh applies the canonical migrations to a new, private database.
// The caller must own the mode-0700 parent and keep it exclusively under its
// control until this function returns. Existing databases are never upgraded.
func BootstrapFresh(ctx context.Context, role SchemaRole, path string) error {
	var migrations fs.FS
	switch role {
	case DispatcherSchema:
		migrations = dispatcherdb.MigrationFS()
	case ExecutorSchema:
		migrations = executordb.MigrationFS()
	default:
		return fmt.Errorf("unknown demo schema role %q", role)
	}
	return bootstrapFresh(ctx, path, migrations)
}

// CheckSchema verifies an existing database against the schema versions this
// package's services support. Local services never upgrade a database in
// place, so an unsupported one is reported instead of being migrated.
func CheckSchema(ctx context.Context, role SchemaRole, path string) error {
	switch role {
	case DispatcherSchema:
		return storagecheck.Check(ctx, storagecheck.Dispatcher, path)
	case ExecutorSchema:
		return storagecheck.Check(ctx, storagecheck.Executor, path)
	default:
		return fmt.Errorf("unknown demo schema role %q", role)
	}
}

func bootstrapFresh(ctx context.Context, path string, migrations fs.FS) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if path == "" {
		return errors.New("fresh database path is empty")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve fresh database path: %w", err)
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("inspect fresh database parent: %w", err)
	}
	if !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return errors.New("fresh database requires a mode-0700 directory parent")
	}
	if err := schemaParentOwned(parent); err != nil {
		return err
	}

	// SQLite may otherwise consume a pre-existing journal or WAL, or cleanup
	// might remove one that this invocation did not create.
	sidecars := []string{path + "-journal", path + "-wal", path + "-shm"}
	for _, sidecar := range sidecars {
		if _, err := os.Lstat(sidecar); !errors.Is(err, fs.ErrNotExist) {
			if err == nil {
				err = fs.ErrExist
			}
			return fmt.Errorf("fresh database sidecar %q: %w", sidecar, err)
		}
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create fresh database: %w", err)
	}
	var closeDB func() error
	defer func() {
		if closeDB != nil {
			if closeErr := closeDB(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close fresh database: %w", closeErr))
			}
		}
		if err != nil {
			// All these paths were absent before exclusive creation in the
			// caller's private parent. Close SQLite before removing its files.
			for _, owned := range append(sidecars, path) {
				if removeErr := os.Remove(owned); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
					err = errors.Join(err, fmt.Errorf("remove fresh database file: %w", removeErr))
				}
			}
		}
	}()
	if err := file.Close(); err != nil {
		return fmt.Errorf("close new database file: %w", err)
	}

	// A file URI keeps spaces, question marks and other filename characters
	// separate from connection options. mode=rw prevents implicit recreation.
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	dsn.RawQuery = url.Values{
		"mode":    {"rw"},
		"_pragma": {"foreign_keys(1)", "busy_timeout(1000)"},
	}.Encode()
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return fmt.Errorf("open fresh database: %w", err)
	}
	closeDB = db.Close
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, migrations,
		goose.WithDisableGlobalRegistry(true), goose.WithLogger(goose.NopLogger()))
	if err != nil {
		return fmt.Errorf("create fresh migration provider: %w", err)
	}
	closeDB = provider.Close
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply fresh database migrations: %w", err)
	}
	return ctx.Err()
}
