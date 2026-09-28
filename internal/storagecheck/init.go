package storagecheck

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

// BootstrapFresh applies the canonical migrations to a new, private database.
// The caller must own the mode-0700 parent and keep it exclusively under its
// control until this function returns. Existing databases are never upgraded.
func BootstrapFresh(ctx context.Context, role Role, path string) error {
	var migrations fs.FS
	switch role {
	case Dispatcher:
		migrations = dispatcherdb.MigrationFS()
	case Executor:
		migrations = executordb.MigrationFS()
	default:
		return fmt.Errorf("unknown database role %q", role)
	}
	return bootstrapFresh(ctx, path, migrations)
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

	// The file exists now, so the default mode=rw prevents implicit recreation.
	db, err := sqlitedb.Open(path)
	if err != nil {
		return fmt.Errorf("open fresh database: %w", err)
	}
	closeDB = db.Close
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := sqlitedb.Migrate(ctx, db, migrations, sqlitedb.Latest); err != nil {
		return fmt.Errorf("apply fresh database migrations: %w", err)
	}
	return ctx.Err()
}
