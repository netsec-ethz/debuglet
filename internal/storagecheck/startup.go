// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package storagecheck

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// OpenForService checks an existing database and opens it for the daemon.
// Unlike Check, it may recover a hot rollback journal left by an interrupted
// writer. Recovery is first checked on a private copy, so an unknown or
// unsupported database is still refused without changing the original.
// It never creates or upgrades the original database. As with the daemon's
// normal startup, the caller must be the only service using this state.
func OpenForService(ctx context.Context, role Role, path string) (*sql.DB, error) {
	policy, err := PolicyFor(role)
	if err != nil {
		return nil, err
	}
	absolute, err := policy.checkForService(ctx, path)
	if err != nil {
		return nil, err
	}
	db, err := sqlitedb.Open(absolute)
	if err != nil {
		return nil, err
	}
	// This read performs SQLite's normal journal recovery on the original
	// when needed, and verifies the connection that the service will use.
	if err := policy.verify(ctx, db, absolute); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// CheckForService verifies a database before launching its daemon. A hot
// rollback journal is recovered only in a temporary copy; the database and
// journal are left unchanged. The daemon must still call OpenForService to
// recover the original. This is not an offline-backup or stopped-writer check.
func CheckForService(ctx context.Context, role Role, path string) error {
	policy, err := PolicyFor(role)
	if err != nil {
		return err
	}
	_, err = policy.checkForService(ctx, path)
	return err
}

func (policy Policy) checkForService(ctx context.Context, path string) (string, error) {
	absolute, err := policy.locate(path)
	if err != nil {
		return "", err
	}
	if err := policy.Check(ctx, absolute); err != nil {
		var sqliteErr *sqlite.Error
		if !errors.As(err, &sqliteErr) || sqliteErr.Code() != sqlite3.SQLITE_READONLY_ROLLBACK {
			return "", err
		}
		// SQLite names a rollback journal beside the resolved database file.
		absolute, err = filepath.EvalSymlinks(absolute)
		if err != nil {
			return "", err
		}
		if err := policy.checkRecoveryCopy(ctx, absolute); err != nil {
			return "", fmt.Errorf("check interrupted database before recovery: %w", err)
		}
	}
	return absolute, nil
}

func (p Policy) checkRecoveryCopy(ctx context.Context, path string) error {
	dir, err := os.MkdirTemp(filepath.Dir(path), ".debuglet-recovery-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	copyPath := filepath.Join(dir, "database.sqlite")
	// Copy exactly the initial sizes, using fixed memory. A growing source
	// cannot turn this into an unbounded copy. Space/write errors affect only
	// these temporary files, which are removed before returning.
	sources := []string{path, path + "-journal"}
	var before [2]os.FileInfo
	for i, source := range sources {
		before[i], err = os.Stat(source)
		if err != nil {
			return err
		}
		if !before[i].Mode().IsRegular() {
			return fmt.Errorf("recovery input %q is not a regular file", source)
		}
		target := copyPath
		if i == 1 {
			target += "-journal"
		}
		if err := copyRecoveryFile(ctx, source, target, before[i]); err != nil {
			return fmt.Errorf("copy recovery input %q: %w", source, err)
		}
	}
	db, err := sqlitedb.Open(copyPath)
	if err != nil {
		return err
	}
	err = p.verify(ctx, db, path)
	err = errors.Join(err, db.Close())
	if err != nil {
		return err
	}
	for i, source := range sources {
		if err := recoveryInputUnchanged(source, before[i]); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func recoveryInputUnchanged(path string, before os.FileInfo) error {
	after, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return fmt.Errorf("database recovery input %q changed; stop every process using the database and retry", path)
	}
	return nil
}

func copyRecoveryFile(ctx context.Context, source, target string, before os.FileInfo) (err error) {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, out.Close()) }()
	buf := make([]byte, 64<<10)
	for remaining := before.Size(); remaining > 0; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := io.ReadFull(in, buf[:min(int64(len(buf)), remaining)])
		if err != nil {
			return err
		}
		if _, err := out.Write(buf[:n]); err != nil {
			return err
		}
		remaining -= int64(n)
	}
	return recoveryInputUnchanged(source, before)
}
