package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	_ "modernc.org/sqlite"
)

// dispositionBindingLimit bounds how many distinct control sessions one
// inspection distinguishes. Rows and results are counted exactly whatever
// their number; only the number of sessions they came from is bounded, and a
// node that retains work from more sessions than this reports a lower bound.
// It is a variable so this package's tests can reach the bound without
// creating a thousand sessions.
var dispositionBindingLimit int64 = 1000

// InspectDisposition reads what a stopped executor's database still holds.
//
// It is an inspection, not a recovery: the database is opened read-only, no
// row is scheduled, finalized or deleted, and nothing here decides what
// happens to retained work. It is meant for the moment after local ownership
// has joined and before an operator decides whether the node may be upgraded
// or rebuilt, so it never opens a database a daemon is still serving on
// purpose: a caller must prove the join first.
func InspectDisposition(ctx context.Context, path string) (d scheduler.Disposition, err error) {
	err = PreserveDatabaseOwnership(path, func() error {
		var readErr error
		d, readErr = inspect(ctx, path)
		return readErr
	})
	return d, err
}

// PreserveDatabaseOwnership gives any newly created SQLite sidecars the
// database owner's identity. The operation must close all handles before it
// returns. Existing sidecars are untouched and no locking file is unlinked.
func PreserveDatabaseOwnership(path string, operation func() error) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("executor database %q is not a regular file", path)
	}
	var missing []string
	for _, suffix := range []string{"-shm", "-wal"} {
		sidecar := path + suffix
		if _, err := os.Lstat(sidecar); errors.Is(err, fs.ErrNotExist) {
			missing = append(missing, sidecar)
		} else if err != nil {
			return err
		}
	}
	err = operation()
	for _, sidecar := range missing {
		if ownErr := ownLike(info, sidecar); ownErr != nil {
			err = errors.Join(err, fmt.Errorf("preserve database sidecar ownership: %w", ownErr))
		}
	}
	return err
}

// ownLike gives the file at index the owner of the file owner describes,
// through the descriptor it is opened on, so no name is resolved twice. The
// index is a file SQLite built next to a database in a directory that belongs
// to the service account, and the account can replace it while this runs, so
// what it is is read from that descriptor and nothing else is accepted: not a
// link, not a named pipe that would make the open wait for somebody to answer
// it, and not a second name for a file elsewhere on the host, which would take
// the ownership with it. An index that is not there, because SQLite removed it
// when the last connection closed, is nothing to hand over.
func ownLike(owner fs.FileInfo, index string) error {
	file, err := os.OpenFile(index, os.O_RDONLY|openWithoutFollowing|openWithoutWaiting, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is %s, not a shared-memory index", index, info.Mode().Type())
	}
	names, ok := fileNames(info)
	if !ok {
		return fmt.Errorf("this platform does not report how many names %q has", index)
	}
	if names != 1 {
		return fmt.Errorf("%q is one of %d names for the same file", index, names)
	}
	uid, gid, ok := fileOwner(owner)
	if !ok {
		return errors.New("this platform does not report who owns a file")
	}
	return file.Chown(uid, gid)
}

// inspect reads one database strictly read-only. A daemon that was killed
// leaves its write-ahead log, and whether it also left its shared-memory file
// or not, that log is read here without being recovered and without writing to
// any of those files: an inspection never repairs the database it reads, and
// never leaves files behind that the service account may then not be able to
// write. A read that cannot be done read-only is reported as such, and the
// drain that asked for it still reports the node as drained.
func inspect(ctx context.Context, absolute string) (scheduler.Disposition, error) {
	var d scheduler.Disposition
	db, err := open(absolute)
	if err != nil {
		return d, fmt.Errorf("read executor database %q: %w", absolute, err)
	}
	defer db.Close()
	if err := inspectRuns(ctx, db, &d); err != nil {
		return d, fmt.Errorf("read retained runs from %q: %w", absolute, err)
	}
	if err := inspectTerminals(ctx, db, &d); err != nil {
		return d, fmt.Errorf("read retained terminal results from %q: %w", absolute, err)
	}
	return d, nil
}

// inspectRuns counts what is retained and how many control sessions it came
// from. The restore policy of this build accepts no stored binding, so every
// retained row is quarantined work on the next start; the number of sessions
// still shows an operator whether the retained rows accumulated over one
// session or many.
func inspectRuns(ctx context.Context, db *sql.DB, d *scheduler.Disposition) error {
	var started sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT count(*),
		sum(CASE WHEN started_at IS NOT NULL THEN 1 ELSE 0 END) FROM debuglets`).
		Scan(&d.Retained, &started); err != nil {
		return err
	}
	d.Started = started.Int64
	d.Queued = d.Retained - d.Started
	// Every stored binding belongs to a session that no longer exists, and
	// this build restores none of them.
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM operator_dispositions`).Scan(&d.Archived); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM debuglets
		WHERE NOT EXISTS (SELECT 1 FROM operator_dispositions WHERE run_id = debuglets.uuid)`).Scan(&d.Quarantined); err != nil {
		return err
	}
	// Counting sessions is the only bounded part, and the order makes the
	// bound a deterministic prefix rather than whichever rows came first.
	var bindings int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM (
		SELECT 1 FROM debuglets GROUP BY dispatcher_incarnation, session_id
		ORDER BY dispatcher_incarnation, session_id LIMIT ?)`, dispositionBindingLimit).
		Scan(&bindings); err != nil {
		return err
	}
	d.Bindings = int(bindings)
	d.Truncated = bindings >= dispositionBindingLimit
	return nil
}

func inspectTerminals(ctx context.Context, db *sql.DB, d *scheduler.Disposition) error {
	row := db.QueryRowContext(ctx, `SELECT count(*),
		sum(CASE WHEN attempts = 0 THEN 1 ELSE 0 END),
		sum(CASE WHEN rejected THEN 1 ELSE 0 END) FROM debuglet_exits`)
	var total int64
	var unsent, rejected sql.NullInt64
	if err := row.Scan(&total, &unsent, &rejected); err != nil {
		return err
	}
	d.RetainedTerminal, d.UnsentTerminal, d.RejectedTerminal = total, unsent.Int64, rejected.Int64
	return nil
}

// open opens an existing database without creating, upgrading or writing to
// it. A file URI keeps filename characters separate from options.
func open(path string) (*sql.DB, error) {
	if path == "" {
		return nil, errors.New("executor database path is empty")
	}
	return sqlitedb.Open(path, sqlitedb.ReadOnly())
}
