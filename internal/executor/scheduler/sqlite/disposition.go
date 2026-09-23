package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"

	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
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
func InspectDisposition(ctx context.Context, path string) (scheduler.Disposition, error) {
	var d scheduler.Disposition
	absolute, err := filepath.Abs(path)
	if err != nil {
		return d, err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return d, err
	}
	if !info.Mode().IsRegular() {
		return d, fmt.Errorf("executor database %q is not a regular file", absolute)
	}
	// Reading a write-ahead log makes SQLite build the database's
	// shared-memory index, creating that file when it is absent. This
	// command runs as an administrator over a directory that belongs to
	// the service account, so a file it creates there would belong to the
	// wrong account and the daemon could not write it at its next start.
	// An index that was not there before is therefore given to whoever owns
	// the database. It is handed over rather than removed: a daemon started
	// since this read may already be serving on it, and unlinking a live
	// database's index takes the locking state its connections share away
	// from them. It is a scratch file either way.
	index := absolute + "-shm"
	_, indexErr := os.Lstat(index)
	d, err = inspect(ctx, absolute)
	if errors.Is(indexErr, fs.ErrNotExist) {
		if ownErr := ownLike(info, index); ownErr != nil {
			return d, errors.Join(err, fmt.Errorf("hand the shared-memory index of %q to the database's owner: %w", absolute, ownErr))
		}
	}
	return d, err
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
	d.Quarantined = d.Retained
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
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	dsn.RawQuery = url.Values{
		"mode":    {"ro"},
		"_pragma": {"query_only(1)", "busy_timeout(1000)"},
	}.Encode()
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}
