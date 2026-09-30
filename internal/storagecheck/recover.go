package storagecheck

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

// ErrNeedsRecovery reports a database that a process stopped in the middle of
// a write: its journal still holds the unfinished transaction, and a read-only
// connection cannot roll it back. It accompanies ErrUnreadable.
var ErrNeedsRecovery = errors.New("database needs crash recovery")

// Extended SQLite result codes a read-only connection returns when the file
// needs recovery that only a writer may perform.
const (
	sqliteReadOnlyRecovery = 264  // SQLITE_READONLY_RECOVERY: the WAL index needs rebuilding
	sqliteReadOnlyRollback = 776  // SQLITE_READONLY_ROLLBACK: a hot rollback journal exists
	sqliteReadOnlyCantInit = 1288 // SQLITE_READONLY_CANTINIT: the WAL shared memory cannot be initialized
)

// Recovery describes the crash recovery CheckAtStart or Upgrade let SQLite
// perform before checking a database.
type Recovery struct {
	// Path is the database file.
	Path string
	// Journal is the rollback journal or write-ahead log SQLite consumed.
	Journal string
}

// CheckAtStart is Check for the process that is about to serve or upgrade the
// database. A database left mid-write by a killed process has a hot journal,
// which a read-only connection cannot roll back, so Check refuses it. Rolling
// it back only restores the last committed state, which any writer does when
// it opens the file, so CheckAtStart first lets SQLite do that on a connection
// that reads and writes nothing else, reports it through recovered when not
// nil, and then checks the database read-only like Check. A database that
// needs no recovery is left unchanged, and a policy refusal still leaves the
// recovered file as the last committed transaction wrote it.
func CheckAtStart(ctx context.Context, role Role, path string, recovered func(Recovery)) error {
	policy, err := PolicyFor(role)
	if err != nil {
		return err
	}
	absolute, err := policy.locate(path)
	if err != nil {
		return err
	}
	if err := recoverJournal(ctx, absolute, recovered); err != nil {
		return err
	}
	return policy.Check(ctx, absolute)
}

// probe opens the database read-only and reads its schema, which is where
// SQLite first notices a journal it would have to recover.
func probe(ctx context.Context, path string) error {
	db, err := openReadOnly(path)
	if err != nil {
		return err
	}
	defer db.Close()
	var tables int64
	return db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&tables)
}

// needsRecovery reports whether err is SQLite refusing a read-only connection
// until a writer recovers the database.
func needsRecovery(err error) bool {
	var coded interface{ Code() int }
	if !errors.As(err, &coded) {
		return false
	}
	switch coded.Code() {
	case sqliteReadOnlyRecovery, sqliteReadOnlyRollback, sqliteReadOnlyCantInit:
		return true
	}
	return false
}

// journalOf names the companion file SQLite recovers the database from.
func journalOf(path string) string {
	if _, err := os.Lstat(path + "-journal"); err == nil {
		return path + "-journal"
	}
	if _, err := os.Lstat(path + "-wal"); err == nil {
		return path + "-wal"
	}
	return path + "-journal"
}

// recoveryRefusal is the refusal of a database that still needs recovery.
func recoveryRefusal(path string, cause error) error {
	return fmt.Errorf("%w: %w: %q was left mid-write by a process that stopped, and its journal %q holds the unfinished "+
		"transaction (%v). Starting the daemon or running its -upgrade-database lets SQLite roll it back; "+
		"keep both files together and do not delete the journal", ErrUnreadable, ErrNeedsRecovery, path, journalOf(path), cause)
}

// recoverJournal lets SQLite recover a database whose read-only probe it
// refuses for want of a writer, and does nothing otherwise: an unreadable file
// is left for Check to report. The recovering connection only reads the
// schema inside a transaction it rolls back, so SQLite writes nothing but the
// pages the journal restores, and deletes the journal once they are restored.
func recoverJournal(ctx context.Context, path string, recovered func(Recovery)) error {
	err := probe(ctx, path)
	if err == nil || !needsRecovery(err) {
		return nil
	}
	journal := journalOf(path)
	err = rollBack(ctx, path)
	if err == nil {
		// A file SQLite can open only read-only, for example one without
		// write permission, is still hot after the writer's read.
		if err = probe(ctx, path); err != nil && !needsRecovery(err) {
			err = nil
		}
	}
	if err != nil {
		return fmt.Errorf("%w: %w: %q was left mid-write by a process that stopped, and SQLite could not roll back "+
			"its journal %q: %v. Stop every process using the database, keep the database and journal together "+
			"and restore the database from a backup", ErrUnreadable, ErrNeedsRecovery, path, journal, err)
	}
	if recovered != nil {
		recovered(Recovery{Path: path, Journal: journal})
	}
	return nil
}

// readable refuses, before any policy question, a database whose read-only
// probe SQLite rejects because it needs recovery first. Other read errors are
// left for the policy check to report.
func readable(ctx context.Context, path string) error {
	if err := probe(ctx, path); err != nil && needsRecovery(err) {
		return recoveryRefusal(path, err)
	}
	return nil
}

// rollBack opens the database for writing and reads its schema in a
// transaction that it rolls back: taking the read lock is what makes SQLite
// roll back a hot journal or rebuild a WAL index.
func rollBack(ctx context.Context, path string) (err error) {
	db, err := sqlitedb.Open(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	var tables int64
	err = tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&tables)
	if rollbackErr := tx.Rollback(); err == nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
		err = rollbackErr
	}
	return err
}
