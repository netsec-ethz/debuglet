package storagecheck

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

// UpgradeOption changes what Upgrade agrees to do.
type UpgradeOption func(*upgradeOptions)

type upgradeOptions struct {
	acceptDataLoss bool
}

// AcceptDataLoss lets Upgrade apply a migration that drops the recorded runs
// and their logs. Without it such a database is refused and left unchanged.
func AcceptDataLoss() UpgradeOption {
	return func(o *upgradeOptions) { o.acceptDataLoss = true }
}

// Upgrade applies the packaged migrations of the role to the database at path
// and returns the schema version it then records, once Check accepts it. It
// first refuses, with Check's answers, a path that is absent, unreadable, not
// this role's Debuglet database, or newer than this build, and writes nothing
// to it. A database whose upgrade drops the recorded runs is refused the same
// way with ErrDataLoss unless the caller passes AcceptDataLoss. It takes no
// backup and expects the daemon using the file to be stopped. It holds an
// exclusive SQLite connection across every migration and the final check, so
// another writer cannot interleave between migration commits. Each migration
// commits on its own; a failed one leaves the earlier ones applied and a later
// Upgrade continues from the recorded version. The deployment procedure keeps
// the original backup and leaves the service stopped after a failed upgrade.
func Upgrade(ctx context.Context, role Role, path string, opts ...UpgradeOption) (int64, error) {
	var options upgradeOptions
	for _, opt := range opts {
		opt(&options)
	}
	policy, err := PolicyFor(role)
	if err != nil {
		return 0, err
	}
	migrations := dispatcherdb.MigrationFS()
	if role == Executor {
		migrations = executordb.MigrationFS()
	}
	absolute, err := policy.locate(path)
	if err != nil {
		return 0, err
	}
	db, err := openReadOnly(absolute)
	if err != nil {
		return 0, fmt.Errorf("%w: cannot read database %q: %v", ErrUnreadable, absolute, err)
	}
	version, _, err := policy.recognize(ctx, db, absolute)
	if closeErr := db.Close(); err == nil && closeErr != nil {
		err = fmt.Errorf("%w: cannot read database %q: %v", ErrUnreadable, absolute, closeErr)
	}
	if err != nil {
		return 0, err
	}
	if policy.dropsData(version) && !options.acceptDataLoss {
		return 0, fmt.Errorf("%w: upgrading %s database %q from schema version %d drops the recorded runs and their logs "+
			"(tables debuglets and debuglet_logs); nothing was changed. Keep a backup and run the upgrade again with "+
			"-accept-data-loss (upgrade_accept_data_loss=true for deploy/ansible/upgrade-database.yml) to accept it",
			ErrDataLoss, role, absolute, version)
	}
	if version == policy.Current {
		return version, policy.Check(ctx, absolute)
	}
	db, err = OpenExclusive(ctx, absolute)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	// Recognition before taking ownership is only a read-only preflight. Check
	// again on the exclusive connection so another upgrader cannot invalidate
	// the decision while this caller waits for the lock.
	version, _, err = policy.recognize(ctx, db, absolute)
	if err != nil {
		return 0, err
	}
	if policy.dropsData(version) && !options.acceptDataLoss {
		return 0, fmt.Errorf("%w: database version changed before exclusive ownership; nothing was migrated; check the database and explicitly accept any required data loss", ErrDataLoss)
	}
	version, err = applyPending(ctx, db, migrations)
	if err != nil {
		return 0, fmt.Errorf("upgrade %s database %q: %w", role, absolute, err)
	}
	if err := policy.verify(ctx, db, absolute); err != nil {
		return 0, err
	}
	if err := db.Close(); err != nil {
		return 0, fmt.Errorf("close upgraded database %q: %w", absolute, err)
	}
	return version, nil
}

// OpenExclusive takes SQLite ownership for offline maintenance. With one
// connection in EXCLUSIVE locking mode, COMMIT retains the database lock until
// Close; goose can still use its normal per-migration transactions. This also
// applies to WAL databases and does not rely on every writer using a sidecar
// lock. It cannot establish that an idle daemon has stopped; operators must
// still stop the service before upgrading it.
// The caller must check the schema and prove shutdown separately, and keep
// this connection open until its complete maintenance operation has finished.
func OpenExclusive(ctx context.Context, path string) (*sql.DB, error) {
	db, err := sqlitedb.Open(path)
	if err != nil {
		return nil, err
	}
	for _, statement := range []string{"PRAGMA locking_mode = EXCLUSIVE", "BEGIN EXCLUSIVE", "COMMIT"} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			db.Close()
			return nil, fmt.Errorf("cannot acquire exclusive database access for %q: stop every daemon using it and retry maintenance: %w", path, err)
		}
	}
	return db, nil
}

// applyPending retains the caller's exclusive connection while the canonical
// migrations commit, then reports their durable progress if one fails.
func applyPending(ctx context.Context, db *sql.DB, migrations fs.FS) (version int64, err error) {
	version, err = sqlitedb.Migrate(ctx, db, migrations, sqlitedb.Latest)
	if err != nil {
		if version >= 0 {
			err = fmt.Errorf("%w; the database records version %d, run the upgrade again to continue", err, version)
		}
		return 0, err
	}
	return version, nil
}
