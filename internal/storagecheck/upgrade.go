package storagecheck

import (
	"context"
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
// backup and expects the daemon using the file to be stopped. Each migration
// commits on its own, so a failed one leaves the earlier ones applied; Check
// then reports the version reached as outdated and a later Upgrade continues
// from it.
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
	version, err = applyPending(ctx, absolute, migrations)
	if err != nil {
		return 0, fmt.Errorf("upgrade %s database %q: %w", role, absolute, err)
	}
	if err := policy.Check(ctx, absolute); err != nil {
		return 0, err
	}
	return version, nil
}

// applyPending applies every pending migration to an existing database and
// reports the version it records afterwards. sqlitedb.Open never creates a
// missing file.
func applyPending(ctx context.Context, path string, migrations fs.FS) (version int64, err error) {
	db, err := sqlitedb.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() {
		if closeErr := db.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	version, err = sqlitedb.Migrate(ctx, db, migrations, sqlitedb.Latest)
	if err != nil {
		if version >= 0 {
			err = fmt.Errorf("%w; the database records version %d, run the upgrade again to continue", err, version)
		}
		return 0, err
	}
	return version, nil
}
