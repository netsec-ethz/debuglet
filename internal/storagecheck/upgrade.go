package storagecheck

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net/url"
	"path/filepath"

	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/pressly/goose/v3"
)

// Upgrade applies the packaged migrations of the role to the database at path
// and returns the schema version it then records, once Check accepts it. It
// first refuses, with Check's answers, a path that is absent, unreadable, not
// this role's Debuglet database, or newer than this build, and writes nothing
// to it. It takes no backup and expects the daemon using the file to be
// stopped. Each migration commits on its own, so a failed one leaves the
// earlier ones applied; Check then reports the version reached as outdated
// and a later Upgrade continues from it.
func Upgrade(ctx context.Context, role Role, path string) (int64, error) {
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
	_, _, err = policy.recognize(ctx, db, absolute)
	if closeErr := db.Close(); err == nil && closeErr != nil {
		err = fmt.Errorf("%w: cannot read database %q: %v", ErrUnreadable, absolute, closeErr)
	}
	if err != nil {
		return 0, err
	}
	version, err := applyPending(ctx, absolute, migrations)
	if err != nil {
		return 0, fmt.Errorf("upgrade %s database %q: %w", role, absolute, err)
	}
	if err := policy.Check(ctx, absolute); err != nil {
		return 0, err
	}
	return version, nil
}

// applyPending applies every pending migration to an existing database and
// reports the version it records afterwards. The file URI keeps filename
// characters out of the options, and mode=rw never creates a missing file.
func applyPending(ctx context.Context, path string, migrations fs.FS) (version int64, err error) {
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	dsn.RawQuery = url.Values{
		"mode":    {"rw"},
		"_pragma": {"foreign_keys(1)", "busy_timeout(1000)"},
	}.Encode()
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return 0, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, migrations,
		goose.WithDisableGlobalRegistry(true), goose.WithLogger(goose.NopLogger()))
	if err != nil {
		db.Close()
		return 0, err
	}
	// Closing the provider closes the database.
	defer func() {
		if closeErr := provider.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	if _, err := provider.Up(ctx); err != nil {
		if recorded, versionErr := provider.GetDBVersion(ctx); versionErr == nil {
			err = fmt.Errorf("%w; the database records version %d, run the upgrade again to continue", err, recorded)
		}
		return 0, err
	}
	return provider.GetDBVersion(ctx)
}
