package storagecheck

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"

	_ "modernc.org/sqlite"
)

// Reasons a database is refused. An absent database, a readable one that is
// not ours, and a storage fault are separate answers for an operator.
var (
	ErrAbsent     = errors.New("database not found")
	ErrUnknown    = errors.New("unknown database")
	ErrUnreadable = errors.New("unreadable database")
	ErrOutdated   = errors.New("outdated database schema")
	ErrNewer      = errors.New("newer database schema")
	ErrIncomplete = errors.New("incomplete database schema")
)

// The table the packaged migrations record their progress in.
const versionTable = "goose_db_version"

// Check verifies the database at path against the schema policy of the role.
// It opens the file read-only and leaves its bytes unchanged even when it
// refuses it, so a refused database can still be inspected or restored. A
// database in WAL mode can still gain the usual -wal and -shm companions.
func Check(ctx context.Context, role Role, path string) error {
	policy, err := PolicyFor(role)
	if err != nil {
		return err
	}
	return policy.Check(ctx, path)
}

// Check verifies one database against this policy.
func (p Policy) Check(ctx context.Context, path string) error {
	absolute, err := p.locate(path)
	if err != nil {
		return err
	}
	db, err := openReadOnly(absolute)
	if err != nil {
		return fmt.Errorf("%w: cannot read database %q: %v", ErrUnreadable, absolute, err)
	}
	defer db.Close()
	return p.verify(ctx, db, absolute)
}

// locate resolves the configured path of an existing regular database file.
func (p Policy) locate(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: no %s database path is configured", ErrAbsent, p.Role)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s database path: %w", p.Role, err)
	}
	// Stat, not Lstat: SQLite follows a symlinked database path, so a link to
	// a regular database file is served like the file itself.
	info, err := os.Stat(absolute)
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("%w: %s database %q does not exist; apply the packaged migrations to it first "+
			"(make upgrade) or start a local service, which creates its own state directory",
			ErrAbsent, p.Role, absolute)
	}
	if err != nil {
		return "", fmt.Errorf("%w: cannot read database %q: %v", ErrUnreadable, absolute, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s database %q is not a regular file", ErrUnknown, p.Role, absolute)
	}
	return absolute, nil
}

// openReadOnly opens an existing database without creating, upgrading or
// journaling it. The file URI keeps filename characters out of the options.
func openReadOnly(path string) (*sql.DB, error) {
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

func (p Policy) verify(ctx context.Context, db *sql.DB, path string) error {
	version, tables, err := p.recognize(ctx, db, path)
	if err != nil {
		return err
	}
	if version < p.Minimum {
		return fmt.Errorf("%w: %q uses %s schema version %d; this build supports %s. "+
			"Stop the daemon, back the file up and run debuglet-%s -config FILE -upgrade-database "+
			"(a deployment runs deploy/ansible/upgrade-database.yml), or start from a new state directory",
			ErrOutdated, path, p.Role, version, p.supported(), p.Role)
	}
	return p.verifyTables(ctx, db, path, version, tables)
}

// recognize reports the schema version of a database that this role's
// migrations created and that is not newer than this build. Anything else is
// refused, so an upgrade never writes to a file that is not this role's.
func (p Policy) recognize(ctx context.Context, db *sql.DB, path string) (int64, map[string]struct{}, error) {
	tables, err := tableNames(ctx, db)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: cannot read database %q: %v", ErrUnreadable, path, err)
	}
	if _, ok := tables[versionTable]; !ok {
		return 0, nil, fmt.Errorf("%w: %q has no %s table and was not created by Debuglet; "+
			"point database.path in the %s configuration at a Debuglet database", ErrUnknown, path, versionTable, p.Role)
	}
	version, err := schemaVersion(ctx, db)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: cannot read database %q: %v", ErrUnreadable, path, err)
	}
	if version == 0 {
		return 0, nil, fmt.Errorf("%w: %q records no applied migration; the %s schema was never created. "+
			"Restore a backup or start from a new state directory", ErrIncomplete, path, p.Role)
	}
	// Which role a database belongs to is decided before its version, so a
	// path pointing at the other database reports the path, not an upgrade.
	if err := p.identify(ctx, db, path, tables); err != nil {
		return 0, nil, err
	}
	if version > p.Current {
		return 0, nil, fmt.Errorf("%w: %q uses %s schema version %d, newer than the version %d this build supports; "+
			"install a Debuglet release that supports it", ErrNewer, path, p.Role, version, p.Current)
	}
	return version, tables, nil
}

// identify reports a readable Debuglet database that belongs to the other
// role, whatever schema version it records.
func (p Policy) identify(ctx context.Context, db *sql.DB, path string, tables map[string]struct{}) error {
	wrong := fmt.Errorf("%w: %q is not a %s database; point database.path in the %s configuration at its own database",
		ErrUnknown, path, p.Role, p.Role)
	for _, table := range sortedKeys(p.Identity) {
		if _, ok := tables[table]; !ok {
			return wrong
		}
		columns, err := p.columnNames(ctx, db, path, table)
		if err != nil {
			return err
		}
		for _, column := range p.Identity[table] {
			if _, ok := columns[column]; !ok {
				return wrong
			}
		}
	}
	return nil
}

// verifyTables reports a schema whose recorded version was reached without its
// tables and columns, which is what a migration interrupted halfway leaves.
func (p Policy) verifyTables(ctx context.Context, db *sql.DB, path string, version int64, tables map[string]struct{}) error {
	for _, table := range sortedKeys(p.Tables) {
		if _, ok := tables[table]; !ok {
			return fmt.Errorf("%w: %q records %s schema version %d but has no table %q; "+
				"the migrations did not complete. Restore a backup or start from a new state directory",
				ErrIncomplete, path, p.Role, version, table)
		}
		columns, err := p.columnNames(ctx, db, path, table)
		if err != nil {
			return err
		}
		for _, column := range p.Tables[table] {
			if _, ok := columns[column]; !ok {
				return fmt.Errorf("%w: %q records %s schema version %d but table %q has no column %q; "+
					"the migrations did not complete. Restore a backup or start from a new state directory",
					ErrIncomplete, path, p.Role, version, table, column)
			}
		}
	}
	return nil
}

func (p Policy) supported() string {
	if p.Minimum == p.Current {
		return fmt.Sprintf("version %d", p.Current)
	}
	return fmt.Sprintf("versions %d to %d", p.Minimum, p.Current)
}

// names reads a one-column result into a set.
func names(ctx context.Context, db *sql.DB, query string, args ...any) (map[string]struct{}, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := make(map[string]struct{})
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		found[name] = struct{}{}
	}
	return found, rows.Err()
}

func tableNames(ctx context.Context, db *sql.DB) (map[string]struct{}, error) {
	return names(ctx, db, "SELECT name FROM sqlite_master WHERE type = 'table'")
}

func (p Policy) columnNames(ctx context.Context, db *sql.DB, path, table string) (map[string]struct{}, error) {
	columns, err := names(ctx, db, "SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read database %q: %v", ErrUnreadable, path, err)
	}
	return columns, nil
}

// schemaVersion reports the highest applied migration; zero means none.
func schemaVersion(ctx context.Context, db *sql.DB) (int64, error) {
	var version int64
	err := db.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(version_id), 0) FROM "+versionTable+" WHERE is_applied != 0").Scan(&version)
	if err != nil {
		return 0, err
	}
	return version, nil
}

func sortedKeys(tables map[string][]string) []string {
	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
