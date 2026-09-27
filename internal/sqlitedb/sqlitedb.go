// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package sqlitedb opens and migrates the daemons' SQLite databases with the
// connection settings their schemas rely on. Production code, the checkers
// and the tests all open SQLite through it, so every database is configured
// the same way.
package sqlitedb

import (
	"context"
	"database/sql"
	"io/fs"
	"math"
	"net/url"
	"path/filepath"
	"strconv"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

// BusyTimeoutMS is how long a connection waits for a lock held by another
// process, such as a checker or an operator command, before failing.
const BusyTimeoutMS = 1000

// Latest asks Migrate to apply every pending migration.
const Latest int64 = math.MaxInt64

// Option adjusts how Open opens a database.
type Option func(*options)

type options struct {
	mode        string
	queryOnly   bool
	synchronous bool
	busyTimeout int
}

// Create lets Open create the database file when it is absent. Only code that
// makes a new database, such as fresh-state setup, schema checks and tests,
// uses it; daemons open files that already exist.
func Create() Option {
	return func(o *options) { o.mode = "rwc" }
}

// ReadOnly opens the database without writing to it: the file is opened
// read-only and the connection refuses statements that would modify it, so a
// checker neither upgrades nor journals the file it inspects.
func ReadOnly() Option {
	return func(o *options) { o.mode, o.queryOnly = "ro", true }
}

// WithoutSync disables fsync (synchronous=OFF). Locking and journaling are
// unchanged, but a committed transaction may be lost on power failure, so only
// tests use it, where fsync otherwise dominates fixture cost on the CI
// container's overlay filesystem.
func WithoutSync() Option {
	return func(o *options) { o.synchronous = false }
}

// BusyTimeout replaces BusyTimeoutMS for a connection that must wait longer,
// such as a test that races writers on separate handles.
func BusyTimeout(ms int) Option {
	return func(o *options) { o.busyTimeout = ms }
}

// Open opens an existing database for reading and writing. SQLite enforces
// foreign keys only on connections that enable them, and the schemas declare
// references and cascades, so every connection enables them. mode=rw never
// creates a missing file unless Create is given, and the file URI keeps
// filename characters out of the options. The pool holds one connection:
// SQLite has a single writer.
func Open(path string, opts ...Option) (*sql.DB, error) {
	o := options{mode: "rw", synchronous: true, busyTimeout: BusyTimeoutMS}
	for _, opt := range opts {
		opt(&o)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	pragmas := []string{"foreign_keys(1)", "busy_timeout(" + strconv.Itoa(o.busyTimeout) + ")"}
	if o.queryOnly {
		pragmas = append(pragmas, "query_only(1)")
	}
	if !o.synchronous {
		pragmas = append(pragmas, "synchronous(OFF)")
	}
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(absolute)}
	dsn.RawQuery = url.Values{"mode": {o.mode}, "_pragma": pragmas}.Encode()
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

// Migrate applies the pending goose migrations in migrations to db, up to and
// including version upTo (Latest for all of them), and reports the version the
// database records afterwards. Each migration commits on its own, so when one
// fails the earlier ones stay applied; Migrate then still reports the version
// recorded, or -1 when it cannot read it, together with the error. Migrate
// leaves db open for the caller to close.
func Migrate(ctx context.Context, db *sql.DB, migrations fs.FS, upTo int64) (int64, error) {
	// The provider holds no resources of its own; closing it would only close
	// db, which belongs to the caller.
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, migrations,
		goose.WithDisableGlobalRegistry(true), goose.WithLogger(goose.NopLogger()))
	if err != nil {
		return -1, err
	}
	if _, err := provider.UpTo(ctx, upTo); err != nil {
		version, versionErr := provider.GetDBVersion(ctx)
		if versionErr != nil {
			version = -1
		}
		return version, err
	}
	return provider.GetDBVersion(ctx)
}
