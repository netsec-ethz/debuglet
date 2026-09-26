// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package sqlitedb opens the daemons' SQLite databases with the connection
// settings their schemas rely on.
package sqlitedb

import (
	"database/sql"
	"net/url"
	"path/filepath"
	"strconv"

	_ "modernc.org/sqlite"
)

// BusyTimeoutMS is how long a connection waits for a lock held by another
// process, such as a checker or an operator command, before failing.
const BusyTimeoutMS = 1000

// Open opens an existing database for reading and writing. SQLite enforces
// foreign keys only on connections that enable them, and the schemas declare
// references and cascades, so every connection enables them. mode=rw never
// creates a missing file, and the file URI keeps filename characters out of
// the options. The pool holds one connection: SQLite has a single writer.
func Open(path string) (*sql.DB, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(absolute)}
	dsn.RawQuery = url.Values{
		"mode":    {"rw"},
		"_pragma": {"foreign_keys(1)", "busy_timeout(" + strconv.Itoa(BusyTimeoutMS) + ")"},
	}.Encode()
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}
