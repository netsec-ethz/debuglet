// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sqlitedb

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func create(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`
		CREATE TABLE parents (id INTEGER PRIMARY KEY);
		CREATE TABLE children (parent_id INTEGER NOT NULL REFERENCES parents(id) ON DELETE CASCADE);`); err != nil {
		t.Fatal(err)
	}
}

func TestOpenEnforcesForeignKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a b%c#d.sqlite")
	create(t, path)
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var enabled, timeout int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	if enabled != 1 || timeout != BusyTimeoutMS {
		t.Fatalf("foreign_keys=%d busy_timeout=%d, want 1 and %d", enabled, timeout, BusyTimeoutMS)
	}

	if _, err := db.Exec(`INSERT INTO children (parent_id) VALUES (7)`); err == nil {
		t.Fatal("an orphan row was inserted")
	}
	if _, err := db.Exec(`INSERT INTO parents (id) VALUES (1); INSERT INTO children (parent_id) VALUES (1); DELETE FROM parents`); err != nil {
		t.Fatal(err)
	}
	var children int
	if err := db.QueryRow(`SELECT count(*) FROM children`).Scan(&children); err != nil {
		t.Fatal(err)
	}
	if children != 0 {
		t.Fatalf("%d children survived their parent's deletion", children)
	}
}

func TestOpenNeverCreatesADatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.sqlite")
	db, err := Open(path)
	if err == nil {
		err = db.Ping()
		db.Close()
	}
	if err == nil {
		t.Fatal("opening an absent database succeeded")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("the absent database was created: %v", statErr)
	}
}

func TestOpenOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "created.sqlite")
	db, err := Open(path, Create(), WithoutSync(), BusyTimeout(5000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE rows (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	var synchronous, timeout int
	if err := db.QueryRow(`PRAGMA synchronous`).Scan(&synchronous); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	if synchronous != 0 || timeout != 5000 {
		t.Fatalf("synchronous=%d busy_timeout=%d, want 0 and 5000", synchronous, timeout)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := Open(path, ReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var rows int
	if err := reader.QueryRow(`SELECT count(*) FROM rows`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Exec(`INSERT INTO rows (id) VALUES (1)`); err == nil {
		t.Fatal("a read-only handle wrote to the database")
	}
}

func TestMigrate(t *testing.T) {
	migrations := fstest.MapFS{
		"00001_parents.sql":  {Data: []byte("-- +goose Up\nCREATE TABLE parents (id INTEGER PRIMARY KEY);\n-- +goose Down\nDROP TABLE parents;\n")},
		"00002_children.sql": {Data: []byte("-- +goose Up\nCREATE TABLE children (parent_id INTEGER REFERENCES parents(id));\n-- +goose Down\nDROP TABLE children;\n")},
		"00003_broken.sql":   {Data: []byte("-- +goose Up\nCREATE TABLE parents (id INTEGER);\n-- +goose Down\nSELECT 1;\n")},
	}
	db, err := Open(filepath.Join(t.TempDir(), "migrated.sqlite"), Create())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := t.Context()

	if version, err := Migrate(ctx, db, migrations, 2); err != nil || version != 2 {
		t.Fatalf("migrating to version 2 reports version %d: %v", version, err)
	}
	if version, err := Migrate(ctx, db, migrations, 2); err != nil || version != 2 {
		t.Fatalf("migrating again reports version %d: %v", version, err)
	}
	// Version 3 fails; the version recorded before it is still reported.
	if version, err := Migrate(ctx, db, migrations, Latest); err == nil || version != 2 {
		t.Fatalf("a failed migration reports version %d: %v", version, err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("Migrate closed the database: %v", err)
	}
}
