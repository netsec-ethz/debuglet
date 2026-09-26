// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sqlitedb

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
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
