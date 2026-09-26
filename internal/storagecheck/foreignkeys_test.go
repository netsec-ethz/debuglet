package storagecheck

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestForeignKeyViolationsCountsOrphansWithoutChangingThem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orphans.sqlite")
	// Written without foreign keys enforced, as the daemons wrote before.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE transactions (id TEXT PRIMARY KEY);
		CREATE TABLE debuglet_order (transaction_id TEXT NOT NULL REFERENCES transactions(id), order_id INTEGER);
		INSERT INTO transactions (id) VALUES ('kept');
		INSERT INTO debuglet_order VALUES ('kept', 1), ('gone', 1), ('gone', 2);`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	violations, err := ForeignKeyViolations(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	want := ForeignKeyViolation{Table: "debuglet_order", Parent: "transactions", Rows: 2}
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations %+v, want [%+v]", violations, want)
	}

	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var orders int
	if err := db.QueryRow(`SELECT count(*) FROM debuglet_order`).Scan(&orders); err != nil || orders != 3 {
		t.Fatalf("the check changed the database: %d rows, %v", orders, err)
	}
}

func TestForeignKeyViolationsOfAConsistentDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clean.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE parents (id INTEGER PRIMARY KEY); CREATE TABLE children (parent_id INTEGER REFERENCES parents(id));`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if violations, err := ForeignKeyViolations(t.Context(), path); err != nil || len(violations) != 0 {
		t.Fatalf("violations %+v, %v; want none", violations, err)
	}
}
