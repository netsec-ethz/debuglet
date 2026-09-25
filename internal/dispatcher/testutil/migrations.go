// Package testutil holds test support shared by dispatcher packages. It is not
// imported by production code.
package testutil

import (
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ApplyMigrations initialises a fresh test database from the goose migration
// files in directory, in filename order, executing only each file's
// "-- +goose up" section. It understands the plain SQL those files currently
// contain (statements separated by ";", CRLF normalised, marker case ignored)
// and fails the test on any other goose directive. It records each applied
// file in the schema version table, so the result is the same state a
// migration run leaves behind. It is support for fresh test databases, not a
// production migration tool.
func ApplyMigrations(t *testing.T, db *sql.DB, directory string) {
	t.Helper()

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatalf("no migrations found in %s", directory)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS goose_db_version (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		version_id INTEGER NOT NULL,
		is_applied INTEGER NOT NULL,
		tstamp TIMESTAMP DEFAULT (datetime('now'))
	)`); err != nil {
		t.Fatalf("create schema version table: %v", err)
	}

	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		text := strings.ReplaceAll(string(raw), "\r\n", "\n")

		var up []string
		inUp := false
		for _, line := range strings.Split(text, "\n") {
			marker := strings.ToLower(strings.TrimSpace(line))
			switch {
			case marker == "-- +goose up":
				inUp = true
				continue
			case marker == "-- +goose down":
				inUp = false
				continue
			case strings.HasPrefix(marker, "-- +goose"):
				t.Fatalf("migration %s uses goose directive %q, which this helper does not support", name, line)
			}
			if inUp {
				up = append(up, line)
			}
		}
		if len(up) == 0 {
			t.Fatalf("migration %s has no up section", name)
		}

		applied := 0
		for _, stmt := range strings.Split(strings.Join(up, "\n"), ";") {
			if blankSQL(stmt) {
				continue
			}
			if _, err := db.Exec(stmt); err != nil {
				t.Fatalf("migration %s: %v\nstatement:\n%s", name, err, stmt)
			}
			applied++
		}
		if applied == 0 {
			t.Fatalf("migration %s applied no statements", name)
		}
		digits, _, _ := strings.Cut(name, "_")
		version, err := strconv.ParseInt(digits, 10, 64)
		if err != nil {
			t.Fatalf("migration %s has no version prefix", name)
		}
		if _, err := db.Exec("INSERT INTO goose_db_version (version_id, is_applied) VALUES (?, 1)", version); err != nil {
			t.Fatalf("record migration %s: %v", name, err)
		}
	}
}

// blankSQL reports whether a statement holds only whitespace and comments.
func blankSQL(stmt string) bool {
	for _, line := range strings.Split(stmt, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "--") {
			return false
		}
	}
	return true
}
