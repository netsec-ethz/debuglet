package database

import (
	"embed"
	"io/fs"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// MigrationFS exposes the canonical SQL migrations without global registration.
func MigrationFS() fs.FS {
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		panic(err) // The embedded directory is fixed at build time.
	}
	return migrations
}
