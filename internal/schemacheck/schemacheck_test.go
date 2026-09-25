package schemacheck

import (
	"database/sql"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// freshDatabase applies a role's embedded sequence to a private database and
// closes it when the test ends.
func freshDatabase(t *testing.T, role Role) *sql.DB {
	t.Helper()
	db, err := OpenFresh(t.Context(), t.TempDir(), role.Migrations)
	if err != nil {
		t.Fatalf("%s fresh database: %v", role.Name, err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close %s database: %v", role.Name, err)
		}
	})
	return db
}

// TestMigrationSequenceOrdering rejects a sequence a fresh database could not
// apply in a defined order: a name outside NNNNN_lower_case.sql, a repeated or
// skipped version, or a file without both goose annotations.
func TestMigrationSequenceOrdering(t *testing.T) {
	for _, role := range Roles() {
		t.Run(role.Name, func(t *testing.T) {
			migrations, err := Migrations(role.Migrations)
			if err != nil {
				t.Fatalf("%s migrations: %v", role.Name, err)
			}
			for _, migration := range migrations {
				if err := Directives(role.Migrations, migration.File); err != nil {
					t.Errorf("%s: %v", role.Name, err)
				}
			}
			t.Logf("%s embeds %d migrations up to version %d",
				role.Name, len(migrations), migrations[len(migrations)-1].Version)
		})
	}
}

// TestEmbeddedSequenceMatchesCheckout proves the sequence compiled into the
// binaries is the same set of bytes the generator reads from the checkout. A
// migration that the embed pattern misses would otherwise reach sqlc without
// ever being applied at runtime.
func TestEmbeddedSequenceMatchesCheckout(t *testing.T) {
	root := repoRoot(t)
	for _, role := range Roles() {
		t.Run(role.Name, func(t *testing.T) {
			migrations, err := Migrations(role.Migrations)
			if err != nil {
				t.Fatalf("%s migrations: %v", role.Name, err)
			}
			embedded := make([]string, 0, len(migrations))
			for _, migration := range migrations {
				embedded = append(embedded, migration.File)
			}
			directory := filepath.Join(root, filepath.FromSlash(role.MigrationsDir))
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatalf("read %s: %v", role.MigrationsDir, err)
			}
			checkout := make([]string, 0, len(entries))
			for _, entry := range entries {
				checkout = append(checkout, entry.Name())
			}
			slices.Sort(embedded)
			slices.Sort(checkout)
			if !slices.Equal(embedded, checkout) {
				t.Fatalf("%s embeds %v but %s holds %v",
					role.Name, embedded, role.MigrationsDir, checkout)
			}
			for _, name := range embedded {
				want, err := os.ReadFile(filepath.Join(directory, name))
				if err != nil {
					t.Fatalf("read %s: %v", name, err)
				}
				got, err := fs.ReadFile(role.Migrations, name)
				if err != nil {
					t.Fatalf("read embedded %s: %v", name, err)
				}
				if string(got) != string(want) {
					t.Errorf("%s: embedded %s differs from %s/%s", role.Name, name, role.MigrationsDir, name)
				}
			}
		})
	}
}

// TestGeneratorConfigAddressesEmbeddedSequences keeps the generator pointed at
// the directories the roles actually embed and generate into. Bindings built
// from some other schema would compile and still not match the database.
func TestGeneratorConfigAddressesEmbeddedSequences(t *testing.T) {
	config, err := ReadGeneratorConfig(filepath.Join(repoRoot(t), "sqlc.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var schema, queries, out []string
	for _, role := range Roles() {
		schema = append(schema, role.MigrationsDir)
		queries = append(queries, role.QueriesDir)
		out = append(out, role.GeneratedDir)
	}
	for _, pair := range []struct {
		name       string
		configured []string
		want       []string
	}{
		{"schema", config.Schema, schema},
		{"queries", config.Queries, queries},
		{"out", config.Out, out},
	} {
		configured := slices.Clone(pair.configured)
		want := slices.Clone(pair.want)
		slices.Sort(configured)
		slices.Sort(want)
		if !slices.Equal(configured, want) {
			t.Errorf("sqlc.yml %s is %v, roles use %v", pair.name, configured, want)
		}
	}
}

// TestFreshDatabaseAppliesEmbeddedSequence applies each sequence to a real,
// private SQLite database and confirms every migration was recorded. It says
// nothing about upgrading a database that already holds rows.
func TestFreshDatabaseAppliesEmbeddedSequence(t *testing.T) {
	for _, role := range Roles() {
		t.Run(role.Name, func(t *testing.T) {
			migrations, err := Migrations(role.Migrations)
			if err != nil {
				t.Fatalf("%s migrations: %v", role.Name, err)
			}
			ctx := t.Context()
			db := freshDatabase(t, role)
			version, err := AppliedVersion(ctx, db)
			if err != nil {
				t.Fatal(err)
			}
			if want := migrations[len(migrations)-1].Version; version != want {
				t.Fatalf("%s applied up to version %d, embedded sequence ends at %d",
					role.Name, version, want)
			}
			tables, err := TableColumns(ctx, db)
			if err != nil {
				t.Fatal(err)
			}
			if len(tables) == 0 {
				t.Fatalf("%s fresh schema has no tables", role.Name)
			}
		})
	}
}

// TestGeneratedQueriesPrepareAgainstFreshSchema runs every committed generated
// query through SQLite against the canonical fresh schema, so a query naming a
// column the migrations do not create fails here instead of at runtime.
func TestGeneratedQueriesPrepareAgainstFreshSchema(t *testing.T) {
	root := repoRoot(t)
	for _, role := range Roles() {
		t.Run(role.Name, func(t *testing.T) {
			generated, err := GeneratedQueries(filepath.Join(root, filepath.FromSlash(role.GeneratedDir)))
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := CanonicalQueryNames(filepath.Join(root, filepath.FromSlash(role.QueriesDir)))
			if err != nil {
				t.Fatal(err)
			}
			names := make([]string, 0, len(generated))
			for name := range generated {
				names = append(names, name)
			}
			slices.Sort(names)
			if !slices.Equal(names, canonical) {
				t.Fatalf("%s generates %v from canonical queries %v", role.Name, names, canonical)
			}
			ctx := t.Context()
			db := freshDatabase(t, role)
			for _, name := range names {
				statement, err := db.PrepareContext(ctx, generated[name])
				if err != nil {
					t.Errorf("%s query %s does not prepare against the fresh schema: %v",
						role.Name, name, err)
					continue
				}
				if err := statement.Close(); err != nil {
					t.Errorf("close prepared %s: %v", name, err)
				}
			}
			t.Logf("%s prepared %d generated queries", role.Name, len(names))
		})
	}
}

// TestGeneratedModelsMatchFreshSchema compares the committed models with the
// columns a fresh database really has. The generator reads the migrations with
// its own SQL parser; this is the independent check against SQLite itself.
func TestGeneratedModelsMatchFreshSchema(t *testing.T) {
	root := repoRoot(t)
	for _, role := range Roles() {
		t.Run(role.Name, func(t *testing.T) {
			models, err := GeneratedStructs(filepath.Join(root, filepath.FromSlash(role.GeneratedDir), "models.go"))
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			db := freshDatabase(t, role)
			tables, err := TableColumns(ctx, db)
			if err != nil {
				t.Fatal(err)
			}
			unmatched := make(map[string][]string, len(models))
			for model, fields := range models {
				signature := Signature(fields)
				unmatched[signature] = append(unmatched[signature], model)
			}
			matched := 0
			for _, table := range slices.Sorted(maps.Keys(tables)) {
				signature := Signature(tables[table])
				candidates := unmatched[signature]
				if len(candidates) == 0 {
					t.Errorf("%s table %s has columns %v that no generated model matches",
						role.Name, table, tables[table])
					continue
				}
				slices.Sort(candidates)
				unmatched[signature] = candidates[1:]
				matched++
			}
			for _, signature := range slices.Sorted(maps.Keys(unmatched)) {
				for _, model := range unmatched[signature] {
					t.Errorf("%s model %s with fields %v matches no table of the fresh schema",
						role.Name, model, models[model])
				}
			}
			t.Logf("%s matched %d models against the fresh schema", role.Name, matched)
		})
	}
}
