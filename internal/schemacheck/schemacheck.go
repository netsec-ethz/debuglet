// Package schemacheck reads the canonical SQL of both roles and the bindings
// generated from it so tests can compare them against a real database. It
// exposes those inputs without interpreting them: deciding what has to agree
// is left to the tests.
package schemacheck

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

const modulePath = "github.com/netsec-ethz/debuglet"

// Role is one embedded migration sequence together with the canonical queries
// and the generated bindings produced from it.
type Role struct {
	Name          string
	Migrations    fs.FS
	MigrationsDir string
	QueriesDir    string
	GeneratedDir  string
}

// Roles returns both schemas the project ships, in a stable order. Each role
// keeps its sequence, its canonical queries and its bindings below one
// directory named after it, which is also what sqlc.yml addresses.
func Roles() []Role {
	role := func(name string, sequence fs.FS) Role {
		dir := "internal/" + name + "/database"
		return Role{Name: name, Migrations: sequence, MigrationsDir: dir + "/migrations", QueriesDir: dir + "/queries", GeneratedDir: dir}
	}
	return []Role{role("dispatcher", dispatcherdb.MigrationFS()), role("executor", executordb.MigrationFS())}
}

// RepoRoot locates the checkout that holds the running package.
func RepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("locate working directory: %w", err)
	}
	marker := []byte("module " + modulePath + "\n")
	for {
		body, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && bytes.Contains(body, marker) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no %s checkout above the working directory", modulePath)
		}
		dir = parent
	}
}

// Migration is one file of an embedded sequence.
type Migration struct {
	Version int64
	File    string
}

// Numbered migrations are applied in numeric order, so a name goose cannot
// order unambiguously is rejected before it reaches a database.
var migrationFile = regexp.MustCompile(`^([0-9]{5})_[a-z0-9]+(?:_[a-z0-9]+)*\.sql$`)

// Migrations lists an embedded sequence in applied order. It rejects names
// outside NNNNN_lower_case.sql, repeated version numbers, and sequences that
// do not run from 1 without gaps.
func Migrations(sequence fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(sequence, ".")
	if err != nil {
		return nil, fmt.Errorf("read migration sequence: %w", err)
	}
	var migrations []Migration
	seen := make(map[int64]string, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			return nil, fmt.Errorf("migration sequence contains directory %s", name)
		}
		match := migrationFile.FindStringSubmatch(name)
		if match == nil {
			return nil, fmt.Errorf("migration %s is not named NNNNN_lower_case.sql", name)
		}
		version, _ := strconv.ParseInt(match[1], 10, 64)
		if other, exists := seen[version]; exists {
			return nil, fmt.Errorf("migrations %s and %s share version %d", other, name, version)
		}
		seen[version] = name
		migrations = append(migrations, Migration{Version: version, File: name})
	}
	if len(migrations) == 0 {
		return nil, errors.New("migration sequence is empty")
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	for i, migration := range migrations {
		if want := int64(i + 1); migration.Version != want {
			return nil, fmt.Errorf("migration %s is numbered %d where the sequence expects %d",
				migration.File, migration.Version, want)
		}
	}
	return migrations, nil
}

// Directives reports whether a migration carries both goose annotations. A
// file without them applies as a single statement block or not at all.
func Directives(sequence fs.FS, name string) error {
	body, err := fs.ReadFile(sequence, name)
	if err != nil {
		return fmt.Errorf("read migration %s: %w", name, err)
	}
	text := strings.ToLower(string(body))
	for _, directive := range []string{"-- +goose up", "-- +goose down"} {
		if !strings.Contains(text, directive) {
			return fmt.Errorf("migration %s has no %q annotation", name, directive)
		}
	}
	return nil
}

// OpenFresh creates a new SQLite database below dir and applies the embedded
// sequence to it. The caller closes the returned handle.
func OpenFresh(ctx context.Context, dir string, sequence fs.FS) (*sql.DB, error) {
	path := filepath.Join(dir, "fresh.db")
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	dsn.RawQuery = url.Values{
		"_pragma": {"foreign_keys(1)", "busy_timeout(1000)"},
	}.Encode()
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, fmt.Errorf("open fresh database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, sequence,
		goose.WithDisableGlobalRegistry(true), goose.WithLogger(goose.NopLogger()))
	if err != nil {
		return nil, errors.Join(fmt.Errorf("create migration provider: %w", err), db.Close())
	}
	if _, err := provider.Up(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("apply migrations: %w", err), provider.Close())
	}
	return db, nil
}

// AppliedVersion reports the highest migration goose recorded as applied.
func AppliedVersion(ctx context.Context, db *sql.DB) (int64, error) {
	var version int64
	row := db.QueryRowContext(ctx, `SELECT MAX(version_id) FROM goose_db_version WHERE is_applied = 1`)
	if err := row.Scan(&version); err != nil {
		return 0, fmt.Errorf("read applied migration version: %w", err)
	}
	return version, nil
}

// TableColumns reports the tables the migrations produced and the columns of
// each, excluding SQLite's own tables and goose's bookkeeping.
func TableColumns(ctx context.Context, db *sql.DB) (map[string][]string, error) {
	tables, err := queryNames(ctx, db, `SELECT name FROM sqlite_schema
	    WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> 'goose_db_version'
	    ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	columns := make(map[string][]string, len(tables))
	for _, table := range tables {
		names, err := queryNames(ctx, db, `SELECT name FROM pragma_table_info(?) ORDER BY cid`, table)
		if err != nil {
			return nil, fmt.Errorf("read columns of %s: %w", table, err)
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("table %s reports no columns", table)
		}
		columns[table] = names
	}
	return columns, nil
}

// queryNames reads a one-column result in the order the query returns it.
func queryNames(ctx context.Context, db *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	var found []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, errors.Join(err, rows.Close())
		}
		found = append(found, name)
	}
	return found, errors.Join(rows.Err(), rows.Close())
}

// GeneratedQueries returns the SQL embedded in the generated bindings below
// dir, keyed by the query name the generator recorded with it.
func GeneratedQueries(dir string) (map[string]string, error) {
	sources, err := filepath.Glob(filepath.Join(dir, "*.sql.go"))
	if err != nil {
		return nil, fmt.Errorf("list generated queries: %w", err)
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no generated query bindings in %s", dir)
	}
	sort.Strings(sources)
	queries := make(map[string]string)
	positions := token.NewFileSet()
	for _, source := range sources {
		parsed, err := parser.ParseFile(positions, source, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", source, err)
		}
		for _, declaration := range parsed.Decls {
			group, ok := declaration.(*ast.GenDecl)
			if !ok || group.Tok != token.CONST {
				continue
			}
			for _, specification := range group.Specs {
				value, ok := specification.(*ast.ValueSpec)
				if !ok || len(value.Values) != 1 {
					continue
				}
				literal, ok := value.Values[0].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				text, err := strconv.Unquote(literal.Value)
				if err != nil {
					continue
				}
				name, ok := queryName(text)
				if !ok {
					continue
				}
				if _, exists := queries[name]; exists {
					return nil, fmt.Errorf("query %s is generated more than once in %s", name, dir)
				}
				queries[name] = text
			}
		}
	}
	if len(queries) == 0 {
		return nil, fmt.Errorf("no generated queries found in %s", dir)
	}
	return queries, nil
}

// CanonicalQueryNames returns the names declared in the SQL below dir.
func CanonicalQueryNames(dir string) ([]string, error) {
	sources, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		return nil, fmt.Errorf("list canonical queries: %w", err)
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no canonical queries in %s", dir)
	}
	sort.Strings(sources)
	var names []string
	for _, source := range sources {
		body, err := os.ReadFile(source)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", source, err)
		}
		for _, line := range strings.Split(string(body), "\n") {
			if name, ok := queryName(line); ok {
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no named queries in %s", dir)
	}
	sort.Strings(names)
	return names, nil
}

// queryName reads the "-- name: Something :kind" header the generator keeps
// with every query.
func queryName(text string) (string, bool) {
	line, _, _ := strings.Cut(text, "\n")
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), "-- name: ")
	if !ok {
		return "", false
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", false
	}
	return fields[0], true
}

// GeneratedStructs returns the field names of every generated model struct.
func GeneratedStructs(path string) (map[string][]string, error) {
	positions := token.NewFileSet()
	parsed, err := parser.ParseFile(positions, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	structs := make(map[string][]string)
	for _, declaration := range parsed.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.TYPE {
			continue
		}
		for _, specification := range group.Specs {
			definition, ok := specification.(*ast.TypeSpec)
			if !ok {
				continue
			}
			shape, ok := definition.Type.(*ast.StructType)
			if !ok {
				continue
			}
			var fields []string
			for _, field := range shape.Fields.List {
				if len(field.Names) == 0 {
					return nil, fmt.Errorf("struct %s in %s embeds a type", definition.Name.Name, path)
				}
				for _, name := range field.Names {
					fields = append(fields, name.Name)
				}
			}
			structs[definition.Name.Name] = fields
		}
	}
	if len(structs) == 0 {
		return nil, fmt.Errorf("no models declared in %s", path)
	}
	return structs, nil
}

// Signature folds a set of column or field names onto an order-independent
// key. The generator derives Go field names from column names by removing the
// separators and changing case, so both sides fold onto the same value.
func Signature(names []string) string {
	folded := make([]string, len(names))
	for i, name := range names {
		folded[i] = strings.ToLower(strings.ReplaceAll(name, "_", ""))
	}
	sort.Strings(folded)
	return strings.Join(folded, ",")
}

// GeneratorConfig holds the directories recorded in sqlc.yml.
type GeneratorConfig struct {
	Queries []string
	Schema  []string
	Out     []string
}

var generatorPath = regexp.MustCompile(`^\s*(queries|schema|out):\s*"([^"]+)"\s*$`)

// ReadGeneratorConfig collects the directories the SQL generator reads and
// writes, so tests can confirm they address the sequences the roles embed.
func ReadGeneratorConfig(path string) (GeneratorConfig, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return GeneratorConfig{}, fmt.Errorf("read %s: %w", path, err)
	}
	var config GeneratorConfig
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimRight(line, "\r")
		match := generatorPath.FindStringSubmatch(trimmed)
		if match == nil {
			if key := strings.TrimSpace(trimmed); strings.HasPrefix(key, "queries:") ||
				strings.HasPrefix(key, "schema:") || strings.HasPrefix(key, "out:") {
				return GeneratorConfig{}, fmt.Errorf("%s: %q is not a quoted directory", path, trimmed)
			}
			continue
		}
		switch match[1] {
		case "queries":
			config.Queries = append(config.Queries, match[2])
		case "schema":
			config.Schema = append(config.Schema, match[2])
		case "out":
			config.Out = append(config.Out, match[2])
		}
	}
	if len(config.Queries) == 0 || len(config.Schema) == 0 || len(config.Out) == 0 {
		return GeneratorConfig{}, fmt.Errorf("%s declares no query, schema or output directory", path)
	}
	return config, nil
}
