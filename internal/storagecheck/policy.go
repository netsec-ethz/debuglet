// Package storagecheck states which database schemas a build can operate on
// and verifies a supplied SQLite file against that policy before a daemon
// serves requests or restores work. The check never migrates or repairs a
// database: an incompatible file is refused with the action its operator has
// to take. Upgrade applies the packaged migrations only when an operator runs
// it explicitly.
package storagecheck

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
)

// Role names one of the two databases a local environment keeps.
type Role string

const (
	Dispatcher Role = "dispatcher"
	Executor   Role = "executor"
)

// Minimum supported schema versions. Every version from the minimum up to the
// version the packaged migrations produce is served without a migration step.
// Raise the minimum together with a migration the daemon's queries depend on:
// an older database can then no longer answer them and must be refused instead
// of failing later during service.
const (
	MinimumDispatcherVersion int64 = 8
	MinimumExecutorVersion   int64 = 4
)

// Policy is the schema contract of one database for this build.
type Policy struct {
	Role Role
	// Minimum is the oldest schema version the daemon serves.
	Minimum int64
	// Current is the version the packaged migrations produce. A database
	// beyond it was written by a newer Debuglet.
	Current int64
	// Identity lists tables, with columns, that only this role's database
	// has and that it has carried since its first migration. They are
	// checked before the version, so a path pointing at the other role's
	// database is reported as the wrong file rather than as a wrong version.
	Identity map[string][]string
	// Tables lists the tables the supported schema must contain, with the
	// columns that distinguish a completely applied schema from one whose
	// migrations stopped halfway.
	Tables map[string][]string
}

// PolicyFor returns the schema policy of the given role.
func PolicyFor(role Role) (Policy, error) {
	switch role {
	case Dispatcher:
		current, err := packagedVersion(dispatcherdb.MigrationFS())
		if err != nil {
			return Policy{}, err
		}
		return Policy{Role: role, Minimum: MinimumDispatcherVersion, Current: current, Identity: map[string][]string{
			"transaction_states": nil,
			"transactions":       nil,
		}, Tables: map[string][]string{
			"debuglets":                  {"uuid", "ceil_bw", "transaction_id", "order_id", "dispatcher_incarnation", "session_id"},
			"debuglet_logs":              {"debuglet_id", "output"},
			"debuglet_order":             {"transaction_id", "state", "refund_address", "debuglet_id"},
			"debuglet_users":             {"debuglet_id", "user_id"},
			"earnings":                   {"executor_id", "currency", "sui_wallet_address"},
			"executor_enrollments":       {"executor_id", "fingerprint"},
			"executor_enrollment_tokens": {"selector", "executor_id", "secret_hash", "expires_at"},
			"sessions":                   {"selector", "verifier_hash", "csrf_hash", "user_id", "expires_at", "revoked"},
			"transaction_users":          {"transaction_id", "user_id"},
			"transactions":               {"currency", "status"},
			"user_credentials":           {"user_id", "kind", "selector", "secret_hash"},
			"users":                      {"uuid", "name", "role"},
		}}, nil
	case Executor:
		current, err := packagedVersion(executordb.MigrationFS())
		if err != nil {
			return Policy{}, err
		}
		return Policy{Role: role, Minimum: MinimumExecutorVersion, Current: current, Identity: map[string][]string{
			"debuglets": {"wasm"},
		}, Tables: map[string][]string{
			"debuglets":      {"uuid", "wasm", "transaction_id", "dispatcher_incarnation", "session_id"},
			"debuglet_logs":  {"debuglet_id", "output"},
			"debuglet_exits": {"debuglet_id", "dispatcher_incarnation", "session_id", "exit_code", "attempts", "rejected"},
		}}, nil
	default:
		return Policy{}, fmt.Errorf("unknown database role %q", role)
	}
}

// Supports reports whether a schema version is inside the supported range.
func (p Policy) Supports(version int64) bool {
	return version >= p.Minimum && version <= p.Current
}

// packagedVersion reports the schema version the packaged migrations produce.
func packagedVersion(migrations fs.FS) (int64, error) {
	entries, err := fs.ReadDir(migrations, ".")
	if err != nil {
		return 0, fmt.Errorf("read packaged migrations: %w", err)
	}
	var current int64
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		digits, _, found := strings.Cut(name, "_")
		if !found {
			continue
		}
		version, err := strconv.ParseInt(digits, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("packaged migration %q has no version prefix", name)
		}
		if version > current {
			current = version
		}
	}
	if current == 0 {
		return 0, fmt.Errorf("packaged migrations contain no schema version")
	}
	return current, nil
}
