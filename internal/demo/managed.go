package demo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/netsec-ethz/debuglet/internal/readiness"
)

// A managed service and a foreground role differ only in who supervises the
// process: both are the same verified payload, reading a configuration this
// package generates, over a state directory this package owns. These exported
// entry points keep that single generator, so an installed unit can never be
// started against a configuration shape no foreground role was ever tested on.

// DispatcherConfiguration returns the generated dispatcher configuration for a
// database path. Callers may override the server ports before writing it.
func DispatcherConfiguration(version, database string) map[string]any {
	return dispatcherConfiguration(version, database)
}

// ExecutorConfiguration returns the generated executor configuration for one
// executor identity, database and dispatcher control record.
func ExecutorConfiguration(version, executorID, database string, dispatcher readiness.Record) map[string]any {
	return executorConfiguration(version, executorID, database, dispatcher)
}

// WriteConfig writes a generated configuration to an absent path, mode 0600.
func WriteConfig(path string, config map[string]any) error {
	return writeConfig(path, config)
}

// ValidateControlAddress accepts the literal-loopback host:port spelling the
// generated configurations use for the local control plane.
func ValidateControlAddress(address string) error {
	return validateAddress(address)
}

// RoleDatabase names the database file a role keeps in its state directory.
func RoleDatabase(dir string, role SchemaRole) string {
	return filepath.Join(dir, string(role)+".sqlite")
}

// PrepareRoleDatabase creates the role's database on first use and verifies an
// existing one against the schema versions this build serves. It never
// migrates: an unsupported database is reported with the action to take. It
// reports whether this call is the one that created the database. The caller
// owns the mode-0700 parent directory for the whole call.
//
// Whether creating is allowed is the bootstrap's own decision, not a guess
// made here: it requires a mode-0700 parent this administrator owns, which is
// a directory an installation has just made and never one it handed to the
// service account when it last finished. So an installation interrupted before
// its database existed can be completed by the next one, a finished directory
// can have nothing created in it, and no account that could replace the name
// in between has the directory to do it in.
func PrepareRoleDatabase(ctx context.Context, role SchemaRole, dir string) (path string, created bool, err error) {
	return productionDependencies().prepareRoleDatabase(ctx, role, dir)
}

// prepareRoleDatabase is that decision with the bootstrap and the schema check
// left as seams, so a foreground role and an installed unit make it once and
// reach the same database in the same states.
func (d dependencies) prepareRoleDatabase(ctx context.Context, role SchemaRole, dir string) (path string, created bool, err error) {
	path = RoleDatabase(dir, role)
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		bootstrap := d.bootstrap
		if bootstrap == nil {
			bootstrap = BootstrapFresh
		}
		if err := bootstrap(ctx, role, path); err != nil {
			return path, false, fmt.Errorf("bootstrap %s: %w", role, err)
		}
		created = true
	case err != nil:
		return path, false, err
	case !info.Mode().IsRegular():
		return path, false, errors.New("service database must be a regular file")
	default:
		// A second name for this database is a name no installation
		// made, and everything served through this one is served under
		// that one too.
		names, ok := FileNames(info)
		if !ok {
			return path, false, errors.New("this platform does not report how many names a file has, so the service database cannot be checked for a second one")
		}
		if names != 1 {
			return path, false, fmt.Errorf("service database is one of %d names for the same file; remove it before starting again", names)
		}
	}
	return path, created, d.verifySchema(ctx, role, path)
}
