// Package service installs a verified Debuglet role payload as a service the
// host's service manager supervises. It owns one coherent contract: exactly
// one unit, one persistent state directory, one service account and one
// readiness record per installed role instance. It starts, stops and inspects
// only the units it wrote, and it never migrates a database, replays
// interrupted work or touches a unit it does not own.
package service

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/internal/demo"
)

const (
	// ReadyTimeout bounds the observation of a published readiness record
	// after the service manager reports the unit started. It matches the
	// startup bound of the foreground role commands.
	ReadyTimeout = 30 * time.Second
	// StopBudget is the unit's TimeoutStopSec: the time the service manager
	// gives the daemon to revoke admission, join its owned local work and
	// exit before it is killed. It has to exceed the daemon's own bounded
	// local join (scheduler.CleanupTimeout per session) with room for the
	// operating system to reap the process group.
	StopBudget = 45 * time.Second
	// StopObservation is how long a stop is waited for by default. It
	// exceeds StopBudget, because a daemon that uses its whole budget has
	// not failed: reporting it incomplete would be this command's
	// impatience rather than the daemon's.
	StopObservation = StopBudget + 30*time.Second
	// DrainBudget is the default whole-operation bound for a drain. It
	// exceeds the stop observation so a drain reports what the service
	// manager actually did rather than its own impatience.
	DrainBudget = StopObservation + 15*time.Second
	// pollEvery is the pause between readiness or unit-state observations.
	pollEvery = 100 * time.Millisecond
	// maintenanceLimit bounds a read of the dispatcher maintenance switch,
	// and recordLimit a read of an installed service record.
	maintenanceLimit = 4 << 10
	recordLimit      = 4 << 10
)

// Profile is the complete description of one managed role instance. Every
// path is absolute inside Root, so a staging root and the real root differ in
// exactly one value and nothing else about the contract changes.
type Profile struct {
	Role demo.SchemaRole `json:"role"`
	Name string          `json:"name"`
	// Root is the filesystem prefix every path below is derived from.
	Root string `json:"root"`
	// Unit is the service-manager unit this instance owns.
	Unit string `json:"unit"`
	// User and Group are the service account the daemon runs as. The
	// account has to exist already: installing a service never creates,
	// modifies or removes an account.
	User  string `json:"user"`
	Group string `json:"group"`
	// Version and SourceSHA identify the verified installed payload this
	// unit starts, and PayloadRoot is that payload's directory.
	Version     string `json:"version"`
	SourceSHA   string `json:"source_sha"`
	PayloadRoot string `json:"payload_root"`
	// Executable is the daemon inside PayloadRoot the unit starts.
	Executable string `json:"executable"`
	// StateDir persists the database, the role identity and the generated
	// configuration across restarts; RuntimeDir holds only the readiness
	// record and is recreated for every start.
	StateDir   string `json:"state_dir"`
	RuntimeDir string `json:"runtime_dir"`
	UnitPath   string `json:"unit_path"`
	// ExecutorID is the persistent identity of a managed executor. A
	// restart keeps it; it is empty for a dispatcher.
	ExecutorID string `json:"executor_id,omitempty"`
	// HTTPPort and GRPCPort are the dispatcher's loopback listeners.
	HTTPPort int `json:"http_port,omitempty"`
	GRPCPort int `json:"grpc_port,omitempty"`
	// DispatcherGRPC and DispatcherHTTP are the control addresses a managed
	// executor connects to.
	DispatcherGRPC string `json:"dispatcher_grpc,omitempty"`
	DispatcherHTTP string `json:"dispatcher_http,omitempty"`
	// MaintenanceFile is the dispatcher's admission switch. Its presence
	// stops submission admission; it is empty for an executor.
	MaintenanceFile string `json:"maintenance_file,omitempty"`
	// ConfigPath, DatabasePath and ReadyFile are the generated
	// configuration, the served database and the readiness record.
	ConfigPath   string `json:"config_path"`
	DatabasePath string `json:"database_path"`
	ReadyFile    string `json:"ready_file"`
	// StopBudgetSeconds is the unit's stop timeout, recorded so an operator
	// reading the record knows the budget without parsing the unit.
	StopBudgetSeconds int `json:"stop_budget_seconds"`
}

// Request is what an operator asks for. Everything else in a Profile is
// derived, so two installs of the same request produce the same unit.
type Request struct {
	Role demo.SchemaRole
	Name string
	// Root prefixes every managed path. Empty means the real root.
	Root string
	// User and Group default to DefaultAccount.
	User, Group string
	// HTTPPort and GRPCPort are required for a dispatcher; a managed
	// service needs stable ports, so 0 is refused.
	HTTPPort, GRPCPort int
	// DispatcherGRPC and DispatcherHTTP are required for an executor.
	DispatcherGRPC, DispatcherHTTP string
}

// DefaultAccount is the unprivileged service account the generated units use.
// The Ansible deployment provisions the same name.
const DefaultAccount = "debuglet"

// Default dispatcher ports. They match the foreground dispatcher role, so an
// executor pointed at a managed dispatcher needs no extra configuration.
const (
	DefaultHTTPPort = 9000
	DefaultGRPCPort = 9001
)

// UnitName returns the unit one role instance owns. A separate unit per
// instance keeps every operation on exactly one service: an install, a stop or
// an uninstall of one role never names, reloads or restarts another.
func UnitName(role demo.SchemaRole, name string) string {
	return fmt.Sprintf("debuglet-%s-%s.service", role, name)
}

// Resolve derives the complete profile of a request against a verified
// payload. It performs no I/O beyond the assets the caller already verified.
func Resolve(request Request, assets demo.Assets) (Profile, error) {
	p, err := DerivePaths(request.Root, request.Role, request.Name)
	if err != nil {
		return p, err
	}
	user, group := request.User, request.Group
	if user == "" {
		user = DefaultAccount
	}
	if group == "" {
		group = user
	}
	if err := validAccountName(user); err != nil {
		return p, fmt.Errorf("service user: %w", err)
	}
	if err := validAccountName(group); err != nil {
		return p, fmt.Errorf("service group: %w", err)
	}
	if assets.Manifest.Version == "" || assets.Root == "" {
		return p, errors.New("managed services require a verified installed payload")
	}
	if err := systemPayload(assets.Root); err != nil {
		return p, err
	}
	p.User, p.Group = user, group
	p.Version, p.SourceSHA, p.PayloadRoot = assets.Manifest.Version, assets.Manifest.SourceSHA, assets.Root
	if request.Role == demo.DispatcherSchema {
		p.Executable = assets.Dispatcher
		p.HTTPPort, p.GRPCPort = request.HTTPPort, request.GRPCPort
		if p.HTTPPort == 0 {
			p.HTTPPort = DefaultHTTPPort
		}
		if p.GRPCPort == 0 {
			p.GRPCPort = DefaultGRPCPort
		}
		if !validPort(p.HTTPPort) || !validPort(p.GRPCPort) || p.HTTPPort == p.GRPCPort {
			return p, errors.New("managed dispatcher ports must be different and between 1 and 65535")
		}
	} else {
		p.Executable = assets.Executor
		p.DispatcherGRPC, p.DispatcherHTTP = request.DispatcherGRPC, request.DispatcherHTTP
		if p.DispatcherGRPC == "" {
			p.DispatcherGRPC = fmt.Sprintf("127.0.0.1:%d", DefaultGRPCPort)
		}
		if p.DispatcherHTTP == "" {
			p.DispatcherHTTP = fmt.Sprintf("127.0.0.1:%d", DefaultHTTPPort)
		}
		// The managed profile disables transport security, so its control
		// plane stays on one host's loopback interface exactly like the
		// foreground roles. A remote dispatcher needs a configuration this
		// generator does not write.
		if err := demo.ValidateControlAddress(p.DispatcherGRPC); err != nil {
			return p, fmt.Errorf("dispatcher control address: %w", err)
		}
		if err := demo.ValidateControlAddress(p.DispatcherHTTP); err != nil {
			return p, fmt.Errorf("dispatcher HTTP address: %w", err)
		}
	}
	return p, nil
}

// UnitDirectory is where generated units are written below a root.
func UnitDirectory(root string) string {
	if root == "" {
		root = string(filepath.Separator)
	}
	return filepath.Join(root, "etc", "systemd", "system")
}

// DerivePaths computes every path of one role instance from its root, role and
// name alone. Nothing it returns is read from disk, so a later operation can
// check an installed record against it: the record says which version and
// account an instance was installed with, and it is never allowed to say where
// the instance lives.
func DerivePaths(root string, role demo.SchemaRole, name string) (Profile, error) {
	var p Profile
	if role != demo.DispatcherSchema && role != demo.ExecutorSchema {
		return p, errors.New("managed services support the dispatcher and executor roles only")
	}
	if err := connections.ValidateName(name); err != nil {
		return p, err
	}
	if root == "" {
		root = string(filepath.Separator)
	}
	if !filepath.IsAbs(root) {
		return p, errors.New("managed service root must be absolute")
	}
	root = filepath.Clean(root)
	p = Profile{
		Role: role, Name: name, Root: root, Unit: UnitName(role, name),
		StateDir:          StateDirectory(root, role, name),
		RuntimeDir:        filepath.Join(root, "run", "debuglet", string(role)+"s", name),
		StopBudgetSeconds: int(StopBudget / time.Second),
	}
	p.UnitPath = filepath.Join(UnitDirectory(root), p.Unit)
	p.ConfigPath = filepath.Join(p.StateDir, "service.toml")
	p.DatabasePath = demo.RoleDatabase(p.StateDir, role)
	p.ReadyFile = filepath.Join(p.RuntimeDir, "ready.json")
	if role == demo.DispatcherSchema {
		p.MaintenanceFile = filepath.Join(AdministrationDirectory(root), fmt.Sprintf("%s-%s.maintenance", role, name))
	}
	return p, nil
}

// SamePaths reports whether two profiles describe the same instance in the same
// places. Everything an operation acts on is compared: a record that disagrees
// about any of them is not this instance's record.
func (p Profile) SamePaths(other Profile) bool {
	return p.Role == other.Role && p.Name == other.Name && p.Root == other.Root &&
		p.Unit == other.Unit && p.UnitPath == other.UnitPath &&
		p.StateDir == other.StateDir && p.RuntimeDir == other.RuntimeDir &&
		p.ReadyFile == other.ReadyFile && p.ConfigPath == other.ConfigPath &&
		p.DatabasePath == other.DatabasePath && p.MaintenanceFile == other.MaintenanceFile
}

// AdministrationDirectory holds what only an administrator may write: the
// installed record of each instance and each dispatcher's maintenance switch.
// They are deliberately outside the state directory, because that directory is
// handed to the service account, and an account that can write its own
// directory can replace anything in it. A daemon must not be able to tell a
// later privileged command where to look, what to remove or what to chown.
func AdministrationDirectory(root string) string {
	if root == "" {
		root = string(filepath.Separator)
	}
	return filepath.Join(root, "etc", "debuglet", "services")
}

// RecordPath is the installed record of one instance.
func RecordPath(root string, role demo.SchemaRole, name string) string {
	return filepath.Join(AdministrationDirectory(root), fmt.Sprintf("%s-%s.json", role, name))
}

// StateDirectory is where a role instance keeps its persistent state. It holds
// only what the daemon itself serves: its database, its role identity and its
// generated configuration.
func StateDirectory(root string, role demo.SchemaRole, name string) string {
	if root == "" {
		root = string(filepath.Separator)
	}
	return filepath.Join(root, "var", "lib", "debuglet", string(role)+"s", name)
}

func validPort(port int) bool { return port >= 1 && port <= 65535 }

// systemPayload refuses a payload the generated unit could never execute. The
// unit hides home directories from the service, which is what makes a system
// service independent of any user's account, so a package installed under one
// has to be refused here rather than fail as an unexplained exec error at the
// first start.
func systemPayload(root string) error {
	for _, home := range []string{"/home", "/root", "/run/user"} {
		if root == home || strings.HasPrefix(root, home+"/") {
			return fmt.Errorf("a managed service runs with home directories hidden, so it can never start the payload installed at %s; install the package under a system prefix such as /usr/local", root)
		}
	}
	return nil
}

// validAccountName accepts the portable account spelling. It is deliberately
// stricter than the host's: an account name reaches a unit file, where a stray
// space or newline would change the meaning of a directive.
func validAccountName(name string) error {
	if len(name) == 0 || len(name) > 32 {
		return errors.New("name must be 1-32 characters")
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
		case r == '-' && i > 0:
		default:
			return errors.New("name must be lowercase letters, digits, underscores or hyphens")
		}
	}
	if strings.HasPrefix(name, "-") {
		return errors.New("name must not start with a hyphen")
	}
	return nil
}
