package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/readiness"
)

// Account is the resolved service account a unit runs as.
type Account struct{ UID, GID int }

// Options configure an installer. The three function fields are the only
// seams: they exist so the file operations, the generated unit and the
// readiness observation can be exercised without a live service manager, a
// provisioned account or root privileges.
type Options struct {
	// Root prefixes every managed path; empty means the real root.
	Root string
	// Manager is the service manager to drive. Required.
	Manager Manager
	// LookupAccount resolves the service account. nil uses the host's user
	// database.
	LookupAccount func(user, group string) (Account, error)
	// Chown applies the service account to one already-open managed file.
	// nil uses the operating system's fchown on the descriptor itself.
	Chown func(file *os.File, uid, gid int) error
	// ReadyTimeout bounds the readiness observation. Zero uses ReadyTimeout.
	ReadyTimeout time.Duration
	// StopTimeout bounds a stop and the verification that it finished. Zero
	// uses StopObservation, which allows for a daemon that uses its whole
	// shutdown budget.
	StopTimeout time.Duration
}

// Installer performs the managed-service operations of one root.
type Installer struct {
	root         string
	manager      Manager
	lookup       func(user, group string) (Account, error)
	chown        func(file *os.File, uid, gid int) error
	readyTimeout time.Duration
	stopTimeout  time.Duration
}

// New returns an installer for the supplied options.
func New(options Options) (*Installer, error) {
	if options.Manager == nil {
		return nil, errors.New("managed services need a service manager")
	}
	i := &Installer{
		root: options.Root, manager: options.Manager,
		lookup: options.LookupAccount, chown: options.Chown,
		readyTimeout: options.ReadyTimeout, stopTimeout: options.StopTimeout,
	}
	if i.lookup == nil {
		i.lookup = lookupSystemAccount
	}
	if i.chown == nil {
		// fchown on the open descriptor, never chown on a path: the file
		// is the one that was opened, so nothing that replaces the name
		// afterwards can redirect the ownership at a host file.
		i.chown = func(file *os.File, uid, gid int) error { return file.Chown(uid, gid) }
	}
	if i.readyTimeout <= 0 {
		i.readyTimeout = ReadyTimeout
	}
	if i.stopTimeout <= 0 {
		i.stopTimeout = StopObservation
	}
	return i, nil
}

// Report is what one managed-service operation observed. Every field is either
// something this command did or something it read back; nothing is inferred
// from a manager call having returned successfully.
type Report struct {
	Operation string `json:"operation"`
	Role      string `json:"role"`
	Name      string `json:"name"`
	Unit      string `json:"unit"`
	Version   string `json:"version"`
	// State is the observed outcome: installed, ready, started, stopped,
	// uninstalled, not-installed, or incomplete.
	State string `json:"state"`
	// Ready reports an observed readiness record published by the running
	// process, never the manager's belief that a process exists.
	Ready bool `json:"ready"`
	// Joined reports a daemon that finished its own shutdown. It is the
	// only thing that permits deleting, upgrading or rebuilding state.
	Joined     bool   `json:"joined,omitempty"`
	Enabled    bool   `json:"enabled"`
	Active     string `json:"active,omitempty"`
	MainPID    int    `json:"main_pid,omitempty"`
	ExecutorID string `json:"executor_id,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	StateDir   string `json:"state_dir,omitempty"`
	UnitPath   string `json:"unit_path,omitempty"`
	// Changed lists what this operation actually altered on disk or in the
	// service manager. A repeated identical install changes nothing.
	Changed []string `json:"changed,omitempty"`
	// RestartRequired reports a running unit whose unit file or generated
	// configuration changed. Installing never restarts a running daemon.
	RestartRequired bool `json:"restart_required,omitempty"`
	// Note carries the one thing an operator has to know that the fields
	// above do not already say.
	Note string `json:"note,omitempty"`
}

// Install writes, or brings up to date, one managed role instance from a
// verified payload and, when start is true, starts it and observes its
// readiness record. It is repeatable: running it again with the same payload
// and request changes nothing and reports nothing changed.
//
// It never restarts a running daemon, never migrates a database, never creates
// an account and never touches a unit other than this instance's own.
func (i *Installer) Install(ctx context.Context, request Request, assets demo.Assets, start, enable bool) (Report, error) {
	request.Root = i.root
	p, err := Resolve(request, assets)
	if err != nil {
		return Report{Operation: "install"}, err
	}
	report := Report{Operation: "install", Role: string(p.Role), Name: p.Name, Unit: p.Unit,
		Version: p.Version, StateDir: p.StateDir, UnitPath: p.UnitPath, State: "installed"}
	account, err := i.lookup(p.User, p.Group)
	if err != nil {
		return report, err
	}
	// An existing installation of another version keeps its databases: this
	// build never upgrades state in place, so the operator is told which
	// version owns the directory instead of silently adopting it.
	if existing, err := ReadRecord(i.root, p.Role, p.Name); err == nil {
		if existing.Version != p.Version || existing.SourceSHA != p.SourceSHA {
			return report, fmt.Errorf("%s %s is installed from version %s (%s); reinstall that version, or install this one under a different --name",
				existing.Role, existing.Name, existing.Version, existing.SourceSHA)
		}
		if !existing.SamePaths(p) {
			return report, fmt.Errorf("the record at %s does not describe this instance", RecordPath(i.root, p.Role, p.Name))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return report, err
	} else {
		// The record is written before the unit, so a unit without a record
		// is not an interrupted managed installation.
		if _, err := os.Lstat(p.UnitPath); err == nil {
			return report, fmt.Errorf("refusing to replace unmanaged unit %s", p.UnitPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return report, err
		}
	}
	if err := i.prepareState(ctx, &p, &report, account); err != nil {
		return report, err
	}
	report.ExecutorID = p.ExecutorID
	unitChanged, err := i.writeUnit(p)
	if err != nil {
		return report, err
	}
	if unitChanged {
		report.Changed = append(report.Changed, "unit")
	}
	state, err := i.manager.State(ctx, p.Unit)
	if err != nil {
		return report, err
	}
	// Reload whenever the manager does not know this unit, not only when
	// its bytes changed: a reload that failed the last time left the unit
	// unknown, and an install that skipped it would never try again.
	if unitChanged || !state.Loaded {
		if err := i.manager.Reload(ctx); err != nil {
			return report, err
		}
		if state, err = i.manager.State(ctx, p.Unit); err != nil {
			return report, err
		}
	}
	if enable && !state.Enabled {
		if err := i.manager.Enable(ctx, p.Unit); err != nil {
			return report, err
		}
		report.Changed = append(report.Changed, "enabled")
	}
	if state.Running() && len(report.Changed) > 0 {
		// Rewriting a unit or a configuration cannot interrupt a running
		// measurement. Applying it is an operator decision, taken after a
		// drain, not a side effect of reinstalling.
		report.RestartRequired = true
		report.Note = "the running daemon still uses its previous unit and configuration; drain and start it again to apply the change"
	}
	if start && !state.Running() {
		if err := i.manager.Start(ctx, p.Unit); err != nil {
			return report, err
		}
		report.Changed = append(report.Changed, "started")
	}
	return i.finishReport(ctx, p, report, start)
}

// finishReport observes the actual unit state and, when the caller asked for a
// started service, the readiness record the daemon publishes for itself.
func (i *Installer) finishReport(ctx context.Context, p Profile, report Report, wantReady bool) (Report, error) {
	state, err := i.manager.State(ctx, p.Unit)
	if err != nil {
		return report, err
	}
	report.Enabled, report.Active, report.MainPID = state.Enabled, state.Active, state.MainPID
	if !wantReady {
		return report, nil
	}
	record, err := i.observeReady(ctx, p, state)
	if err != nil {
		report.State = "incomplete"
		return report, fmt.Errorf("%s did not publish readiness: %w", p.Unit, err)
	}
	report.Ready, report.State, report.MainPID = true, "ready", record.PID
	if p.Role == demo.DispatcherSchema {
		report.Endpoint = "http://" + record.HTTPAddr
	}
	return report, nil
}

// observeReady waits for the readiness record the daemon publishes once it has
// actually reached its ready point, and accepts it only from the process the
// manager reports as this unit's main process. A unit that leaves the active
// state ends the wait immediately: there is nothing left to become ready.
func (i *Installer) observeReady(ctx context.Context, p Profile, state UnitState) (readiness.Record, error) {
	ctx, cancel := context.WithTimeout(ctx, i.readyTimeout)
	defer cancel()
	var last error
	for {
		if !state.Running() {
			return readiness.Record{}, fmt.Errorf("unit is %s (%s) with no readiness record", state.Active, state.Sub)
		}
		if state.MainPID > 0 {
			record, err := demo.ReadReadyRecord(p.ReadyFile, state.MainPID, p.ExecutorID)
			if err == nil {
				return record, nil
			}
			last = err
			// A record naming another identity is never this instance's.
			if record.ExecutorID != "" && p.ExecutorID != "" && record.ExecutorID != p.ExecutorID {
				return record, fmt.Errorf("readiness record belongs to executor %s", record.ExecutorID)
			}
		} else {
			last = errors.New("the service manager reports no main process")
		}
		if err := pause(ctx); err != nil {
			if last == nil {
				last = err
			}
			return readiness.Record{}, fmt.Errorf("%s: %w", ctx.Err(), last)
		}
		var err error
		if state, err = i.manager.State(ctx, p.Unit); err != nil {
			return readiness.Record{}, err
		}
	}
}

// prepareState creates and owns the persistent role directory: the database,
// the role identity and the generated configuration. The directory is created
// and populated by the invoking administrator and handed to the service
// account as the last step, so the bootstrap never runs in a directory another
// account could already write to.
func (i *Installer) prepareState(ctx context.Context, p *Profile, report *Report, account Account) error {
	if err := os.MkdirAll(filepath.Dir(p.StateDir), 0755); err != nil {
		return err
	}
	if err := os.Mkdir(p.StateDir, 0700); err == nil {
		report.Changed = append(report.Changed, "state directory")
	} else if !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := os.Lstat(p.StateDir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("%s must be a real mode-0700 directory", p.StateDir)
	}
	// The role identity is established before the database exists: a
	// directory that already holds a database but no identity belongs to
	// something else, and adopting it would take ownership of state this
	// installation never created.
	state, err := demo.EnsureRoleState(p.StateDir, p.Role, demo.Manifest{Version: p.Version, SourceSHA: p.SourceSHA})
	if err != nil {
		return err
	}
	_, bootstrapped, err := demo.PrepareRoleDatabase(ctx, p.Role, p.StateDir)
	if err != nil {
		return err
	}
	if bootstrapped {
		report.Changed = append(report.Changed, "database")
	}
	if p.Role == demo.ExecutorSchema {
		p.ExecutorID = state.Identity
	}
	changed, err := i.writeConfiguration(*p)
	if err != nil {
		return err
	}
	if changed {
		report.Changed = append(report.Changed, "configuration")
	}
	if err := i.own(p.StateDir, account); err != nil {
		return err
	}
	// The record is written last and outside the account's directory: it is
	// the administrator's statement about this instance, not the daemon's.
	return writeRecord(*p)
}

// writeConfiguration regenerates the daemon configuration from the same
// generator the foreground roles use and reports whether its bytes changed.
func (i *Installer) writeConfiguration(p Profile) (bool, error) {
	var config map[string]any
	if p.Role == demo.DispatcherSchema {
		config = demo.DispatcherConfiguration(p.Version, p.DatabasePath)
		server := config["server"].(map[string]any)
		server["http_port"], server["grpc_port"] = p.HTTPPort, p.GRPCPort
		// A managed dispatcher is a system service that the host starts at
		// boot and that every account on that host can reach on loopback.
		// The credential-free operator bypass belongs to a foreground
		// environment its own operator owns end to end, so it is switched
		// off here explicitly rather than inherited from whatever the
		// shared generator emits.
		server["local_development"] = false
	} else {
		config = demo.ExecutorConfiguration(p.Version, p.ExecutorID, p.DatabasePath,
			readiness.Record{GRPCAddr: p.DispatcherGRPC, HTTPAddr: p.DispatcherHTTP})
		// A managed executor derives its TESLA horizon from its delay, like
		// every independently started role.
		config["tesla"].(map[string]any)["chain_length"] = 0
		// It runs on a host that has other services on it, and not in the
		// loopback environment the generator describes, so the permission to
		// measure against targets on this same machine is switched off here
		// explicitly: a debuglet would otherwise reach whatever else the
		// host serves on loopback and on the internal ranges.
		config["network"].(map[string]any)["policy"].(map[string]any)["local_targets"] = false
	}
	temporary := filepath.Join(p.StateDir, ".service.toml.new")
	if err := os.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if err := demo.WriteConfig(temporary, config); err != nil {
		return false, err
	}
	defer os.Remove(temporary)
	if same, err := sameContent(p.ConfigPath, temporary); err != nil {
		return false, err
	} else if same {
		return false, nil
	}
	return true, os.Rename(temporary, p.ConfigPath)
}

// writeUnit publishes the generated unit and reports whether it changed.
func (i *Installer) writeUnit(p Profile) (bool, error) {
	text, err := Unit(p)
	if err != nil {
		return false, err
	}
	directory := filepath.Dir(p.UnitPath)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return false, err
	}
	if existing, err := os.ReadFile(p.UnitPath); err == nil && string(existing) == text {
		return false, nil
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	temporary, err := os.CreateTemp(directory, ".debuglet-unit-")
	if err != nil {
		return false, err
	}
	defer os.Remove(temporary.Name())
	_, writeErr := temporary.WriteString(text)
	if err := errors.Join(writeErr, temporary.Chmod(0644), temporary.Close()); err != nil {
		return false, err
	}
	return true, os.Rename(temporary.Name(), p.UnitPath)
}

// own hands the whole state directory to the service account: mode 0700 for
// the directory and 0600 for the state it holds, so no other account on the
// host can read a database, a configuration or a role identity.
//
// The account owns this directory between installations and can create,
// replace and unlink anything in it while this runs, so every entry is read
// twice and the two readings must agree: what the name was before it was
// opened, and what the descriptor it was opened on turns out to be. The walk
// is confined to a descriptor on the directory: every entry is opened relative
// to it, ownership and mode are applied to the open file rather than to its
// name, and the descent uses the same confined resolution. An entry replaced
// between the two readings is refused, an entry replaced after them reaches
// nothing outside this directory, and a name that resolves outside it is
// refused rather than followed.
//
// Only regular files and directories are owned, and only a file this directory
// alone names: anything else, a symbolic link or a second name for a file
// elsewhere on the host, is refused with its path, because it is not state
// this installation created and ownership given to it would be given outside
// this directory.
func (i *Installer) own(dir string, account Account) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err != nil {
			return fmt.Errorf("hand %s to the service account: %w", path, err)
		}
		// A symbolic link is refused before anything is opened, wherever
		// it points: it is not state this installation created, and the
		// entry an operator has to remove is the link, not its target.
		link, err := root.Lstat(name)
		if err != nil {
			return fmt.Errorf("hand %s to the service account: %w", path, err)
		}
		if link.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("refusing to hand %s to the service account: %s is neither a regular file nor a directory; remove it before installing again", path, link.Mode().Type())
		}
		// Opening never waits: a named pipe left here would otherwise stop
		// this install until somebody opened the other end of it.
		file, err := root.OpenFile(name, os.O_RDONLY|demo.OpenWithoutWaiting, 0)
		if err != nil {
			return fmt.Errorf("hand %s to the service account: %w", path, err)
		}
		defer file.Close()
		// What this is, is read from the descriptor and not from the
		// directory entry: the entry says what the name meant when the
		// directory was read, and the account may have changed it since.
		info, err := file.Stat()
		if err != nil {
			return fmt.Errorf("hand %s to the service account: %w", path, err)
		}
		// The two readings of the name must be the same file. An account
		// that swapped the entry in between handed this walk something
		// the directory listing never described.
		if !os.SameFile(link, info) {
			return fmt.Errorf("refusing to hand %s to the service account: it was replaced while it was being read; remove it before installing again", path)
		}
		mode := fs.FileMode(0600)
		switch {
		case info.IsDir():
			mode = 0700
		case info.Mode().IsRegular():
			// A second name for this file is a name this installation
			// never made, and ownership given here is given to that
			// name as well, wherever on the host it is.
			names, ok := demo.FileNames(info)
			if !ok {
				return fmt.Errorf("refusing to hand %s to the service account: this platform does not report how many names a file has", path)
			}
			if names != 1 {
				return fmt.Errorf("refusing to hand %s to the service account: it is one of %d names for the same file; remove it before installing again", path, names)
			}
		default:
			return fmt.Errorf("refusing to hand %s to the service account: %s is neither a regular file nor a directory; remove it before installing again", path, info.Mode().Type())
		}
		if err := i.chown(file, account.UID, account.GID); err != nil {
			return fmt.Errorf("hand %s to the service account: %w", path, err)
		}
		if err := file.Chmod(mode); err != nil {
			return fmt.Errorf("hand %s to the service account: %w", path, err)
		}
		return nil
	})
}

// Start starts an installed instance and observes its readiness record.
func (i *Installer) Start(ctx context.Context, role demo.SchemaRole, name string) (Report, error) {
	p, report, err := i.load(ctx, "start", role, name)
	if err != nil {
		return report, err
	}
	state, err := i.manager.State(ctx, p.Unit)
	if err != nil {
		return report, err
	}
	if !state.Running() {
		if err := i.manager.Start(ctx, p.Unit); err != nil {
			return report, err
		}
		report.Changed = append(report.Changed, "started")
	}
	report.State = "started"
	return i.finishReport(ctx, p, report, true)
}

// Stop stops an installed instance within the stop budget and verifies that
// the manager actually reports it down. It leaves the unit enabled: stopping
// for a moment is not the same decision as removing a node from service, which
// is what Drain is for.
func (i *Installer) Stop(ctx context.Context, role demo.SchemaRole, name string) (Report, error) {
	p, report, err := i.load(ctx, "stop", role, name)
	if err != nil {
		return report, err
	}
	stopped, joined, err := i.stopAndVerify(ctx, p, &report)
	if err != nil {
		return report, err
	}
	report.Joined = joined
	if !stopped {
		report.State = "incomplete"
		return report, errors.New("the service manager has not reported this unit stopped; its process may still own the database")
	}
	report.State = "stopped"
	if !joined {
		report.State = "incomplete"
		return report, errors.New("the unit is down but its daemon did not complete its own shutdown; nothing may be deleted, upgraded or rebuilt on the strength of it")
	}
	return report, nil
}

// stopAndVerify asks the manager to stop the unit and then reads back how the
// daemon actually left. It reports a join only for a daemon that finished on
// its own terms; a unit that is merely down, because it was killed at its stop
// timeout or exited with a failure, is not a join and nothing downstream may
// treat it as one.
func (i *Installer) stopAndVerify(ctx context.Context, p Profile, report *Report) (stopped, joined bool, err error) {
	stopCtx, cancel := context.WithTimeout(ctx, i.stopTimeout)
	defer cancel()
	state, err := i.manager.State(stopCtx, p.Unit)
	if err != nil {
		return false, false, err
	}
	asked := false
	if !state.Stopped() {
		if err := i.manager.Stop(stopCtx, p.Unit); err != nil {
			return false, false, err
		}
		asked = true
	}
	for {
		if state, err = i.manager.State(ctx, p.Unit); err != nil {
			return false, false, err
		}
		report.Active, report.MainPID, report.Enabled = state.Active, state.MainPID, state.Enabled
		if state.Joined() {
			if asked {
				report.Changed = append(report.Changed, "stopped")
			}
			return true, true, nil
		}
		if state.Stopped() {
			// Down, but not finished: the manager recorded how it ended.
			report.Note = fmt.Sprintf("the unit is %s after %s (exit status %d), so its daemon did not complete its own shutdown; start and stop it again, and inspect its journal, before deciding that its state can be discarded",
				state.Active, unitResult(state.Result), state.ExecMainStatus)
			if asked {
				report.Changed = append(report.Changed, "stopped")
			}
			return true, false, nil
		}
		if err := pause(stopCtx); err != nil {
			return false, false, nil
		}
	}
}

// unitResult names how a unit ended in an operator's terms.
func unitResult(result string) string {
	switch result {
	case "":
		return "an unreported result"
	case "timeout":
		return "being killed at its stop timeout"
	case "exit-code":
		return "a failing exit status"
	case "signal", "core-dump":
		return "being killed by a signal"
	default:
		return "the result " + result
	}
}

// Status reports the installed contract and what the manager and the readiness
// record currently say about it, without changing anything.
func (i *Installer) Status(ctx context.Context, role demo.SchemaRole, name string) (Report, error) {
	p, report, err := i.load(ctx, "status", role, name)
	if err != nil {
		return report, err
	}
	state, err := i.manager.State(ctx, p.Unit)
	if err != nil {
		return report, err
	}
	report.Enabled, report.Active, report.MainPID = state.Enabled, state.Active, state.MainPID
	report.State = "stopped"
	if state.Running() {
		report.State = "started"
		if record, err := demo.ReadReadyRecord(p.ReadyFile, state.MainPID, p.ExecutorID); err == nil {
			report.Ready, report.State = true, "ready"
			if p.Role == demo.DispatcherSchema {
				report.Endpoint = "http://" + record.HTTPAddr
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			report.Note = "the published readiness record does not describe the running process: " + err.Error()
		}
	}
	if p.Role == demo.DispatcherSchema {
		if switchState, err := ReadMaintenance(p.MaintenanceFile); err == nil && switchState.Paused {
			report.Note = "submission admission is stopped for maintenance: " + switchState.Reason
		}
	}
	return report, nil
}

// Uninstall stops the instance, disables it and removes the unit it owns. The
// persistent state directory is kept unless purge is set, and purge is refused
// until the manager reports the unit stopped: until local ownership has
// joined, no database, identity or result may be deleted.
func (i *Installer) Uninstall(ctx context.Context, role demo.SchemaRole, name string, purge bool) (Report, error) {
	p, report, err := i.load(ctx, "uninstall", role, name)
	if err != nil {
		return report, err
	}
	stopped, joined, err := i.stopAndVerify(ctx, p, &report)
	if err != nil {
		return report, err
	}
	report.Joined = joined
	if !stopped {
		report.State = "incomplete"
		return report, errors.New("the service manager has not reported this unit stopped; nothing was disabled, removed or deleted")
	}
	// Removing a unit and disabling it touch no state, so a daemon that
	// ended badly does not block them. Deleting what it served does need
	// the proof that it finished, and without it nothing at all is undone,
	// so the instance stays inspectable.
	if purge && !joined {
		report.State = "incomplete"
		return report, errors.New("the daemon did not complete its own shutdown, so its state may still be in use; nothing was disabled, removed or deleted")
	}
	state, err := i.manager.State(ctx, p.Unit)
	if err != nil {
		return report, err
	}
	if state.Enabled {
		if err := i.manager.Disable(ctx, p.Unit); err != nil {
			return report, err
		}
		report.Changed = append(report.Changed, "disabled")
	}
	if err := os.Remove(p.UnitPath); err == nil {
		report.Changed = append(report.Changed, "unit")
		if err := i.manager.Reload(ctx); err != nil {
			return report, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return report, err
	}
	report.State, report.Enabled, report.Active = "uninstalled", false, state.Active
	if !purge {
		report.Note = "the state directory, its database and the role identity were kept; use the purge option to delete them"
		return report, nil
	}
	if err := os.RemoveAll(p.StateDir); err != nil {
		return report, err
	}
	report.Changed = append(report.Changed, "state directory")
	// The instance is gone, so the administrator's record of it and any
	// maintenance switch it left go with it.
	for _, path := range []string{RecordPath(p.Root, p.Role, p.Name), p.MaintenanceFile} {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return report, err
		}
	}
	report.Changed = append(report.Changed, "installed record")
	report.Note = "the database, the role identity and all retained results were deleted"
	return report, nil
}

// load prepares one instance for an operation. Every path it returns is
// derived from the root, role and name the operator named; the installed
// record only supplies what an operator chose at installation time, and it is
// accepted at all only when it agrees with those derived paths.
func (i *Installer) load(ctx context.Context, operation string, role demo.SchemaRole, name string) (Profile, Report, error) {
	report := Report{Operation: operation, Role: string(role), Name: name}
	derived, err := DerivePaths(i.root, role, name)
	if err != nil {
		return derived, report, err
	}
	report.Unit, report.StateDir, report.UnitPath = derived.Unit, derived.StateDir, derived.UnitPath
	record, err := ReadRecord(i.root, role, name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			report.State = "not-installed"
			return derived, report, fmt.Errorf("no managed %s %q is installed under %s", role, name, RecordPath(i.root, role, name))
		}
		return derived, report, err
	}
	if !derived.SamePaths(record) {
		return derived, report, fmt.Errorf("the record at %s does not describe %s %s where it is installed; it was not written by an installation of this instance",
			RecordPath(i.root, role, name), role, name)
	}
	// Only the installation-time choices come from the record. The paths
	// stay the derived ones even though they compared equal.
	p := derived
	p.User, p.Group = record.User, record.Group
	p.Version, p.SourceSHA, p.PayloadRoot, p.Executable = record.Version, record.SourceSHA, record.PayloadRoot, record.Executable
	p.ExecutorID = record.ExecutorID
	p.HTTPPort, p.GRPCPort = record.HTTPPort, record.GRPCPort
	p.DispatcherGRPC, p.DispatcherHTTP = record.DispatcherGRPC, record.DispatcherHTTP
	report.Version, report.ExecutorID = p.Version, p.ExecutorID
	return p, report, ctx.Err()
}

// ReadRecord reads the installed record of one instance.
func ReadRecord(root string, role demo.SchemaRole, name string) (Profile, error) {
	var p Profile
	path := RecordPath(root, role, name)
	info, err := os.Lstat(path)
	if err != nil {
		return p, err
	}
	if !info.Mode().IsRegular() || info.Size() > recordLimit {
		return p, fmt.Errorf("%s is not a regular file within %d bytes", path, recordLimit)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("invalid managed service record %s: %w", path, err)
	}
	return p, nil
}

// writeRecord publishes the installed record where only an administrator can
// write it, and where every account may read what is installed.
func writeRecord(p Profile) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	path := RecordPath(p.Root, p.Role, p.Name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'), 0644)
}

// writeFileAtomic publishes exact bytes at path through a same-directory
// rename, so a reader sees either the previous file or the complete new one.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".debuglet-record-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Chmod(mode), file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func sameContent(path, candidate string) (bool, error) {
	existing, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	fresh, err := os.ReadFile(candidate)
	if err != nil {
		return false, err
	}
	return string(existing) == string(fresh), nil
}

func pause(ctx context.Context) error {
	timer := time.NewTimer(pollEvery)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// lookupSystemAccount resolves an existing account. Installing a service never
// creates one: account provisioning belongs to the host's deployment, and a
// service that silently invented its own account would own state nobody
// expected it to own.
func lookupSystemAccount(name, group string) (Account, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return Account{}, fmt.Errorf("service account %q does not exist on this host; create it before installing a managed service: %w", name, err)
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return Account{}, fmt.Errorf("service group %q does not exist on this host: %w", group, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return Account{}, fmt.Errorf("service account %q has no numeric id: %w", name, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return Account{}, fmt.Errorf("service group %q has no numeric id: %w", group, err)
	}
	return Account{UID: uid, GID: gid}, nil
}
