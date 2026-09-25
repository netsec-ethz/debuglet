package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// UnitState is what the service manager reports about one unit. It is
// deliberately a small, literal view: it says what the manager believes, never
// what the daemon inside the unit has actually finished.
type UnitState struct {
	// Loaded reports whether the manager knows a unit of this name at all.
	Loaded bool
	// Active is the manager's active state ("active", "inactive",
	// "failed", "activating", "deactivating").
	Active string
	// Sub is the manager's finer substate ("running", "dead", "exited").
	Sub string
	// Enabled reports whether the unit starts on its own at boot.
	Enabled bool
	// MainPID is the daemon's process ID, or 0 when none is running. A
	// readiness record is only believed when it names this process.
	MainPID int
	// Result is how the manager's last attempt to run the unit ended:
	// "success", or "timeout", "exit-code", "signal", "core-dump",
	// "watchdog" and the like for a failure.
	Result string
	// ExecMainStatus is the daemon's exit status, or the signal number
	// that killed it.
	ExecMainStatus int
}

// Running reports a unit the manager considers up.
func (s UnitState) Running() bool { return s.Active == "active" }

// Stopped reports a unit with no process left: it is down, whether it got
// there by exiting or by being killed.
func (s UnitState) Stopped() bool {
	return !s.Loaded || s.Active == "inactive" || s.Active == "failed"
}

// Joined reports a unit whose daemon finished on its own terms, which is the
// only thing that proves local ownership was released.
//
// It is deliberately not "the unit is down" and not "the readiness record is
// gone". The readiness record lives in the unit's runtime directory, which the
// manager removes whenever the unit stops, killed or not, so its absence
// proves nothing at all. What does prove something is how the daemon left: an
// inactive unit with a successful result and a zero exit status means the
// daemon ran its whole shutdown path, joined its own work and closed its
// database before exiting. A unit killed at its stop timeout, or one that
// exited nonzero, is failed with a result that says so, and its retained state
// may still be owned by a process that never finished.
func (s UnitState) Joined() bool {
	if s.Active != "inactive" {
		return false // Active, activating, deactivating or failed.
	}
	if !s.Loaded {
		return true // The manager knows no such unit, so nothing of it runs.
	}
	return s.Result == "success" && s.ExecMainStatus == 0
}

// Manager is the service manager an installation drives. It is an interface
// for one reason: nothing in this package may depend on running as root on a
// host with a live service manager, so the file operations, the unit contents
// and the readiness observation are exercised against a recorder instead.
type Manager interface {
	// Reload makes the manager re-read unit files from disk.
	Reload(ctx context.Context) error
	// Enable and Disable change only whether the unit starts at boot.
	Enable(ctx context.Context, unit string) error
	Disable(ctx context.Context, unit string) error
	// Start and Stop are synchronous: Stop returns when the manager has
	// finished stopping the unit or its own stop timeout expired.
	Start(ctx context.Context, unit string) error
	Stop(ctx context.Context, unit string) error
	// State reports what the manager believes about one unit.
	State(ctx context.Context, unit string) (UnitState, error)
}

// Systemctl drives the host service manager through its command-line client.
// Every call names exactly one unit, so no operation can reach a unit this
// package did not write.
type Systemctl struct {
	// Path is the absolute systemctl binary. NewSystemctl resolves it.
	Path string
}

// NewSystemctl resolves the host's service-manager client.
func NewSystemctl() (*Systemctl, error) {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return nil, fmt.Errorf("this host has no systemctl client; managed services need one: %w", err)
	}
	return &Systemctl{Path: path}, nil
}

func (s *Systemctl) Reload(ctx context.Context) error {
	_, err := s.run(ctx, "daemon-reload")
	return err
}

func (s *Systemctl) Enable(ctx context.Context, unit string) error {
	_, err := s.run(ctx, "enable", unit)
	return err
}

func (s *Systemctl) Disable(ctx context.Context, unit string) error {
	_, err := s.run(ctx, "disable", unit)
	return err
}

func (s *Systemctl) Start(ctx context.Context, unit string) error {
	_, err := s.run(ctx, "start", unit)
	return err
}

func (s *Systemctl) Stop(ctx context.Context, unit string) error {
	_, err := s.run(ctx, "stop", unit)
	return err
}

// State asks for the exact properties this package uses. A unit the manager
// does not know reports LoadState=not-found rather than an error, so an
// uninstalled service is distinguishable from an unreachable manager.
func (s *Systemctl) State(ctx context.Context, unit string) (UnitState, error) {
	out, err := s.run(ctx, "show", unit, "--property=LoadState", "--property=ActiveState",
		"--property=SubState", "--property=UnitFileState", "--property=MainPID",
		"--property=Result", "--property=ExecMainStatus")
	if err != nil {
		return UnitState{}, err
	}
	var state UnitState
	for line := range strings.Lines(out) {
		key, value, found := strings.Cut(strings.TrimRight(line, "\n"), "=")
		if !found {
			continue
		}
		switch key {
		case "LoadState":
			state.Loaded = value == "loaded"
		case "ActiveState":
			state.Active = value
		case "SubState":
			state.Sub = value
		case "UnitFileState":
			state.Enabled = value == "enabled" || value == "enabled-runtime"
		case "MainPID":
			state.MainPID, _ = strconv.Atoi(value)
		case "Result":
			state.Result = value
		case "ExecMainStatus":
			state.ExecMainStatus, _ = strconv.Atoi(value)
		}
	}
	return state, nil
}

func (s *Systemctl) run(ctx context.Context, args ...string) (string, error) {
	if s.Path == "" {
		return "", errors.New("service manager client is not resolved")
	}
	cmd := exec.CommandContext(ctx, s.Path, args...)
	// A static client needs no inherited environment, and inheriting one
	// would let an operator's session change what the manager is asked.
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, bounded(stderr.String()))
	}
	return stdout.String(), nil
}

// bounded keeps a manager diagnostic readable in a command's output.
func bounded(text string) string {
	text = strings.TrimSpace(text)
	if len(text) > 512 {
		return text[:512] + "..."
	}
	return text
}

// ErrStagingRoot reports an operation that would have to act on the host's
// service manager while the caller asked for an alternate filesystem root.
var ErrStagingRoot = errors.New("an alternate root stages files only; it cannot drive the host service manager")

// StagingManager stands in for the service manager when files are written
// below an alternate root. Such a tree is not a second installation: the host
// has exactly one service manager, its units live at their own absolute paths
// and a unit's runtime directory is always the real one, so acting on a unit
// named by a staged tree would act on the production instance of that name.
// Every operation that would do so is refused here rather than performed
// against the wrong target.
type StagingManager struct{}

// Reload has nothing to re-read: no unit of a staged tree was ever loaded, and
// the manager's own units were not touched. It is the one operation that is
// not refused, because it changes nothing either way.
func (StagingManager) Reload(context.Context) error { return nil }

func (StagingManager) Enable(context.Context, string) error  { return ErrStagingRoot }
func (StagingManager) Disable(context.Context, string) error { return ErrStagingRoot }
func (StagingManager) Start(context.Context, string) error   { return ErrStagingRoot }
func (StagingManager) Stop(context.Context, string) error    { return ErrStagingRoot }

// State reports the staged instance as one the manager does not know, which is
// what it is: no unit of a staged tree was ever loaded.
func (StagingManager) State(context.Context, string) (UnitState, error) {
	return UnitState{Active: "inactive", Sub: "dead", Result: "success"}, nil
}
