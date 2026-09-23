package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/sqlite"
)

// Drain removes one managed role from eligible capacity and reports what
// happened to the work it held. The two roles are drained by different means
// because they hold different things:
//
//   - An executor is stopped. Stopping is what revokes its control
//     eligibility, signals its active runs and joins its own local work; this
//     package adds no second lifecycle controller beside it. Only executors
//     that were actually stopped are affected: every other executor keeps
//     serving, because nothing in a drain touches another unit.
//   - A dispatcher is not stopped. It keeps serving its accepted work,
//     its executors and its queries, and only the admission of new
//     submissions is switched off.
//
// The wait-versus-cancel policy is explicit and is the daemon's own, not a new
// one: a drain waits for local ownership to join inside the stop budget and
// cancels nothing beyond what stopping already signals. Queued work stays
// persisted and is never replayed. Work that was already running is signaled
// and joined; a run that ends as a result of that is reported by the ordinary
// terminal path, whose delivery to the dispatcher may still be unknown.
//
// A drain that does not join inside its budget is reported as incomplete. It
// is then not a drain at all: nothing may be deleted, upgraded or reinitialized
// on the strength of it, because the process may still own the database.
type DrainOptions struct {
	// Reason is the operator note the dispatcher switch carries.
	Reason string
	// Timeout bounds the whole drain. Zero uses DrainBudget.
	Timeout time.Duration
	// Disable also stops the unit from starting again on its own, so a
	// reboot during maintenance does not undo the drain. It applies to a
	// role that is drained by being stopped: a dispatcher is not stopped,
	// and its switch is a file an administrator owns that survives a reboot
	// on its own, so this says nothing about one.
	Disable bool
}

// DrainReport is what a drain or its reversal observed.
type DrainReport struct {
	Operation string `json:"operation"`
	Role      string `json:"role"`
	Name      string `json:"name"`
	Unit      string `json:"unit"`
	// Outcome is drained, paused, resumed, started or incomplete.
	Outcome string `json:"outcome"`
	// Joined reports proven local completion: the service manager reports
	// the unit inactive with a successful result and a zero exit status,
	// which is the daemon saying it released what it owned. It is the only
	// field that may be used to authorize deletion, an upgrade or closing
	// the database.
	Joined  bool   `json:"joined"`
	Enabled bool   `json:"enabled"`
	Active  string `json:"active,omitempty"`
	Ready   bool   `json:"ready,omitempty"`
	// Disposition is read from the persistent state once, after the join.
	Disposition *scheduler.Disposition `json:"disposition,omitempty"`
	StateDir    string                 `json:"state_dir,omitempty"`
	Changed     []string               `json:"changed,omitempty"`
	Note        string                 `json:"note,omitempty"`
}

// ErrDrainIncomplete reports a drain whose local ownership did not join inside
// its budget. The node is neither serving nor known to be finished.
var ErrDrainIncomplete = errors.New("drain incomplete: local ownership has not joined")

// Drain performs the drain of one installed role instance.
func (i *Installer) Drain(ctx context.Context, role demo.SchemaRole, name string, options DrainOptions) (DrainReport, error) {
	p, base, err := i.load(ctx, "drain", role, name)
	report := DrainReport{Operation: "drain", Role: base.Role, Name: base.Name, Unit: base.Unit, StateDir: base.StateDir}
	if err != nil {
		report.Outcome = base.State
		return report, err
	}
	if role == demo.DispatcherSchema {
		return i.pauseAdmission(ctx, p, report, options)
	}
	budget := options.Timeout
	if budget <= 0 {
		budget = DrainBudget
	}
	drainCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	stop := *i
	stop.stopTimeout = budget
	_, joined, err := stop.stopAndVerify(drainCtx, p, &base)
	report.Changed, report.Active, report.Enabled, report.Note = base.Changed, base.Active, base.Enabled, base.Note
	if err != nil {
		report.Outcome = "incomplete"
		return report, err
	}
	if !joined {
		report.Outcome = "incomplete"
		if report.Note == "" {
			report.Note = "the service manager has not reported this unit stopped"
		}
		report.Note += "; nothing here authorizes deleting, upgrading or reinitializing its state, and its process may still own the database"
		return report, fmt.Errorf("%w within %s", ErrDrainIncomplete, budget)
	}
	report.Joined, report.Outcome = true, "drained"
	if options.Disable && report.Enabled {
		if err := i.manager.Disable(ctx, p.Unit); err != nil {
			return report, err
		}
		report.Enabled = false
		report.Changed = append(report.Changed, "disabled")
	}
	disposition, err := sqlite.InspectDisposition(ctx, p.DatabasePath)
	if err != nil {
		report.Note = "the node is drained, but its retained work could not be inspected: " + err.Error()
		return report, nil
	}
	report.Disposition = &disposition
	report.Note = disposition.Summary() + "; nothing is replayed and no retained row or result was deleted"
	return report, nil
}

// pauseAdmission stops submission admission on a managed dispatcher without
// stopping it. Queries, reporting, executor control sessions and every
// already-accepted debuglet continue exactly as before.
func (i *Installer) pauseAdmission(ctx context.Context, p Profile, report DrainReport, options DrainOptions) (DrainReport, error) {
	if err := WriteMaintenance(p.MaintenanceFile, options.Reason, time.Now()); err != nil {
		return report, err
	}
	// Read the switch back: the dispatcher refuses submissions on exactly
	// this file, so an operator is told what the daemon will see.
	state, err := ReadMaintenance(p.MaintenanceFile)
	if err != nil || !state.Paused {
		report.Outcome = "incomplete"
		return report, errors.Join(errors.New("the maintenance switch was not published"), err)
	}
	report.Changed = append(report.Changed, "maintenance switch")
	report.Outcome = "paused"
	report.Note = "new submissions are refused from now on; accepted debuglets keep their persistence and schedule, executors keep running, and results and queries are unaffected"
	unit, err := i.manager.State(ctx, p.Unit)
	if err != nil {
		return report, err
	}
	report.Active, report.Enabled = unit.Active, unit.Enabled
	if unit.Running() {
		if _, err := demo.ReadReadyRecord(p.ReadyFile, unit.MainPID, ""); err == nil {
			report.Ready = true
		}
	}
	return report, nil
}

// Resume reverses a drain: it clears a dispatcher's admission switch, or it
// enables and starts a drained executor again and observes its readiness. It
// replays nothing: work retained from before the drain stays quarantined.
func (i *Installer) Resume(ctx context.Context, role demo.SchemaRole, name string) (DrainReport, error) {
	p, base, err := i.load(ctx, "resume", role, name)
	report := DrainReport{Operation: "resume", Role: base.Role, Name: base.Name, Unit: base.Unit, StateDir: base.StateDir}
	if err != nil {
		report.Outcome = base.State
		return report, err
	}
	if role == demo.DispatcherSchema {
		cleared, err := ClearMaintenance(p.MaintenanceFile)
		if err != nil {
			return report, err
		}
		if cleared {
			report.Changed = append(report.Changed, "maintenance switch")
		}
		report.Outcome = "resumed"
		report.Note = "submission admission is open again; the dispatcher was never stopped and needs no restart"
		state, err := i.manager.State(ctx, p.Unit)
		if err != nil {
			return report, err
		}
		report.Active, report.Enabled = state.Active, state.Enabled
		return report, nil
	}
	state, err := i.manager.State(ctx, p.Unit)
	if err != nil {
		return report, err
	}
	if !state.Enabled {
		if err := i.manager.Enable(ctx, p.Unit); err != nil {
			return report, err
		}
		report.Changed = append(report.Changed, "enabled")
	}
	if !state.Running() {
		if err := i.manager.Start(ctx, p.Unit); err != nil {
			return report, err
		}
		report.Changed = append(report.Changed, "started")
	}
	started, err := i.finishReport(ctx, p, base, true)
	report.Active, report.Enabled, report.Ready = started.Active, started.Enabled, started.Ready
	if err != nil {
		report.Outcome = "incomplete"
		return report, err
	}
	report.Outcome = "started"
	report.Note = "the executor serves new work again; work retained from before the drain stays quarantined and is not replayed"
	return report, nil
}
