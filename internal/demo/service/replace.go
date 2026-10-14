// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/sqlite"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

// ReplacePackage selects an already verified full payload for a drained,
// disabled enrolled executor. The operator must retain a stopped-state backup
// and exclude concurrent administration. No state is migrated, replayed or
// relocated, and no service is started or enabled.
func (i *Installer) ReplacePackage(ctx context.Context, request Request, target demo.Assets) (Report, error) {
	old, report, err := i.load(ctx, "replace-package", request.Role, request.Name)
	report.State = "incomplete"
	if err != nil {
		return report, err
	}
	if request.Role != storagecheck.Executor || !old.Enrolled || old.ExecutorID == "" || request.EnrolledState != old.StateDir {
		return report, errors.New("package replacement requires the existing enrolled executor and its canonical --enrolled-state")
	}
	if (request.User != "" && request.User != old.User) || (request.Group != "" && request.Group != old.Group) {
		return report, errors.New("package replacement cannot change the service account or group")
	}
	request.Root, request.User, request.Group = i.root, old.User, old.Group
	selected, err := Resolve(request, target)
	if err != nil {
		return report, err
	}
	if !old.SamePaths(selected) {
		return report, errors.New("package replacement cannot change managed paths")
	}
	account, err := i.lookup(old.User, old.Group)
	if err != nil {
		return report, err
	}
	if account.UID == 0 || account.GID == 0 {
		return report, errors.New("an enrolled executor must run as an unprivileged service account and group")
	}
	// All non-package fields come from the retained record, never from a new
	// default or the selected payload's preferred capability profile.
	candidate := old
	candidate.Version, candidate.SourceSHA = selected.Version, selected.SourceSHA
	candidate.PayloadRoot, candidate.Executable = selected.PayloadRoot, selected.Executable
	report.Version, report.PackagePath = candidate.Version, candidate.PayloadRoot
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		state, err := i.manager.State(ctx, old.Unit)
		if err != nil {
			return err
		}
		if !state.Loaded || !state.Joined() || state.MainPID != 0 || state.Enabled {
			return errors.New("package replacement requires a disabled executor with successful joined shutdown; drain it first")
		}
		// A crash before committing the record can leave precisely the unit
		// requested by this explicit operation. No other mismatch is adopted.
		if _, err := os.Lstat(old.UnitPath); err != nil {
			return err
		}
		if err := i.verifyRemoval(ctx, old); err != nil {
			if err := i.verifyRemoval(ctx, candidate); err != nil {
				return fmt.Errorf("unit matches neither the recorded nor selected package: %w", err)
			}
		}
		return checkEnrolledProcesses("/proc", old, old.ExecutorID, 0)
	}
	if err := check(); err != nil {
		return report, err
	}
	cfg, err := validateEnrolledState(old)
	if err != nil {
		return report, err
	}
	if (cfg.Network.PacketCounter == "auto") != old.PacketCapabilities ||
		cfg.Dispatcher.Addr != old.DispatcherGRPC || cfg.Dispatcher.YamuxAddr != old.DispatcherHTTP {
		return report, errors.New("package replacement cannot change the recorded counter mode or dispatcher; reinstall the same package to apply configuration changes first")
	}
	// Only the selected daemon knows which schemas it supports. Its existing
	// administration flag reads the database before constructing an executor.
	checkCtx, cancel := context.WithTimeout(ctx, ReadyTimeout)
	defer cancel()
	var diagnostic string
	err = sqlite.PreserveDatabaseOwnership(old.DatabasePath, func() error {
		cmd := exec.CommandContext(checkCtx, candidate.Executable, "-config", old.ConfigPath, "-check-database")
		cmd.Env = []string{"LANG=C", "LC_ALL=C", "TZ=UTC"}
		// Output retains only a bounded prefix/suffix of stderr on failure.
		_, err := cmd.Output()
		var failed *exec.ExitError
		if errors.As(err, &failed) {
			diagnostic = bounded(string(failed.Stderr))
		}
		return errors.Join(err, checkCtx.Err())
	})
	if err != nil {
		return report, fmt.Errorf("selected package refused the database check; inspect its -check-database result before replacement: %w: %s", err, diagnostic)
	}
	if err := check(); err != nil {
		return report, err
	}
	report.Joined = true
	changed, err := i.writeUnit(candidate)
	if err != nil {
		return report, err
	}
	if changed {
		report.Changed = append(report.Changed, "unit")
	}
	// Publish the record last. Reload failure/cancellation leaves the old
	// record and exact candidate unit, recoverable only by explicit selection.
	if err := i.manager.Reload(ctx); err != nil {
		return report, err
	}
	if err := check(); err != nil {
		return report, err
	}
	if old != candidate {
		if err := writeRecord(candidate); err != nil {
			return report, err
		}
		report.Changed = append(report.Changed, "installed record")
	}
	report.State, report.Active = "installed", "inactive"
	report.Note = "selected package installed; executor remains drained and disabled; resume explicitly after reviewing the retained state"
	return report, nil
}

// prepareStart refuses an interrupted replacement before any enabling or
// marker removal. Reload also prevents the manager starting a stale definition
// after the files were committed but a previous process was interrupted.
func (i *Installer) prepareStart(ctx context.Context, p Profile) error {
	if _, err := os.Lstat(p.UnitPath); err != nil {
		return err
	}
	if err := i.verifyRemoval(ctx, p); err != nil {
		return err
	}
	return i.manager.Reload(ctx)
}
