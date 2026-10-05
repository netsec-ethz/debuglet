// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package service

import (
	"context"
	"errors"
	"fmt"
	"os"

	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/sqlite"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

type ArchiveReport struct {
	Operation string             `json:"operation"`
	Name      string             `json:"name"`
	Unit      string             `json:"unit"`
	DryRun    bool               `json:"dry_run"`
	Run       sqlite.ArchivedRun `json:"run"`
}

// ArchiveRun operates only on a drained managed executor. It neither stops nor
// restarts a service: an incomplete drain cannot be overridden by this command.
func (i *Installer) ArchiveRun(ctx context.Context, name string, id uuid.UUID, reason string, apply bool) (ArchiveReport, error) {
	p, _, err := i.load(ctx, "archive-run", storagecheck.Executor, name)
	r := ArchiveReport{Operation: "archive-run", Name: name, Unit: p.Unit, DryRun: !apply}
	if err != nil {
		return r, err
	}
	if err := i.verifyRemoval(ctx, p); err != nil {
		return r, err
	}
	checkJoined := func() error {
		state, err := i.manager.State(ctx, p.Unit)
		if err != nil {
			return err
		}
		if !state.Loaded || !state.Joined() || state.MainPID != 0 || state.Enabled {
			return errors.New("archive requires a disabled executor with successful joined shutdown; run dbl drain --role executor --name " + name + " first")
		}
		data, err := os.ReadFile(p.ConfigPath)
		if err != nil {
			return err
		}
		cfg, _, err := executorconfig.DecodeConfig(data)
		if err != nil {
			return err
		}
		if cfg.Database.Path != p.DatabasePath || cfg.Identity.ExecutorID != p.ExecutorID {
			return errors.New("managed executor configuration has a changed database or identity")
		}
		return checkEnrolledProcesses("/proc", p, p.ExecutorID, 0)
	}
	if err := checkJoined(); err != nil {
		return r, err
	}
	err = sqlite.PreserveDatabaseOwnership(p.DatabasePath, func() error {
		return i.archiveDatabase(ctx, p, id, reason, apply, checkJoined, &r)
	})
	return r, err
}

func (i *Installer) archiveDatabase(ctx context.Context, p Profile, id uuid.UUID, reason string, apply bool, checkJoined func() error, r *ArchiveReport) error {
	if err := storagecheck.Check(ctx, storagecheck.Executor, p.DatabasePath); err != nil {
		return err
	}
	if !apply {
		db, err := sqlitedb.Open(p.DatabasePath, sqlitedb.ReadOnly())
		if err != nil {
			return err
		}
		defer db.Close()
		r.Run, err = sqlite.InspectArchive(ctx, db, id)
		return err
	}
	db, err := storagecheck.OpenExclusive(ctx, p.DatabasePath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := storagecheck.CheckOpen(ctx, storagecheck.Executor, db, p.DatabasePath); err != nil {
		return err
	}
	// A concurrent start cannot read this database until Close. Check that it
	// had not already constructed an executor before exclusive ownership.
	if err := i.verifyRemoval(ctx, p); err != nil {
		return err
	}
	if err := checkJoined(); err != nil {
		return err
	}
	r.Run, err = sqlite.ArchiveRun(ctx, db, id, reason)
	if err != nil {
		return fmt.Errorf("archive retained run: %w", err)
	}
	return db.Close()
}
