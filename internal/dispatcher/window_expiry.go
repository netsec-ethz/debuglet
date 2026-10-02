// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/daemonlog"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"go.uber.org/zap"
)

const (
	expiredWindowGrace  = time.Minute
	windowSweepInterval = 30 * time.Second
	windowSweepBound    = 5 * time.Second
)

// Retained for the public projection of historical terminal rows. New window
// expiry records only local accounting reclamation, never a workload outcome.
const outcomeUnknown = "outcome unknown: the reserved window of the run ended without a terminal report from its executor"

// sweepEndedWindows records reclamation after the reserved window plus grace.
// Neither a lost session nor time passing proves the remote guest's outcome.
// Actual terminal evidence remains eligible under its original binding; no run
// is replayed, no payment is settled, and retained-work quotas remain charged.
func (d *Dispatcher) sweepEndedWindows(last time.Time) time.Time {
	now := d.now()
	if !last.IsZero() && now.Sub(last) < windowSweepInterval {
		return last
	}
	d.mu.RLock()
	closed := d.closed
	// These existing reservations also identify a write whose SQLite commit
	// succeeded but returned an error. Retry its in-memory release next sweep.
	var held []uuid.UUID
	for id, request := range d.reservations {
		if request.To.Before(now.Add(-expiredWindowGrace)) {
			held = append(held, id)
		}
	}
	d.mu.RUnlock()
	if closed {
		return last
	}
	ctx, cancel := context.WithTimeout(context.Background(), windowSweepBound)
	defer cancel()
	queries := database.New(d.db)
	destinations := map[string]struct{}{}
	release := func(run database.Debuglet) {
		d.releaseTerminal(run)
		for _, address := range run.Addresses {
			destinations[address] = struct{}{}
		}
	}
	runs, err := queries.ListUnreclaimedAllocations(ctx, database.ListUnreclaimedAllocationsParams{ExitedState: models.RunStateExited, EndTime: models.NewUTCTime(now.Add(-expiredWindowGrace))})
	if err != nil {
		d.logger.Error("Failed to list ended allocations")
		d.logger.Debug("Private runtime diagnostic", zap.String("error", daemonlog.Diagnostic(err)))
		return now
	}
	for _, run := range runs {
		if ctx.Err() != nil {
			break
		}
		// Allocation's final eligibility check holds the same lock. A recorded
		// reclamation therefore fences a late Allocate even after clock rollback.
		d.mu.Lock()
		err := queries.ReclaimAllocation(ctx, database.ReclaimAllocationParams{Uuid: run.Uuid, ReclaimedAt: models.NewUTCTime(now), ExitedState: models.RunStateExited, ExecutorID: run.ExecutorID, DispatcherIncarnation: run.DispatcherIncarnation, SessionID: run.SessionID})
		if err == nil {
			d.releaseTerminalResources(run)
		}
		d.mu.Unlock()
		if err != nil {
			d.logger.Error("Failed to record allocation reclamation", zap.String("debugletID", run.Uuid.String()))
			d.logger.Debug("Private runtime diagnostic", zap.String("error", daemonlog.Diagnostic(err)))
			continue
		}
		for _, address := range run.Addresses {
			destinations[address] = struct{}{}
		}
		d.logger.Info("Reclaimed ended allocation; workload outcome unchanged", zap.String("debugletID", run.Uuid.String()))
	}
	for _, id := range held {
		if ctx.Err() != nil {
			break
		}
		run, err := queries.GetReclaimedDebuglet(ctx, id)
		if err == nil {
			release(run)
		} else if !errors.Is(err, sql.ErrNoRows) {
			d.logger.Error("Failed to read allocation reclamation", zap.String("debugletID", id.String()))
		}
	}
	if len(destinations) > 0 {
		addresses := make([]string, 0, len(destinations))
		for address := range destinations {
			addresses = append(addresses, address)
		}
		if err := d.sendFairshare(ctx, nil, addresses); err != nil {
			d.logger.Warn("Reclaimed allocation notification remains pending")
		}
	}
	return now
}
