// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"go.uber.org/zap"
)

const (
	// expiredWindowGrace is how long after the end of its reserved window a
	// run may still report before the dispatcher stops waiting for it.
	expiredWindowGrace = time.Minute
	// windowSweepInterval is the least time between two sweeps of runs whose
	// window has ended.
	windowSweepInterval = 30 * time.Second
	// windowSweepBound bounds the database work of one sweep.
	windowSweepBound = 5 * time.Second
)

// outcomeUnknown is the stored error of a run classified at the end of its
// window.
const outcomeUnknown = "outcome unknown: the reserved window of the run ended without a terminal report from its executor"

// sweepEndedWindows classifies, at most once per windowSweepInterval since
// last, every unfinished run whose window ended more than expiredWindowGrace
// ago. Such a run is unreconciled, or its report can no longer arrive because
// its control session ended before it started, or its executor holds it past
// its window without reporting. It returns the time of the sweep it ran, or
// last when it ran none. Only the expiry loop calls it.
//
// The terminal write is guarded by the run's stored binding, as every terminal
// write of the run is, so exactly one writer wins: a report that arrived first
// keeps its result, and a later report has no effect. The winner runs the
// effects of a nonzero exit, except the fairshare update, which needs a live
// mutation of the run's session; as for cancelUnbound, other executors keep
// their allocations on the run's destinations until the next update. A run
// without a complete stored binding admits no terminal write and is left as it
// is.
func (d *Dispatcher) sweepEndedWindows(last time.Time) time.Time {
	now := d.now()
	if !last.IsZero() && now.Sub(last) < windowSweepInterval {
		return last
	}
	d.mu.RLock()
	closed := d.closed
	d.mu.RUnlock()
	if closed {
		return last
	}
	ctx, cancel := context.WithTimeout(context.Background(), windowSweepBound)
	defer cancel()
	queries := database.New(d.db)
	runs, err := queries.ListUnfinishedDebugletsEndBefore(ctx, database.ListUnfinishedDebugletsEndBeforeParams{
		ExitedState: models.RunStateExited,
		EndTime:     models.NewUTCTime(now.Add(-expiredWindowGrace)),
	})
	if err != nil {
		d.logger.Error("Failed to list debuglets whose window has ended", zap.Error(err))
		return now
	}
	msg := outcomeUnknown
	for _, run := range runs {
		if ctx.Err() != nil {
			break
		}
		deb, err := queries.CompleteDebuglet(ctx, database.CompleteDebugletParams{
			ExitedState:           models.RunStateExited,
			Error:                 terminalError(-1, &msg),
			Uuid:                  run.Uuid,
			ExecutorID:            run.ExecutorID,
			DispatcherIncarnation: run.DispatcherIncarnation,
			SessionID:             run.SessionID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			d.logger.Debug("Debuglet finished before its window was classified", zap.String("debugletID", run.Uuid.String()))
		} else if err != nil {
			d.logger.Error("Failed to classify debuglet whose window has ended", zap.String("debugletID", run.Uuid.String()), zap.Error(err))
			continue
		} else {
			d.logger.Info("Classified debuglet with outcome unknown at the end of its window", zap.String("debugletID", deb.Uuid.String()), zap.String("executor", deb.ExecutorID))
			d.settleTerminalPayment(ctx, &deb, -1)
		}
		// Release by run identity also when another writer won.
		d.releaseTerminal(run)
	}
	return now
}
