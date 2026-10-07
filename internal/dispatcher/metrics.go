// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
)

const (
	metricsRunLimit        = 10000
	metricsExecutorIDLimit = 1024
)

// ControlMetrics is an observation, not a lifetime event counter. Runs describes
// retained durable rows; pruning changes its counts. Registry and storage are
// read separately, so a transition concurrent with collection may appear on the
// next scrape. No run, executor, account or destination identifiers are exported.
type ControlMetrics struct {
	ObservedAt                 time.Time
	Registered, Ready          int
	ReadyCapacityBitsPerSecond float64
	RegistryUnavailable        string
	Health                     ExecutorHealthMetrics
	Runs                       RetainedRunMetrics
	Settlement                 payments.SettlementMetrics
}

type RetainedRunMetrics struct {
	Unavailable                                                         string
	Admitted, Pending, Started, ReportedSuccess, ReportedError, Unknown int
	PendingOverdueSeconds                                               float64
}

// CollectMetrics reads at most 10,001 run rows and retains no per-run data. An
// oversized or unreadable history is unavailable, never a partial count. The
// two-second query context bounds storage work; registry locks are released
// before waiting for the database connection or reading any rows.
func (d *Dispatcher) CollectMetrics(ctx context.Context) ControlMetrics {
	now := time.Now().UTC()
	report := ControlMetrics{ObservedAt: now}
	type runBinding struct {
		executorID string
		controlsession.Binding
	}
	bindings := make(map[runBinding]struct{})
	d.mu.RLock()
	if !d.closed {
		// Bound work even when the registry is larger than the supported scrape.
		if len(d.executors) > metricsRunLimit {
			report.RegistryUnavailable = "limit"
		} else {
			for _, entry := range d.executors {
				if len(entry.ID) > metricsExecutorIDLimit {
					report.RegistryUnavailable = "limit"
					break
				}
				report.Registered++
				available := entry.owner.Available()
				report.Health.observe(entry, now, available)
				report.Health.observeDisclosureLag(entry, now, available, d.keystore)
				if available {
					report.Ready++
					report.ReadyCapacityBitsPerSecond += float64(entry.capacity)
					bindings[runBinding{entry.ID, entry.owner.Binding()}] = struct{}{}
				}
			}
		}
	}
	d.mu.RUnlock()
	report.Settlement = d.Payment.CollectMetrics(ctx)
	if report.RegistryUnavailable != "" {
		report.Runs.Unavailable = "registry"
		return report
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := d.db.QueryContext(ctx, `SELECT state, error IS NOT NULL,
		start_time, end_time, substr(CAST(executor_id AS BLOB), 1, ?),
		substr(CAST(dispatcher_incarnation AS BLOB), 1, 65), substr(CAST(session_id AS BLOB), 1, 65)
		FROM debuglets LIMIT ?`, metricsExecutorIDLimit+1, metricsRunLimit+1)
	if err != nil {
		report.Runs.Unavailable = "storage"
		return report
	}
	defer rows.Close()
	runs := RetainedRunMetrics{}
	for rows.Next() {
		var state models.DebugletRunState
		var failed bool
		var from, to models.UTCTime
		var executorID, incarnation, sessionID []byte
		if err := rows.Scan(&state, &failed, &from, &to, &executorID, &incarnation, &sessionID); err != nil {
			report.Runs.Unavailable = "storage"
			return report
		}
		runs.Admitted++
		if runs.Admitted > metricsRunLimit || len(executorID) > metricsExecutorIDLimit || len(incarnation) > 64 || len(sessionID) > 64 {
			report.Runs.Unavailable = "limit"
			return report
		}
		binding := runBinding{string(executorID), controlsession.Binding{Incarnation: string(incarnation), SessionID: string(sessionID)}}
		_, current := bindings[binding]
		switch {
		case state == models.RunStateExited:
			if failed {
				runs.ReportedError++
			} else {
				runs.ReportedSuccess++
			}
		case !current || !now.Before(to.Time) || state.SemanticRank() < 0 || state == models.RunStateUnreconciled:
			runs.Unknown++
		case state == models.RunStateStarted:
			runs.Started++
		default:
			runs.Pending++
			if overdue := now.Sub(from.Time).Seconds(); overdue > runs.PendingOverdueSeconds {
				runs.PendingOverdueSeconds = overdue
			}
		}
	}
	if rows.Err() != nil {
		report.Runs.Unavailable = "storage"
		return report
	}
	report.Runs = runs
	return report
}
