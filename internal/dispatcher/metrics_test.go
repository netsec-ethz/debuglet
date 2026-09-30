// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func TestMetricsObserveDurableTransitionsOnce(t *testing.T) {
	f := newTGFixture(t, nil)
	a, b := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
	start := time.Now().UTC().Add(-12 * time.Second)
	if _, err := f.db.Exec("UPDATE debuglets SET start_time = ?, end_time = ? WHERE uuid = ?", models.NewUTCTime(start), models.NewUTCTime(start.Add(time.Hour)), a.id); err != nil {
		t.Fatal(err)
	}
	first := f.d.CollectMetrics(f.ctx)
	if first.Ready != 1 || first.Registered != 1 || first.ReadyCapacityBitsPerSecond != float64(tgCapacity) {
		t.Fatalf("registry observation: %+v", first)
	}
	if first.Runs.Unavailable != "" || first.Runs.Admitted != 2 || first.Runs.Pending != 2 || first.Runs.PendingOverdueSeconds != first.ObservedAt.Sub(start).Seconds() {
		t.Fatalf("pending observation or seconds units: %+v", first)
	}
	if err := f.state(t, a.id, pb.RunState_RUN_STATE_STARTED); err != nil {
		t.Fatal(err)
	}
	if got := f.d.CollectMetrics(f.ctx).Runs; got.Started != 1 || got.Pending != 1 || got.PendingOverdueSeconds != 0 {
		t.Fatalf("started: %+v", got)
	}
	if err := f.exit(t, a.id, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.exit(t, b.id, 1, tgStr("private failure /home/operator/secret")); err != nil {
		t.Fatal(err)
	}
	before := f.d.CollectMetrics(f.ctx).Runs
	if before.Admitted != 2 || before.ReportedSuccess != 1 || before.ReportedError != 1 || before.Pending != 0 || before.Unknown != 0 {
		t.Fatalf("terminal: %+v", before)
	}
	if err := f.exit(t, a.id, 1, tgStr("duplicate must not change success")); err != nil {
		t.Fatal(err)
	}
	if err := f.state(t, a.id, pb.RunState_RUN_STATE_INITIALIZING); err != nil {
		t.Fatal(err)
	}
	if after := f.d.CollectMetrics(f.ctx).Runs; after != before {
		t.Fatalf("duplicate/stale transition changed metrics: before=%+v after=%+v", before, after)
	}
	// Supported payload deletion keeps the run identity and terminal outcome.
	// Arrange confirmed retirement and final output before exercising deletion.
	if err := f.q.ReserveAccountRun(f.ctx, database.ReserveAccountRunParams{DebugletID: a.row.ID, QueuedBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.q.RetireAccountRun(f.ctx, database.RetireAccountRunParams{DebugletID: a.row.ID, RetiredAt: sql.NullInt64{Int64: time.Now().Unix(), Valid: true}}); err != nil {
		t.Fatal(err)
	}
	if err := f.d.createOutputMetadata(f.ctx, f.q, a.id, pb.OutputVersion, ""); err != nil {
		t.Fatal(err)
	}
	binding := controlsession.Binding{Incarnation: a.row.DispatcherIncarnation, SessionID: a.row.SessionID}
	writer := outputWriter{executorID: a.row.ExecutorID, binding: binding, original: binding, version: pb.OutputVersion}
	requireOutputReceipt(t, f.d, writer, a.id, nil, &pb.DebugletOutputEnd{Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE})
	if err := f.d.DeleteCompletedPayload(f.ctx, a.id, false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.q.GetPayloadTombstone(f.ctx, a.id); err != nil {
		t.Fatal(err)
	}
	if after := f.d.CollectMetrics(f.ctx).Runs; after != before {
		t.Fatalf("payload deletion changed retained outcome metrics: before=%+v after=%+v", before, after)
	}
}

func TestMetricsCountCurrentRowsRatherThanLifetimeEvents(t *testing.T) {
	f := newTGFixture(t, nil)
	a := f.seedDirect(t, tgFloorA)
	// This bare fixture row has no retained outcome or accounting references.
	// Removing it verifies that metrics count current rows, not cached events.
	if before := f.d.CollectMetrics(f.ctx).Runs; before.Admitted != 1 || before.Pending != 1 {
		t.Fatalf("before row removal: %+v", before)
	}
	if _, err := f.db.Exec("DELETE FROM debuglets WHERE uuid = ?", a.id); err != nil {
		t.Fatal(err)
	}
	if got := f.d.CollectMetrics(f.ctx).Runs; got != (RetainedRunMetrics{}) {
		t.Fatalf("row removal must change gauges: %+v", got)
	}
}

func TestMetricsUnknownIsNotSuccess(t *testing.T) {
	f := newTGFixture(t, nil)
	a := f.seedDirect(t, tgFloorA)
	if _, err := f.db.Exec("UPDATE debuglets SET executor_id = ? WHERE uuid = ?", "another-executor", a.id); err != nil {
		t.Fatal(err)
	}
	if got := f.d.CollectMetrics(f.ctx).Runs; got.Unknown != 1 || got.Pending != 0 {
		t.Fatalf("same session but different executor: %+v", got)
	}
	if _, err := f.db.Exec("UPDATE debuglets SET executor_id = ? WHERE uuid = ?", tgExecutorID, a.id); err != nil {
		t.Fatal(err)
	}
	for _, state := range []int{int(models.RunStateUnreconciled), 991} {
		if _, err := f.db.Exec("UPDATE debuglets SET state = ? WHERE uuid = ?", state, a.id); err != nil {
			t.Fatal(err)
		}
		if got := f.d.CollectMetrics(f.ctx).Runs; got.Unknown != 1 || got.ReportedSuccess != 0 || got.Pending != 0 {
			t.Fatalf("unknown state %d: %+v", state, got)
		}
	}
	if _, err := f.db.Exec("UPDATE debuglets SET state = ? WHERE uuid = ?", models.RunStateUploaded, a.id); err != nil {
		t.Fatal(err)
	}
	f.d.mu.RLock()
	owner := f.d.executors[tgExecutorID].owner
	f.d.mu.RUnlock()
	owner.Retire()
	got := f.d.CollectMetrics(f.ctx)
	if got.Ready != 0 || got.ReadyCapacityBitsPerSecond != 0 || got.Runs.Unknown != 1 || got.Runs.ReportedSuccess != 0 {
		t.Fatalf("retired control session: %+v", got)
	}
}

func TestMetricsIdentityBoundsPreserveBindings(t *testing.T) {
	f := newTGFixture(t, nil)
	a := f.seedDirect(t, tgFloorA)
	for _, field := range []string{"executor_id", "dispatcher_incarnation", "session_id"} {
		var original string
		if err := f.db.QueryRow("SELECT "+field+" FROM debuglets WHERE uuid = ?", a.id).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.Exec("UPDATE debuglets SET "+field+" = ? WHERE uuid = ?", original+"\x00suffix", a.id); err != nil {
			t.Fatal(err)
		}
		if got := f.d.CollectMetrics(f.ctx).Runs; got.Unavailable != "" || got.Unknown != 1 || got.Pending != 0 {
			t.Fatalf("NUL suffix of %s aliased a live binding: %+v", field, got)
		}
		if _, err := f.db.Exec("UPDATE debuglets SET "+field+" = ? WHERE uuid = ?", original, a.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.db.Exec("UPDATE debuglets SET executor_id = ? WHERE uuid = ?", strings.Repeat("x", metricsExecutorIDLimit+1), a.id); err != nil {
		t.Fatal(err)
	}
	if got := f.d.CollectMetrics(f.ctx).Runs; got.Unavailable != "limit" || got.Admitted != 0 {
		t.Fatalf("oversized identity produced partial metrics: %+v", got)
	}
	registryRegister(t, f.d, strings.Repeat("r", metricsExecutorIDLimit+1))
	if got := f.d.CollectMetrics(f.ctx); got.RegistryUnavailable != "limit" || got.Runs.Unavailable != "registry" {
		t.Fatalf("oversized registry identity: %+v", got)
	}
}

func TestMetricsStorageWaitHoldsNoDispatcherLock(t *testing.T) {
	f := newTGFixture(t, nil)
	connection, err := f.db.Conn(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	before := f.db.Stats().WaitCount
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	done := make(chan ControlMetrics, 1)
	go func() { done <- f.d.CollectMetrics(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for f.db.Stats().WaitCount == before {
		if time.Now().After(deadline) {
			t.Fatal("metrics never reached the occupied database connection")
		}
		runtime.Gosched()
	}
	registry := make(chan struct{})
	go func() { f.d.ExecutorEligibility(); close(registry) }()
	select {
	case <-registry:
	case <-time.After(5 * time.Second):
		t.Fatal("storage observation held the dispatcher lock")
	}
	cancel()
	if got := <-done; got.Runs.Unavailable != "storage" || got.Ready != 1 {
		t.Fatalf("canceled storage observation: %+v", got)
	}
}

func TestMetricsHistoryBoundDoesNotExportPartialTotals(t *testing.T) {
	f := newTGFixture(t, nil)
	_, err := f.db.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < ?)
	INSERT INTO debuglets (uuid, start_time, end_time, usage, ceil_bw, executor_id, state)
	SELECT randomblob(16), ?, ?, 0, 0, 'not-a-label', 5 FROM n`, metricsRunLimit+1, models.NewUTCTime(f.start), models.NewUTCTime(f.start.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	got := f.d.CollectMetrics(f.ctx)
	if got.Runs.Unavailable != "limit" || got.Runs.Admitted != 0 || got.Runs.ReportedSuccess != 0 || got.Ready != 1 {
		t.Fatalf("oversized history: %+v", got)
	}
}
