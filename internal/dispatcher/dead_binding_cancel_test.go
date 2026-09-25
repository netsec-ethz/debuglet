// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// deadCancelError is the stored error of a run cancelled through the API after
// its control session had ended.
const deadCancelError = "cancelled via API; the control session had ended and the executor's outcome was not observed"

// assertCancelledWithoutSession checks the state a cancellation of a run whose
// session has ended leaves: the run is exited with the cancellation error, its
// reservation is released, the order keeps what a nonzero exit gives a TEST
// order, and a repeated cancellation or a late exit changes nothing.
func assertCancelledWithoutSession(t *testing.T, f *tgFixture, run tgDebuglet) {
	t.Helper()
	tgAssertRow(t, f.row(t, run.id), models.RunStateExited, tgText(deadCancelError))
	tgAssertReserved(t, f, run, 0)
	tgAssertOrder(t, f, run, models.Outstanding)

	before := f.snapshot(t)
	if err := f.abort(t, run.id, "cancelled via API"); err != nil {
		t.Fatalf("second cancellation: %v", err)
	}
	tgAssertSnapshot(t, f, before, "second cancellation")
	tgAssertReserved(t, f, run, 0)
	if err := f.exit(t, run.id, 0, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("exit through the current session after the cancellation: got %v, want %s", err, codes.PermissionDenied)
	}
	tgAssertSnapshot(t, f, before, "exit after the cancellation")
	tgAssertReserved(t, f, run, 0)
}

// TestCancelAfterDispatcherRestartRecordsTheCancellation cancels a run stored by
// a previous dispatcher lifetime. The restarted dispatcher has no transport
// client for the executor, so the cancellation succeeds only because it is
// recorded without contacting one.
func TestCancelAfterDispatcherRestartRecordsTheCancellation(t *testing.T) {
	f := newTGFixture(t, nil)
	run := f.seedDirect(t, tgFloorA)
	g := restartTG(t, f)
	if err := g.d.RestoreScheduler(g.ctx); err != nil {
		t.Fatalf("restore after restart: %v", err)
	}
	tgAssertReserved(t, g, run, tgFloorA)
	tgAssertOrder(t, g, run, models.Outstanding)

	if err := g.abort(t, run.id, "cancelled via API"); err != nil {
		t.Fatalf("cancellation after restart: %v", err)
	}
	assertCancelledWithoutSession(t, g, run)
}

// TestCancelAfterSessionReplacementRecordsTheCancellation cancels a run whose
// executor has registered again under a new session of the same dispatcher.
// No Abort reaches the executor.
func TestCancelAfterSessionReplacementRecordsTheCancellation(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	run, err := f.submit(t, tgFloorA)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	tgAssertReserved(t, f, run, tgFloorA)

	owner, err := rpc.NewSessionOwner(tgExecutorID, effectTestBinding(t), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := registryRegisterWithSetup(f.ctx, f.d, owner, &pb.HelloResponse{
		ExecutorId: tgExecutorID, Version: "tg-direct", PricePerBwS: tgPrice, Currency: tgCurrency,
	}, "127.0.0.1"); err != nil {
		t.Fatalf("register replacement session: %v", err)
	}
	if !owner.MarkRegistered() {
		t.Fatal("replacement owner retired before registration completed")
	}
	mutation := effectTestMutation(t, f.d, tgExecutorID)
	_, err = f.d.OnResources(f.ctx, mutation, &pb.ResourcesRequest{ExecutorId: tgExecutorID, BandwidthCapacity: int64(tgCapacity)})
	mutation.Finish()
	if err != nil {
		t.Fatalf("set capacity of the replacement session: %v", err)
	}

	if err := f.abort(t, run.id, "cancelled via API"); err != nil {
		t.Fatalf("cancellation after session replacement: %v", err)
	}
	assertCancelledWithoutSession(t, f, run)
	if aborts := peer.recordedAborts(); len(aborts) != 0 {
		t.Fatalf("executor received %d Abort requests, want none", len(aborts))
	}
}

// TestCancelWithLiveSessionStillAbortsRemotely is the cancellation of a run
// whose session is live: the executor receives the Abort and the run records
// the caller's reason.
func TestCancelWithLiveSessionStillAbortsRemotely(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	run, err := f.submit(t, tgFloorA)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := f.abort(t, run.id, "cancelled via API"); err != nil {
		t.Fatalf("cancellation: %v", err)
	}
	aborts := peer.recordedAborts()
	if len(aborts) != 1 || aborts[0].GetDebugletId() != run.id.String() {
		t.Fatalf("executor received Abort requests %v, want one for %s", aborts, run.id)
	}
	tgAssertRow(t, f.row(t, run.id), models.RunStateExited, tgText("cancelled via API"))
	tgAssertReserved(t, f, run, 0)
}

// TestRestoreSchedulerNamesRunsOfAPreviousLifetime restores a schedule holding
// a finished run, an unfinished run of a previous dispatcher lifetime and an
// unfinished run bound to the restoring lifetime. Only the run of the previous
// lifetime is named, and every unfinished run keeps its reservation.
func TestRestoreSchedulerNamesRunsOfAPreviousLifetime(t *testing.T) {
	f := newTGFixture(t, nil)
	finished := f.seedDirect(t, restoreFloorFinished)
	previous := f.seedDirect(t, tgFloorA)
	current := f.seedDirect(t, tgFloorB)
	if err := f.exit(t, finished.id, 0, nil); err != nil {
		t.Fatalf("finish %s: %v", finished.id, err)
	}

	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)
	ph := payments.NewPaymentHandler(f.db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)
	d, err := New(logger, f.db, "tg-restart", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	if _, err := f.db.ExecContext(f.ctx, "UPDATE debuglets SET dispatcher_incarnation = ? WHERE uuid = ?", d.ControlIncarnation(), current.id); err != nil {
		t.Fatalf("bind %s to the restoring lifetime: %v", current.id, err)
	}
	if err := d.RestoreScheduler(f.ctx); err != nil {
		t.Fatalf("restore: %v", err)
	}

	warned := logs.FilterLevelExact(zapcore.WarnLevel).All()
	if len(warned) != 1 {
		t.Fatalf("restore logged %d warnings, want 1: %v", len(warned), warned)
	}
	fields := warned[0].ContextMap()
	if fields["debugletID"] != previous.id.String() || fields["executor"] != tgExecutorID {
		t.Fatalf("warning names %v, want run %s on %s", fields, previous.id, tgExecutorID)
	}
	for _, key := range []string{"from", "to"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("warning has no %q field: %v", key, fields)
		}
	}
	if got := d.scheduler.QueryMaxExec(tgExecutorID, previous.row.StartTime.Time, previous.row.EndTime.Time); got != tgFloorA+tgFloorB {
		t.Fatalf("restored reservation is %s, want %s", got, tgFloorA+tgFloorB)
	}
}

// TestCancelWithoutStoredBindingIsRefused cancels a run stored without a
// control binding, as rows written before bindings were recorded are. There is
// no binding to record the cancellation under, so it is refused and changes
// nothing.
func TestCancelWithoutStoredBindingIsRefused(t *testing.T) {
	f := newTGFixture(t, nil)
	run := f.seedDirect(t, tgFloorA)
	if _, err := f.db.ExecContext(f.ctx, "UPDATE debuglets SET dispatcher_incarnation = '', session_id = '' WHERE uuid = ?", run.id); err != nil {
		t.Fatalf("clear the binding of %s: %v", run.id, err)
	}
	before := f.snapshot(t)
	err := f.abort(t, run.id, "cancelled via API")
	if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "run has no control binding to cancel under" {
		t.Fatalf("cancellation of a run without a binding: got %v, want %s", err, codes.FailedPrecondition)
	}
	tgAssertSnapshot(t, f, before, "refused cancellation")
	tgAssertReserved(t, f, run, tgFloorA)
}
