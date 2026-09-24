// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

// restoreFloorFinished is the floor of the run that finishes before the
// restart. It differs from the floors of the runs left unfinished, so the
// restored total shows which stored runs a restore counted.
const restoreFloorFinished = resource.Bitrate(5000)

// TestRestoreSchedulerSkipsFinishedRuns restarts the dispatcher over a
// database that holds a run finished early through the terminal callback and
// two runs that are pending or of uncertain outcome, all with their scheduled
// end still ahead. The restore reserves the unfinished runs again but not the
// finished one: the capacity its exit released is admitted, and no more.
func TestRestoreSchedulerSkipsFinishedRuns(t *testing.T) {
	const unfinished = tgFloorA + tgFloorB
	f, run := seedRestoreRuns(t)
	g := restartTG(t, f)
	if err := g.d.RestoreScheduler(g.ctx); err != nil {
		t.Fatalf("restore after restart: %v", err)
	}

	// A run that fills the executor next to the unfinished runs fits only if
	// the finished run holds no floor, and one bit more does not fit because
	// the unfinished runs still do.
	if err := restoreAdmit(g, tgCapacity-unfinished); err != nil {
		t.Errorf("released capacity was refused after restore: %v", err)
	}
	if err := restoreAdmit(g, tgCapacity-unfinished+resource.Bit); !errors.Is(err, resource.ErrCapacityFull) {
		t.Errorf("run exceeding the capacity the unfinished runs leave: got %v, want %v", err, resource.ErrCapacityFull)
	}
	tgAssertReserved(t, g, run, unfinished)
}

// TestRestoreSchedulerRestoresOncePerLifetime pins how often a dispatcher
// restores reservations: a restore that fails reserves nothing and can be
// repeated, and once one has succeeded a further call is refused, so no
// stored run is counted twice.
func TestRestoreSchedulerRestoresOncePerLifetime(t *testing.T) {
	const unfinished = tgFloorA + tgFloorB
	f, run := seedRestoreRuns(t)
	g := restartTG(t, f)

	canceled, cancel := context.WithCancel(g.ctx)
	cancel()
	if err := g.d.RestoreScheduler(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("restore with a canceled context: got %v, want %v", err, context.Canceled)
	}
	tgAssertReserved(t, g, run, 0)

	if err := g.d.RestoreScheduler(g.ctx); err != nil {
		t.Fatalf("restore after a failed restore: %v", err)
	}
	restored := g.reserved(t, run)
	if restored != unfinished {
		t.Errorf("restored reservation is %s, want %s", restored, unfinished)
	}
	if err := g.d.RestoreScheduler(g.ctx); err == nil {
		t.Error("second restore in one dispatcher lifetime succeeded, want it refused")
	}
	if got := g.reserved(t, run); got != restored {
		t.Fatalf("second restore changed the reservation from %s to %s", restored, got)
	}
	if err := restoreAdmit(g, tgCapacity-restored); err != nil {
		t.Fatalf("capacity left by the restored runs was refused: %v", err)
	}
}

// seedRestoreRuns stores runs through the admission and callback paths the
// dispatcher uses: a started run that then finishes early, an uploaded run and
// a started run of uncertain outcome. They share the fixture's window, an hour
// ahead, so every scheduled end is still in the future at the restart. It
// returns the fixture and the uploaded run, whose window they all reserve.
func seedRestoreRuns(t *testing.T) (*tgFixture, tgDebuglet) {
	t.Helper()
	f := newTGFixture(t, nil)
	finished := f.seedDirect(t, restoreFloorFinished)
	uploaded := f.seedDirect(t, tgFloorA)
	started := f.seedDirect(t, tgFloorB)
	for _, id := range []uuid.UUID{finished.id, started.id} {
		if err := f.state(t, id, pb.RunState_RUN_STATE_STARTED); err != nil {
			t.Fatalf("start %s: %v", id, err)
		}
	}
	if err := f.exit(t, finished.id, 0, nil); err != nil {
		t.Fatalf("finish %s: %v", finished.id, err)
	}
	tgAssertRow(t, f.row(t, finished.id), models.RunStateExited, tgNull)
	tgAssertRow(t, f.row(t, uploaded.id), models.RunStateUploaded, tgNull)
	tgAssertRow(t, f.row(t, started.id), models.RunStateStarted, tgNull)
	// The winning exit released the finished run's floor in this lifetime.
	tgAssertReserved(t, f, uploaded, tgFloorA+tgFloorB)
	return f, uploaded
}

// restartTG closes the dispatcher of f and opens its database file again under
// a fresh Dispatcher, as a restarted dispatcher process does: only the stored
// rows carry over. The executor registers again, in a new session and with the
// fixture's capacity. Registration leaves the schedule alone, so the caller
// decides when to restore it.
func restartTG(t *testing.T, f *tgFixture) *tgFixture {
	t.Helper()
	f.d.Close()
	var seq int64
	var name, file string
	if err := f.db.QueryRowContext(f.ctx, "PRAGMA database_list").Scan(&seq, &name, &file); err != nil {
		t.Fatalf("locate database file: %v", err)
	}
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=synchronous(OFF)", file))
	if err != nil {
		t.Fatalf("reopen sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close reopened sqlite: %v", err)
		}
	})

	logger := zap.NewNop()
	ph := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)
	d, err := New(logger, db, "tg-restart", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	owner, err := rpc.NewSessionOwner(tgExecutorID, effectTestBinding(t), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := registryRegisterWithSetup(f.ctx, d, owner, &pb.HelloResponse{
		ExecutorId: tgExecutorID, Version: "tg-direct", PricePerBwS: tgPrice, Currency: tgCurrency,
	}, "127.0.0.1"); err != nil {
		t.Fatalf("register executor after restart: %v", err)
	}
	if !owner.MarkRegistered() {
		t.Fatal("executor owner retired before registration completed")
	}
	mutation := effectTestMutation(t, d, tgExecutorID)
	_, err = d.OnResources(f.ctx, mutation, &pb.ResourcesRequest{ExecutorId: tgExecutorID, BandwidthCapacity: int64(tgCapacity)})
	mutation.Finish()
	if err != nil {
		t.Fatalf("set capacity after restart: %v", err)
	}
	return &tgFixture{ctx: f.ctx, db: db, q: database.New(db), ph: ph, d: d, start: f.start}
}

// restoreAdmit is the admission decision SubmitDebuglets takes for a run of
// floor over the fixture's window. It reserves nothing.
func restoreAdmit(f *tgFixture, floor resource.Bitrate) error {
	start := f.start
	spec := models.DebugletSpec{
		StartTime:  &start,
		ExecutorID: tgExecutorID,
		Policy:     models.DebugletPolicy{FloorBW: floor, CeilBW: floor, Timeout: tgTimeout},
	}
	f.d.mu.Lock()
	defer f.d.mu.Unlock()
	_, err := f.d.validateDebugletSpec(&spec)
	return err
}
