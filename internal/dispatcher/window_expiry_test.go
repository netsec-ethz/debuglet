// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// weLoop drives a dispatcher's clock and expiry loop by hand.
type weLoop struct {
	clock atomic.Int64
	ticks chan time.Time
}

func newWELoop() *weLoop {
	l := &weLoop{ticks: make(chan time.Time)}
	l.clock.Store(time.Now().UnixNano())
	return l
}

// install is a prepare function: it must run before the loop starts.
func (l *weLoop) install(d *Dispatcher) {
	d.now = func() time.Time { return time.Unix(0, l.clock.Load()) }
	d.newExpiryTicker = func(time.Duration) expiryTicker {
		return &registryTestTicker{ticks: l.ticks, started: make(chan struct{}), stopped: make(chan struct{})}
	}
}

func (l *weLoop) set(at time.Time) { l.clock.Store(at.UnixNano()) }

// tick hands the loop two ticks on an unbuffered channel: the second is taken
// only once the work of the first, including its sweep, has returned.
func (l *weLoop) tick(t *testing.T) {
	t.Helper()
	for range 2 {
		select {
		case l.ticks <- time.Now():
		case <-time.After(tgBound):
			t.Fatal("expiry loop did not take a tick")
		}
	}
}

// weAssertLate checks that late reports for runs classified at the end of
// their window change nothing.
func weAssertLate(t *testing.T, f *tgFixture, runs ...tgDebuglet) {
	t.Helper()
	before := f.snapshot(t)
	for _, run := range runs {
		_ = f.exit(t, run.id, 3, nil)
		_ = f.state(t, run.id, pb.RunState_RUN_STATE_STARTED)
		tgAssertSnapshot(t, f, before, "late report")
		tgAssertReserved(t, f, run, 0)
	}
}

func weAssertUnknown(t *testing.T, f *tgFixture, runs ...tgDebuglet) {
	t.Helper()
	for _, run := range runs {
		tgAssertRow(t, f.row(t, run.id), models.RunStateExited, tgText(outcomeUnknown))
		tgAssertOrder(t, f, run, models.Outstanding)
	}
}

// TestWindowEndClassifiesFailedBatchRuns covers the entry path "failed batch,
// cancellation refused or undelivered": the run is stored as unreconciled and
// keeps its reservation, and once its window has ended by expiredWindowGrace
// the next sweep classifies it with outcome unknown and releases it once.
func TestWindowEndClassifiesFailedBatchRuns(t *testing.T) {
	for _, tc := range []struct {
		name    string
		refusal error
	}{
		{"cancellation undelivered", status.Error(codes.Unavailable, "connection lost")},
		{"cancellation refused", status.Error(codes.NotFound, "debuglet not found")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loop := newWELoop()
			peer := &fbPeer{tgPeer: &tgPeer{}, answer: map[string]error{}}
			f := newFBFixture(t, peer, loop.install)
			a, _ := fbSubmitFailedBatch(t, f, peer, tc.refusal, nil, false)
			tgAssertRow(t, f.row(t, a.id), models.RunStateUnreconciled, tgNull)
			tgAssertReserved(t, f, a, tgFloorA)

			// A window that ended exactly expiredWindowGrace ago is not yet
			// classified.
			end := a.row.EndTime.Time
			loop.set(end.Add(expiredWindowGrace))
			loop.tick(t)
			tgAssertRow(t, f.row(t, a.id), models.RunStateUnreconciled, tgNull)
			tgAssertReserved(t, f, a, tgFloorA)

			loop.set(end.Add(expiredWindowGrace + windowSweepInterval))
			loop.tick(t)
			weAssertUnknown(t, f, a)
			tgAssertReserved(t, f, a, 0)
			tgAssertEarnings(t, f, 0)
			weAssertLate(t, f, a)
		})
	}
}

// TestWindowEndKeepsEarlierReport lets the executor's real exit arrive before
// the sweep: it stays the run's result, the sweep logs no error for the run
// and the effects of the exit ran once.
func TestWindowEndKeepsEarlierReport(t *testing.T) {
	loop := newWELoop()
	core, logs := observer.New(zapcore.ErrorLevel)
	peer := &fbPeer{tgPeer: &tgPeer{}, answer: map[string]error{}}
	f := newFBFixture(t, peer, loop.install, func(d *Dispatcher) { d.logger = zap.New(core) })
	a, _ := fbSubmitFailedBatch(t, f, peer, status.Error(codes.Unavailable, "connection lost"), nil, false)
	if err := f.exit(t, a.id, 3, nil); err != nil {
		t.Fatalf("exit A: %v", err)
	}
	tgAssertReserved(t, f, a, 0)
	before := f.snapshot(t)
	logs.TakeAll() // the failed cancellation of the batch

	loop.set(a.row.EndTime.Time.Add(expiredWindowGrace + time.Second))
	loop.tick(t)
	tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgText("debuglet exited with code 3"))
	tgAssertSnapshot(t, f, before, "sweep after the exit")
	tgAssertReserved(t, f, a, 0)
	if n := logs.FilterField(zap.String("debugletID", a.id.String())).Len(); n != 0 {
		t.Fatalf("sweep logged %d errors for %s: %v", n, a.id, logs.All())
	}
}

// weSeedRestart stores a failed-batch run whose cancellation was not
// delivered and a plain uploaded run, both in the first dispatcher lifetime;
// after a restart the second is on the entry path "session ended before the
// run started", and the first on both.
func weSeedRestart(t *testing.T) (*tgFixture, tgDebuglet, tgDebuglet) {
	t.Helper()
	peer := &fbPeer{tgPeer: &tgPeer{}, answer: map[string]error{}}
	f := newFBFixture(t, peer)
	plain, err := f.submit(t, tgFloorB)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	a, _ := fbSubmitFailedBatch(t, f, peer, status.Error(codes.Unavailable, "connection lost"), nil, false)
	tgAssertRow(t, f.row(t, a.id), models.RunStateUnreconciled, tgNull)
	tgAssertRow(t, f.row(t, plain.id), models.RunStateUploaded, tgNull)
	tgAssertReserved(t, f, a, tgFloorA+tgFloorB)
	return f, a, plain
}

func TestWindowEndClassifiesRunsAfterRestart(t *testing.T) {
	t.Run("window open at restart", func(t *testing.T) {
		f, a, plain := weSeedRestart(t)
		loop := newWELoop()
		g := restartTG(t, f, loop.install)
		if err := g.d.RestoreScheduler(g.ctx); err != nil {
			t.Fatalf("restore: %v", err)
		}
		tgAssertReserved(t, g, a, tgFloorA+tgFloorB)
		loop.set(a.row.EndTime.Time.Add(expiredWindowGrace + time.Second))
		loop.tick(t)
		weAssertUnknown(t, g, a, plain)
		tgAssertReserved(t, g, a, 0)
		weAssertLate(t, g, a, plain)
	})

	t.Run("window ended at restart", func(t *testing.T) {
		f, a, plain := weSeedRestart(t)
		loop := newWELoop()
		loop.set(a.row.EndTime.Time.Add(expiredWindowGrace / 2))
		core, logs := observer.New(zapcore.InfoLevel)
		g := restartTG(t, f, loop.install, func(d *Dispatcher) { d.logger = zap.New(core) })
		if err := g.d.RestoreScheduler(g.ctx); err != nil {
			t.Fatalf("restore: %v", err)
		}
		tgAssertReserved(t, g, a, 0)
		ended := logs.FilterMessage("Not reserving debuglet whose window has ended; it will be classified with outcome unknown")
		for _, run := range []tgDebuglet{a, plain} {
			if ended.FilterField(zap.String("debugletID", run.id.String())).Len() != 1 {
				t.Fatalf("restore did not name %s once: %v", run.id, ended.All())
			}
		}
		loop.set(a.row.EndTime.Time.Add(expiredWindowGrace + time.Second))
		loop.tick(t)
		weAssertUnknown(t, g, a, plain)
		tgAssertReserved(t, g, a, 0)
		weAssertLate(t, g, a, plain)
	})
}

// TestWindowEndSweepsWithoutExecutor restarts the dispatcher with no executor
// registering: the restore alone starts the loop. A run with a complete
// binding (entry path "session ended before the run started") is classified;
// a run stored without one admits no terminal write and keeps its state and
// its reservation.
func TestWindowEndSweepsWithoutExecutor(t *testing.T) {
	f := newTGFixture(t, nil)
	bound := f.seedDirect(t, tgFloorA)
	unbound := f.seedDirect(t, tgFloorB)
	if _, err := f.db.ExecContext(f.ctx, "UPDATE debuglets SET session_id = '' WHERE uuid = ?", unbound.id); err != nil {
		t.Fatal(err)
	}
	loop := newWELoop()
	g := reopenTG(t, f, loop.install)
	if err := g.d.RestoreScheduler(g.ctx); err != nil {
		t.Fatalf("restore: %v", err)
	}
	tgAssertReserved(t, g, bound, tgFloorA+tgFloorB)
	loop.set(bound.row.EndTime.Time.Add(expiredWindowGrace + time.Second))
	loop.tick(t)
	weAssertUnknown(t, g, bound)
	tgAssertRow(t, g.row(t, unbound.id), models.RunStateUploaded, tgNull)
	tgAssertReserved(t, g, bound, tgFloorB)
}
