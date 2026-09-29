// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"errors"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource/schedule"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSkippedReservationCannotReleaseCurrentRun(t *testing.T) {
	for _, winner := range []string{"cancel before sweep", "sweep before cancel", "concurrent cancel and sweep"} {
		t.Run(winner, func(t *testing.T) {
			const destination = "192.0.2.77"
			f := newTGFixture(t, nil)
			f.d.mu.Lock()
			f.d.scheduler = schedule.New(30 * time.Second)
			f.d.mu.Unlock()
			// The old window ends five seconds into a minute. The next run
			// starts two seconds later and ends before its next 30s boundary:
			// distinct windows, but the old rounded buckets cover the new ones.
			f.start = time.Now().Add(time.Hour).Truncate(time.Minute).Add(-15 * time.Second)
			old := f.seedDirect(t, tgCapacity, destination)
			loop := newWELoop()
			loop.set(old.row.EndTime.Time.Add(time.Second))
			g := restartTG(t, f, loop.install, func(d *Dispatcher) { d.scheduler = schedule.New(30 * time.Second) })
			if err := g.d.RestoreScheduler(g.ctx); err != nil {
				t.Fatal(err)
			}
			tgAssertReserved(t, g, old, 0)
			g.start = old.row.EndTime.Time.Add(2 * time.Second)
			current := g.seedDirect(t, tgCapacity, destination)
			assertCurrent := func() {
				t.Helper()
				tgAssertReserved(t, g, current, tgCapacity)
				if got := g.d.scheduler.QueryMaxDest(destination, current.row.StartTime.Time, current.row.EndTime.Time); got != tgCapacity {
					t.Fatalf("current destination reservation = %s, want %s", got, tgCapacity)
				}
				if err := restoreAdmit(g, bitrate.Bit); !errors.Is(err, resource.ErrCapacityFull) {
					t.Fatalf("over-capacity admission = %v, want capacity refusal", err)
				}
			}
			assertCurrent()
			sweep := func() {
				loop.set(old.row.EndTime.Time.Add(expiredWindowGrace + time.Second))
				g.d.sweepEndedWindows(time.Time{})
			}
			switch winner {
			case "cancel before sweep":
				if err := g.abort(t, old.id, "cancelled via API"); err != nil {
					t.Fatal(err)
				}
				tgAssertRow(t, g.row(t, old.id), models.RunStateExited, tgText(deadCancelError))
				assertCurrent()
				sweep()
			case "sweep before cancel":
				sweep()
				tgAssertRow(t, g.row(t, old.id), models.RunStateExited, tgText(outcomeUnknown))
			case "concurrent cancel and sweep":
				done := make(chan error, 1)
				go func() { done <- g.d.AbortDebuglet(g.ctx, tgExecutorID, old.id, "cancelled via API") }()
				sweep()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				row := g.row(t, old.id)
				if row.State != models.RunStateExited || row.Error != tgText(deadCancelError) && row.Error != tgText(outcomeUnknown) {
					t.Fatalf("no terminal winner: %+v", row)
				}
			}
			assertCurrent()
			before := g.snapshot(t)
			if err := g.abort(t, old.id, "duplicate cancellation"); err != nil {
				t.Fatal(err)
			}
			if err := g.exit(t, old.id, 0, nil); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("old run accepted a report from the new session: %v", err)
			}
			sweep()
			tgAssertSnapshot(t, g, before, "duplicate cancellation, report and sweep")
			assertCurrent()
			if err := g.exit(t, current.id, 0, nil); err != nil {
				t.Fatal(err)
			}
			tgAssertReserved(t, g, current, 0)
			if got := g.d.scheduler.QueryMaxDest(destination, current.row.StartTime.Time, current.row.EndTime.Time); got != 0 {
				t.Fatalf("current exit left destination reservation %s", got)
			}
			before = g.snapshot(t)
			if err := g.exit(t, current.id, 0, nil); err != nil {
				t.Fatal(err)
			}
			tgAssertSnapshot(t, g, before, "duplicate current exit")
			tgAssertReserved(t, g, current, 0)
		})
	}
}

func TestCurrentReservationReleasesAfterClockRollback(t *testing.T) {
	for _, terminal := range []string{"report", "sweep"} {
		t.Run(terminal, func(t *testing.T) {
			loop := newWELoop()
			restoredAt := time.Now().Add(2 * time.Hour)
			loop.set(restoredAt)
			f := newFBFixture(t, &fbPeer{tgPeer: &tgPeer{}, answer: map[string]error{}}, loop.install)
			if err := f.d.RestoreScheduler(f.ctx); err != nil {
				t.Fatal(err)
			}
			// The clock moves backwards after restore. This new admission
			// still owns its floor even though its end precedes restoredAt.
			loop.set(f.start.Add(-time.Minute))
			run := f.seedDirect(t, tgFloorA, "192.0.2.77")
			if run.row.DispatcherIncarnation != f.d.incarnation || run.row.EndTime.Time.After(restoredAt) {
				t.Fatal("fixture must admit a current-incarnation run ending before restore time")
			}
			tgAssertReserved(t, f, run, tgFloorA)
			if terminal == "report" {
				if err := f.exit(t, run.id, 0, nil); err != nil {
					t.Fatal(err)
				}
			} else {
				loop.set(run.row.EndTime.Time.Add(expiredWindowGrace + time.Second))
				f.d.sweepEndedWindows(time.Time{})
				weAssertUnknown(t, f, run)
			}
			tgAssertReserved(t, f, run, 0)
			if got := f.d.scheduler.QueryMaxDest("192.0.2.77", run.row.StartTime.Time, run.row.EndTime.Time); got != 0 {
				t.Fatalf("terminal settlement left destination reservation %s", got)
			}
		})
	}
}
