// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestReclamationFencesDelayedAllocateAcrossClockRollbackAndRestart(t *testing.T) {
	loop := newWELoop()
	f := newFBFixture(t, &fbPeer{tgPeer: &tgPeer{}, answer: map[string]error{}}, loop.install)
	run := f.seedDirect(t, tgFloorA)
	const destination = "192.0.2.130"
	allocationBind(t, f, run, destination)
	mutation := effectTestMutation(t, f.d, tgExecutorID)
	defer mutation.Finish()
	request := allocationRequest(t, f, run)
	if _, err := f.d.OnDebugletAllocate(f.ctx, mutation, request); err != nil {
		t.Fatal(err)
	}
	before := f.row(t, run.id)
	loop.set(run.row.EndTime.Time.Add(expiredWindowGrace + time.Second))
	f.d.sweepEndedWindows(time.Time{})
	weAssertReclaimed(t, f, run)
	after := f.row(t, run.id)
	if before.State != after.State || before.Error != after.Error {
		t.Fatal("reclamation changed stored outcome")
	}
	allocationCharged(t, f.d, destination, 0)
	first, err := f.q.GetAllocationReclamation(f.ctx, run.id)
	if err != nil {
		t.Fatal(err)
	}
	loop.set(run.row.StartTime.Time)
	if _, err := f.d.OnDebugletAllocate(f.ctx, mutation, request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("late allocate: %v", err)
	}
	allocationCharged(t, f.d, destination, 0)
	mutation.Finish()
	// Actual evidence is independent of the accounting record.
	if err := f.exit(t, run.id, 0, nil); err != nil {
		t.Fatal(err)
	}
	tgAssertRow(t, f.row(t, run.id), models.RunStateExited, tgNull)
	doc, err := f.d.Recovery(f.ctx, run.id)
	if err != nil || doc.AllocationReclaimedAt == nil || !doc.AllocationReclaimedAt.Equal(first.Time) {
		t.Fatalf("recovery reclamation: %+v, %v", doc, err)
	}
	g := restartTG(t, f, loop.install)
	if err := g.d.RestoreScheduler(g.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := database.New(g.db).GetAllocationReclamation(g.ctx, run.id); err != nil {
		t.Fatal(err)
	}
	tgAssertReserved(t, g, run, 0)
}

func TestCommittedReclamationReleaseRetriesWithoutAnotherWrite(t *testing.T) {
	loop := newWELoop()
	f := newFBFixture(t, &fbPeer{tgPeer: &tgPeer{}, answer: map[string]error{}}, loop.install)
	run := f.seedDirect(t, tgFloorA)
	now := run.row.EndTime.Time.Add(expiredWindowGrace + time.Second)
	loop.set(now)
	// A write committed before its caller released in-memory resources.
	if err := f.q.ReclaimAllocation(f.ctx, database.ReclaimAllocationParams{Uuid: run.id, ReclaimedAt: models.NewUTCTime(now), ExitedState: models.RunStateExited, ExecutorID: run.row.ExecutorID, DispatcherIncarnation: run.row.DispatcherIncarnation, SessionID: run.row.SessionID}); err != nil {
		t.Fatal(err)
	}
	tgAssertReserved(t, f, run, tgFloorA)
	f.d.sweepEndedWindows(time.Time{})
	tgAssertReserved(t, f, run, 0)
	first, err := f.q.GetAllocationReclamation(f.ctx, run.id)
	if err != nil {
		t.Fatal(err)
	}
	loop.set(now.Add(time.Minute))
	f.d.sweepEndedWindows(time.Time{})
	again, err := f.q.GetAllocationReclamation(f.ctx, run.id)
	if err != nil || !again.Time.Equal(first.Time) {
		t.Fatalf("repeated cleanup rewrote durable fact: %v, %v", again, err)
	}
	weAssertReclaimed(t, f, run)
	loop.set(run.row.StartTime.Time)
	g := restartTG(t, f, loop.install)
	if err := g.d.RestoreScheduler(g.ctx); err != nil {
		t.Fatal(err)
	}
	tgAssertReserved(t, g, run, 0)
	weAssertReclaimed(t, g, run)
}

func TestLostSessionReclamationKeepsReplacementAllocation(t *testing.T) {
	loop := newWELoop()
	f := newFBFixture(t, &fbPeer{tgPeer: &tgPeer{}, answer: map[string]error{}}, loop.install)
	const destination = "192.0.2.131"
	old := f.seedDirect(t, tgFloorA)
	allocationBind(t, f, old, destination)
	original := effectTestMutation(t, f.d, tgExecutorID)
	if _, err := f.d.OnDebugletAllocate(f.ctx, original, allocationRequest(t, f, old)); err != nil {
		t.Fatal(err)
	}
	original.Finish()
	original.Owner().Retire()
	registryRegister(t, f.d, tgExecutorID)
	current := effectTestMutation(t, f.d, tgExecutorID)
	defer current.Finish()
	if _, err := f.d.OnResources(f.ctx, current, &pb.ResourcesRequest{ExecutorId: tgExecutorID, BandwidthCapacity: int64(tgCapacity)}); err != nil {
		t.Fatal(err)
	}
	f.start = old.row.EndTime.Time.Add(expiredWindowGrace - tgTimeout)
	replacement := f.seedDirect(t, tgFloorB)
	allocationBind(t, f, replacement, destination)
	loop.set(replacement.row.StartTime.Time)
	// The replacement fixture has no reverse transport yet. Its accounted
	// allocation survives that explicit delivery failure until its own release.
	if _, err := f.d.OnDebugletAllocate(f.ctx, current, allocationRequest(t, f, replacement)); status.Code(err) != codes.Unavailable {
		t.Fatalf("replacement allocation: %v", err)
	}
	allocationCharged(t, f.d, destination, tgFloorA+tgFloorB)
	loop.set(old.row.EndTime.Time.Add(expiredWindowGrace + time.Second))
	f.d.sweepEndedWindows(time.Time{})
	allocationCharged(t, f.d, destination, tgFloorB)
	weAssertReclaimed(t, f, old)
	if _, err := f.d.OnDebugletExit(f.ctx, current, &pb.DebugletExitRequest{DebugletId: old.id.String()}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("late old report: %v", err)
	}
	f.d.sweepEndedWindows(time.Time{})
	allocationCharged(t, f.d, destination, tgFloorB)
	if _, err := f.d.OnDebugletExit(f.ctx, current, &pb.DebugletExitRequest{DebugletId: replacement.id.String()}); err != nil {
		t.Fatal(err)
	}
	allocationCharged(t, f.d, destination, 0)
}
