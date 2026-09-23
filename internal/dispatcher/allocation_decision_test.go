package dispatcher

import (
	"context"
	"errors"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource/schedule"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// allocationBind stores the destinations of an admitted run the way a
// submission does, so the executor's request can repeat that policy.
func allocationBind(t *testing.T, f *tgFixture, deb tgDebuglet, addresses ...string) {
	t.Helper()
	if _, err := f.db.ExecContext(f.ctx, "UPDATE debuglets SET addresses = ? WHERE uuid = ?", models.CommaSeparatedList(addresses), deb.id); err != nil {
		t.Fatal(err)
	}
}

// allocationRequest is the request an executor sends after an upload: it
// repeats the admitted policy of the run exactly.
func allocationRequest(t *testing.T, f *tgFixture, deb tgDebuglet) *pb.DebugletAllocateRequest {
	t.Helper()
	row := f.row(t, deb.id)
	return &pb.DebugletAllocateRequest{
		DebugletId: deb.id.String(), ExecutorId: tgExecutorID, TransactionId: row.TransactionID,
		Policy: &pb.DebugletPolicy{Addresses: []string(row.Addresses), FloorBw: row.Usage, CeilBw: row.CeilBw},
	}
}

// allocationFairshare is the executor-to-limit result the dispatcher would
// currently publish for a destination.
func allocationFairshare(t *testing.T, d *Dispatcher, destination string) map[string]resource.Bitrate {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	return maps.Collect(d.destinations.Fairshare(destination))
}

// allocationCharged brackets the floor charged on a destination: with the
// destination limit at want, one more bit no longer fits while the existing
// charge still does. Together that pins the charged floor to want. The limit
// in force is restored before returning.
func allocationCharged(t *testing.T, d *Dispatcher, destination string, want resource.Bitrate) {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	previous := d.destinations.Cap(destination)
	defer d.destinations.SetLimit(destination, previous)
	d.destinations.SetLimit(destination, want)
	if err := d.destinations.CheckCapacity(destination, 0); err != nil {
		t.Fatalf("charged floor on %s is above %s: %v", destination, want, err)
	}
	if err := d.destinations.CheckCapacity(destination, 1); !errors.Is(err, resource.ErrCapacityFull) {
		t.Fatalf("charged floor on %s is below %s: %v", destination, want, err)
	}
}

func allocationTracked(t *testing.T, d *Dispatcher) int {
	t.Helper()
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.destinations.Len()
}

// TestAllocateRepeatsOneDecisionPerRun states that repeated and concurrent
// allocation requests of one run add a single floor and residual allocation,
// and that the single terminal release returns the totals it charged.
func TestAllocateRepeatsOneDecisionPerRun(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	deb := f.seedDirect(t, tgFloorA)
	const destination = "192.0.2.20"
	allocationBind(t, f, deb, destination)
	// The destination is roomy enough for every repeat to be admitted, so a
	// repeat that charged again would show up as a changed decision instead
	// of as a rejection.
	f.d.SetDestinationLimit(destination, 10*tgFloorA)
	client := allocationClient(t, f.d)
	req := allocationRequest(t, f, deb)
	ctx, cancel := context.WithTimeout(f.ctx, tgCallBound)
	defer cancel()
	if _, err := client.DebugletAllocate(ctx, req); err != nil {
		t.Fatalf("first allocation: %v", err)
	}
	decision := allocationFairshare(t, f.d, destination)
	if want := map[string]resource.Bitrate{tgExecutorID: 2 * tgFloorA}; !maps.Equal(decision, want) {
		t.Fatalf("allocation decision %v, want %v", decision, want)
	}

	const repeats = 8
	failures := make(chan error, repeats+1)
	var group sync.WaitGroup
	for range repeats {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := client.DebugletAllocate(ctx, req); err != nil {
				failures <- err
			}
		}()
	}
	group.Wait()
	if _, err := client.DebugletAllocate(ctx, req); err != nil {
		failures <- err
	}
	close(failures)
	for err := range failures {
		t.Fatalf("repeated allocation of the same run: %v", err)
	}
	if got := allocationFairshare(t, f.d, destination); !maps.Equal(got, decision) {
		t.Fatalf("repeats changed the decision to %v, want %v", got, decision)
	}
	allocationCharged(t, f.d, destination, tgFloorA)
	if got := allocationTracked(t, f.d); got != 1 {
		t.Fatalf("repeats tracked %d executor allocations, want 1", got)
	}

	// One terminal release returns the totals to their original values.
	if err := f.exit(t, deb.id, 0, nil); err != nil {
		t.Fatalf("terminal release: %v", err)
	}
	if got := allocationTracked(t, f.d); got != 0 {
		t.Fatalf("%d executor allocations remain after the release", got)
	}
	if got := allocationFairshare(t, f.d, destination); len(got) != 0 {
		t.Fatalf("fairshare after the release = %v, want empty", got)
	}
	f.d.mu.Lock()
	err := f.d.destinations.CheckCapacity(destination, tgFloorA)
	f.d.mu.Unlock()
	if err != nil {
		t.Fatalf("capacity not returned by the release: %v", err)
	}
}

// TestAllocateRejectsChangedPolicy states that a request which does not repeat
// the admitted policy is rejected before anything changes, and can neither
// alter the admitted decision of its own run nor the capacity of another.
func TestAllocateRejectsChangedPolicy(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	first := f.seedDirect(t, tgFloorA)
	second := f.seedDirect(t, tgFloorA)
	const destination, unrelated = "192.0.2.21", "192.0.2.22"
	allocationBind(t, f, first, destination)
	allocationBind(t, f, second, destination)
	f.d.SetDestinationLimit(destination, 2*tgFloorA)
	client := allocationClient(t, f.d)
	ctx, cancel := context.WithTimeout(f.ctx, tgCallBound)
	defer cancel()
	for _, deb := range []tgDebuglet{first, second} {
		if _, err := client.DebugletAllocate(ctx, allocationRequest(t, f, deb)); err != nil {
			t.Fatalf("admitted allocation: %v", err)
		}
	}
	admitted := allocationFairshare(t, f.d, destination)
	if want := map[string]resource.Bitrate{tgExecutorID: 2 * tgFloorA}; !maps.Equal(admitted, want) {
		t.Fatalf("admitted fairshare %v, want %v", admitted, want)
	}

	for _, tc := range []struct {
		name   string
		change func(*pb.DebugletPolicy)
	}{
		{"raised floor", func(p *pb.DebugletPolicy) { p.FloorBw = int64(2 * tgFloorA) }},
		{"lowered floor", func(p *pb.DebugletPolicy) { p.FloorBw = 1 }},
		{"raised ceiling", func(p *pb.DebugletPolicy) { p.CeilBw = int64(8 * tgFloorA) }},
		{"added destination", func(p *pb.DebugletPolicy) { p.Addresses = append(p.Addresses, unrelated) }},
		{"replaced destination", func(p *pb.DebugletPolicy) { p.Addresses = []string{unrelated} }},
		{"dropped destinations", func(p *pb.DebugletPolicy) { p.Addresses = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := allocationRequest(t, f, first)
			tc.change(req.Policy)
			if _, err := client.DebugletAllocate(ctx, req); status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("changed policy accepted with %v", err)
			}
			if got := allocationFairshare(t, f.d, destination); !maps.Equal(got, admitted) {
				t.Fatalf("changed policy altered capacity to %v, want %v", got, admitted)
			}
			if got := allocationFairshare(t, f.d, unrelated); len(got) != 0 {
				t.Fatalf("changed policy allocated %s: %v", unrelated, got)
			}
			if got := allocationTracked(t, f.d); got != 1 {
				t.Fatalf("changed policy tracked %d executor allocations, want 1", got)
			}
		})
	}
	allocationCharged(t, f.d, destination, 2*tgFloorA)

	// Both admitted runs release exactly what they charged.
	for _, deb := range []tgDebuglet{first, second} {
		if err := f.exit(t, deb.id, 0, nil); err != nil {
			t.Fatalf("terminal release: %v", err)
		}
	}
	if got := allocationTracked(t, f.d); got != 0 {
		t.Fatalf("%d executor allocations remain after both releases", got)
	}
}

// TestAllocateRetryKeepsFencing states that the retry of an ambiguous
// allocation returns the same decision under the original session, while every
// existing ownership, identity and session check still rejects the retry.
func TestAllocateRetryKeepsFencing(t *testing.T) {
	f := newTGFixture(t, nil)
	deb := f.seedDirect(t, tgFloorA)
	const destination = "192.0.2.23"
	allocationBind(t, f, deb, destination)
	f.d.SetDestinationLimit(destination, 10*tgFloorA)
	req := allocationRequest(t, f, deb)
	ctx, cancel := context.WithTimeout(f.ctx, tgCallBound)
	defer cancel()

	mutation := effectTestMutation(t, f.d, tgExecutorID)
	if _, err := f.d.OnDebugletAllocate(ctx, mutation, req); err != nil {
		t.Fatalf("first allocation: %v", err)
	}
	decision := allocationFairshare(t, f.d, destination)
	if want := map[string]resource.Bitrate{tgExecutorID: 2 * tgFloorA}; !maps.Equal(decision, want) {
		t.Fatalf("allocation decision %v, want %v", decision, want)
	}
	// The ambiguous response is retried on a fresh ticket of the same session.
	retry := effectTestMutation(t, f.d, tgExecutorID)
	if _, err := f.d.OnDebugletAllocate(ctx, retry, req); err != nil {
		t.Fatalf("retry under the original session: %v", err)
	}
	if got := allocationFairshare(t, f.d, destination); !maps.Equal(got, decision) {
		t.Fatalf("retry changed the decision to %v, want %v", got, decision)
	}
	allocationCharged(t, f.d, destination, tgFloorA)

	foreign := allocationRequest(t, f, deb)
	foreign.ExecutorId = "other-executor"
	if _, err := f.d.OnDebugletAllocate(ctx, retry, foreign); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("retry claiming another executor: %v", err)
	}
	stale := allocationRequest(t, f, deb)
	stale.TransactionId = "not-the-stored-transaction"
	if _, err := f.d.OnDebugletAllocate(ctx, retry, stale); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("retry with another transaction: %v", err)
	}
	unowned := allocationRequest(t, f, deb)
	unowned.DebugletId = uuid.New().String()
	if _, err := f.d.OnDebugletAllocate(ctx, retry, unowned); status.Code(err) != codes.NotFound {
		t.Fatalf("retry of an unknown run: %v", err)
	}

	// A replacement session of the same executor cannot retry the run.
	f.d.mu.RLock()
	original := f.d.executors[tgExecutorID].owner
	f.d.mu.RUnlock()
	original.Retire()
	registryRegister(t, f.d, tgExecutorID)
	replacement := effectTestMutation(t, f.d, tgExecutorID)
	if _, err := f.d.OnDebugletAllocate(ctx, replacement, req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("retry under a replacement session: %v", err)
	}
	if got := allocationFairshare(t, f.d, destination); !maps.Equal(got, decision) {
		t.Fatalf("rejected retries changed the decision to %v, want %v", got, decision)
	}
	allocationCharged(t, f.d, destination, tgFloorA)
}

// TestAllocateCommitsEveryDestinationAtomically states that a run whose later
// destination cannot be charged leaves no partial allocation, that the same
// request holds completely once the destination admits it, and that the
// terminal release returns every destination it charged.
func TestAllocateCommitsEveryDestinationAtomically(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	deb := f.seedDirect(t, tgFloorA)
	const first, blocked = "192.0.2.24", "192.0.2.25"
	allocationBind(t, f, deb, first, blocked)
	f.d.SetDestinationLimit(first, 10*tgFloorA)
	f.d.SetDestinationLimit(blocked, tgFloorA-1)
	client := allocationClient(t, f.d)
	ctx, cancel := context.WithTimeout(f.ctx, tgCallBound)
	defer cancel()

	_, err := client.DebugletAllocate(ctx, allocationRequest(t, f, deb))
	if err == nil || !strings.Contains(err.Error(), "allocate destinations") {
		t.Fatalf("allocation over a full destination = %v", err)
	}
	if got := allocationTracked(t, f.d); got != 0 {
		t.Fatalf("failed allocation tracked %d executor allocations, want 0", got)
	}
	for _, destination := range []string{first, blocked} {
		if got := allocationFairshare(t, f.d, destination); len(got) != 0 {
			t.Fatalf("failed allocation left %s at %v", destination, got)
		}
		allocationCharged(t, f.d, destination, 0)
	}

	f.d.SetDestinationLimit(blocked, 10*tgFloorA)
	if _, err := client.DebugletAllocate(ctx, allocationRequest(t, f, deb)); err != nil {
		t.Fatalf("allocation after the destination admits it: %v", err)
	}
	want := map[string]resource.Bitrate{tgExecutorID: 2 * tgFloorA}
	for _, destination := range []string{first, blocked} {
		if got := allocationFairshare(t, f.d, destination); !maps.Equal(got, want) {
			t.Fatalf("fairshare of %s = %v, want %v", destination, got, want)
		}
		allocationCharged(t, f.d, destination, tgFloorA)
	}
	if got := allocationTracked(t, f.d); got != 2 {
		t.Fatalf("allocation tracked %d executor allocations, want 2", got)
	}

	if err := f.exit(t, deb.id, 0, nil); err != nil {
		t.Fatalf("terminal release: %v", err)
	}
	if got := allocationTracked(t, f.d); got != 0 {
		t.Fatalf("%d executor allocations remain after the release", got)
	}
	for _, destination := range []string{first, blocked} {
		if got := allocationFairshare(t, f.d, destination); len(got) != 0 {
			t.Fatalf("fairshare of %s after the release = %v", destination, got)
		}
		allocationCharged(t, f.d, destination, 0)
	}
}

// TestAllocateChargesRepeatedDestinationsOnce states that a repeated
// destination of an admitted policy is charged once, and that repeating the
// request is admitted even while that destination is exactly full.
func TestAllocateChargesRepeatedDestinationsOnce(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	deb := f.seedDirect(t, tgFloorA)
	const destination = "192.0.2.26"
	allocationBind(t, f, deb, destination, destination)
	// The destination admits exactly one floor of this run, so a second
	// charge for the same run cannot fit.
	f.d.SetDestinationLimit(destination, tgFloorA)
	client := allocationClient(t, f.d)
	ctx, cancel := context.WithTimeout(f.ctx, tgCallBound)
	defer cancel()
	req := allocationRequest(t, f, deb)
	for i := range 3 {
		if _, err := client.DebugletAllocate(ctx, req); err != nil {
			t.Fatalf("allocation %d of a repeated destination: %v", i, err)
		}
	}
	if got, want := allocationFairshare(t, f.d, destination), (map[string]resource.Bitrate{tgExecutorID: tgFloorA}); !maps.Equal(got, want) {
		t.Fatalf("fairshare of a repeated destination = %v, want %v", got, want)
	}
	allocationCharged(t, f.d, destination, tgFloorA)
	if got := allocationTracked(t, f.d); got != 1 {
		t.Fatalf("repeated destination tracked %d executor allocations, want 1", got)
	}
	if err := f.exit(t, deb.id, 0, nil); err != nil {
		t.Fatalf("terminal release: %v", err)
	}
	if got := allocationTracked(t, f.d); got != 0 {
		t.Fatalf("%d executor allocations remain after the release", got)
	}
	allocationCharged(t, f.d, destination, 0)
}

// TestExitKeepsFloorOnlySiblingRun states that the exit of one run leaves a
// sibling run of the same executor and destination allocated with its floor,
// even when neither of them leaves residual bandwidth to share, and that the
// last exit empties the destination accounting.
func TestExitKeepsFloorOnlySiblingRun(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	first := f.seedDirect(t, tgFloorA)
	second := f.seedDirect(t, tgFloorA)
	const destination = "192.0.2.27"
	for _, deb := range []tgDebuglet{first, second} {
		allocationBind(t, f, deb, destination)
		// A run whose ceiling equals its floor has no residual bandwidth.
		if _, err := f.db.ExecContext(f.ctx, "UPDATE debuglets SET ceil_bw = usage WHERE uuid = ?", deb.id); err != nil {
			t.Fatal(err)
		}
	}
	f.d.SetDestinationLimit(destination, 10*tgFloorA)
	client := allocationClient(t, f.d)
	ctx, cancel := context.WithTimeout(f.ctx, tgCallBound)
	defer cancel()
	for _, deb := range []tgDebuglet{first, second} {
		if _, err := client.DebugletAllocate(ctx, allocationRequest(t, f, deb)); err != nil {
			t.Fatalf("allocate floor-only run: %v", err)
		}
	}
	if got, want := allocationFairshare(t, f.d, destination), (map[string]resource.Bitrate{tgExecutorID: 2 * tgFloorA}); !maps.Equal(got, want) {
		t.Fatalf("fairshare of both floor-only runs = %v, want %v", got, want)
	}

	if err := f.exit(t, first.id, 0, nil); err != nil {
		t.Fatalf("terminal release of the first run: %v", err)
	}
	if got, want := allocationFairshare(t, f.d, destination), (map[string]resource.Bitrate{tgExecutorID: tgFloorA}); !maps.Equal(got, want) {
		t.Fatalf("fairshare after one exit = %v, want %v", got, want)
	}
	allocationCharged(t, f.d, destination, tgFloorA)
	if got := allocationTracked(t, f.d); got != 1 {
		t.Fatalf("%d executor allocations after one exit, want 1", got)
	}

	if err := f.exit(t, second.id, 0, nil); err != nil {
		t.Fatalf("terminal release of the second run: %v", err)
	}
	if got := allocationFairshare(t, f.d, destination); len(got) != 0 {
		t.Fatalf("fairshare after the last exit = %v", got)
	}
	if got := allocationTracked(t, f.d); got != 0 {
		t.Fatalf("%d executor allocations remain after the last exit", got)
	}
	allocationCharged(t, f.d, destination, 0)
}

// TestAllocateRejectsTerminalRun states that an allocation arriving after the
// terminal exit of its run is rejected: the exit has already released
// everything the run held, and nothing would ever release a later charge.
func TestAllocateRejectsTerminalRun(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	deb := f.seedDirect(t, tgFloorA)
	const destination = "192.0.2.28"
	allocationBind(t, f, deb, destination)
	f.d.SetDestinationLimit(destination, 10*tgFloorA)
	client := allocationClient(t, f.d)
	req := allocationRequest(t, f, deb)
	ctx, cancel := context.WithTimeout(f.ctx, tgCallBound)
	defer cancel()
	if _, err := client.DebugletAllocate(ctx, req); err != nil {
		t.Fatalf("allocation before the exit: %v", err)
	}
	if err := f.exit(t, deb.id, 0, nil); err != nil {
		t.Fatalf("terminal release: %v", err)
	}
	if err := f.exit(t, deb.id, 0, nil); err != nil {
		t.Fatalf("duplicate terminal release: %v", err)
	}

	if _, err := client.DebugletAllocate(ctx, req); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "run is terminal") {
		t.Fatalf("allocation after the exit = %v", err)
	}
	if got := allocationTracked(t, f.d); got != 0 {
		t.Fatalf("%d executor allocations after the late allocation, want 0", got)
	}
	if got := allocationFairshare(t, f.d, destination); len(got) != 0 {
		t.Fatalf("fairshare after the late allocation = %v", got)
	}
	allocationCharged(t, f.d, destination, 0)
}

func TestAllocateRejectsExitDuringPaymentCheck(t *testing.T) {
	f := newTGFixture(t, nil)
	deb := f.seedDirect(t, tgFloorA)
	const destination = "192.0.2.29"
	allocationBind(t, f, deb, destination)
	req := allocationRequest(t, f, deb)
	core, _ := observer.New(zap.DebugLevel)
	exited := false
	f.d.logger = zap.New(core, zap.Hooks(func(entry zapcore.Entry) error {
		if entry.Message != "Received debuglet allocation request" {
			return nil
		}
		// The handler has read the admitted policy, but has not charged it.
		// Complete cancellation now, before its payment check resumes.
		if err := f.exit(t, deb.id, -1, tgStr("cancelled during allocation")); err != nil {
			t.Fatalf("terminal callback: %v", err)
		}
		exited = true
		return nil
	}))
	mutation := effectTestMutation(t, f.d, tgExecutorID)
	defer mutation.Finish()
	if _, err := f.d.OnDebugletAllocate(f.ctx, mutation, req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("allocation interrupted by exit = %v, want FailedPrecondition", err)
	}
	if !exited || f.row(t, deb.id).State != models.RunStateExited {
		t.Fatal("terminal callback did not complete during allocation")
	}
	if got := allocationTracked(t, f.d); got != 0 {
		t.Fatalf("%d allocations remain after exit interrupted allocation, want 0", got)
	}
	if err := f.exit(t, deb.id, -1, tgStr("duplicate cancellation")); err != nil {
		t.Fatalf("duplicate terminal callback: %v", err)
	}
	if got := allocationTracked(t, f.d); got != 0 {
		t.Fatalf("%d allocations remain after exit interrupted allocation, want 0", got)
	}
	allocationCharged(t, f.d, destination, 0)
}

func TestAdmissionAndRestoreChargeRepeatedDestinationsOnce(t *testing.T) {
	f := newTGFixture(t, &tgPeer{})
	const destination = "192.0.2.30"
	f.d.SetDestinationLimit(destination, 100)
	specs := []models.DebugletSpec{f.spec(t, 60), f.spec(t, 40)}
	specs[0].Policy.Addresses = []string{destination, destination}
	specs[1].Policy.Addresses = []string{destination}
	ids, err := f.d.SubmitDebuglets(f.ctx, specs, nil)
	if err != nil {
		t.Fatalf("admit duplicate destination at 60 and another run at 40: %v", err)
	}
	row := f.row(t, ids[0])
	if got := f.d.scheduler.QueryMaxDest(destination, row.StartTime.Time, row.EndTime.Time); got != 100 {
		t.Fatalf("admitted destination reservation = %d, want 100", got)
	}

	// Rebuild from the stored, still-repeated address list.
	f.d.mu.Lock()
	f.d.scheduler = schedule.New(time.Minute)
	f.d.mu.Unlock()
	if err := f.d.RestoreScheduler(f.ctx); err != nil {
		t.Fatalf("restore reservations: %v", err)
	}
	if got := f.d.scheduler.QueryMaxDest(destination, row.StartTime.Time, row.EndTime.Time); got != 100 {
		t.Fatalf("restored destination reservation = %d, want 100", got)
	}
	for i, remaining := range []resource.Bitrate{40, 0} {
		if err := f.exit(t, ids[i], 0, nil); err != nil {
			t.Fatalf("terminal release: %v", err)
		}
		if got := f.d.scheduler.QueryMaxDest(destination, row.StartTime.Time, row.EndTime.Time); got != remaining {
			t.Fatalf("destination reservation after exit %d = %d, want %d", i, got, remaining)
		}
		if got := f.d.scheduler.QueryMaxExec(tgExecutorID, row.StartTime.Time, row.EndTime.Time); got != remaining {
			t.Fatalf("executor reservation after exit %d = %d, want %d", i, got, remaining)
		}
	}
}
