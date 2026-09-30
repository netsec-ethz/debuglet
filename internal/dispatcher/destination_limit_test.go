package dispatcher

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func dlBandwidth(p *tgPeer) []*pb.BandwidthRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*pb.BandwidthRequest(nil), p.bandwidth...)
}

// dlHold allocates one run with floor tgFloorA and ceiling 2*tgFloorA on
// destination, under a limit of 10*tgFloorA.
func dlHold(t *testing.T, f *tgFixture, destination string) {
	t.Helper()
	deb := f.seedDirect(t, tgFloorA)
	allocationBind(t, f, deb, destination)
	if err := f.d.SetDestinationLimit(destination, 10*tgFloorA); err != nil {
		t.Fatalf("limit of an unheld destination: %v", err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, tgCallBound)
	defer cancel()
	if _, err := allocationClient(t, f.d).DebugletAllocate(ctx, allocationRequest(t, f, deb)); err != nil {
		t.Fatalf("allocation: %v", err)
	}
}

// TestDestinationLimitReachesTheHoldingExecutor states that lowering the limit
// of a destination sends the recomputed share to the executor holding an
// allocation there, instead of waiting for the next allocation or exit.
func TestDestinationLimitReachesTheHoldingExecutor(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	const destination = "192.0.2.90"
	dlHold(t, f, destination)
	before := len(dlBandwidth(peer))
	previous := allocationFairshare(t, f.d, destination)[tgExecutorID]

	const lowered = tgFloorA + tgFloorA/2
	if err := f.d.SetDestinationLimit(destination, lowered); err != nil {
		t.Fatalf("lowered limit: %v", err)
	}
	if recorded := dlCap(f.d, destination); recorded != lowered {
		t.Fatalf("recorded limit %s, want %s", recorded, lowered)
	}
	want := allocationFairshare(t, f.d, destination)[tgExecutorID]
	if want == previous {
		t.Fatalf("lowering the limit left the share at %s", want)
	}
	pushed := dlBandwidth(peer)[before:]
	if len(pushed) != 1 {
		t.Fatalf("the executor received %d bandwidth updates after the limit changed, want 1", len(pushed))
	}
	if limits := pushed[0].GetLimits(); len(limits) != 1 || limits[0].GetAddress() != destination || bitrate.Bitrate(limits[0].GetBitsLimit()) != want {
		t.Fatalf("pushed update %v, want %s at %s", limits, destination, want)
	}
}

func dlCap(d *Dispatcher, destination string) bitrate.Bitrate {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.destinations.Cap(destination)
}

func dlInsert(t *testing.T, d *Dispatcher, destination, executor string) {
	t.Helper()
	d.mu.Lock()
	err := d.destinations.Insert(uuid.New(), destination, executor, 10, 80)
	d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}

// TestDestinationLimitReportsUndeliveredShares states that a share the
// holding executor refuses, or that has no session to reach, is reported to
// the caller, that the limit stays recorded as the admission truth, and that
// the failure is returned once the deliveries ended rather than at the bound.
func TestDestinationLimitReportsUndeliveredShares(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	const refusal = "dl-refused-bandwidth"
	fairshareStartPeer(t, ctx, d, &fairsharePeer{bandwidth: func() error { return errors.New(refusal) }})

	const refused = "192.0.2.91"
	dlInsert(t, d, refused, fairshareExecutorID)
	start := time.Now()
	err := d.SetDestinationLimit(refused, 40)
	if err == nil || status.Code(err) != codes.Unknown || strings.Contains(err.Error(), refusal) {
		t.Fatalf("refused delivery returned %v, want the executor's refusal", err)
	}
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("refused delivery returned after %s, at the delivery bound", elapsed)
	}
	if got := dlCap(d, refused); got != 40 {
		t.Fatalf("recorded limit %s after a refused delivery, want 40", got)
	}

	// An executor that holds an allocation but has no session is a failed
	// delivery, not one that is skipped.
	const unreachable = "192.0.2.92"
	dlInsert(t, d, unreachable, "dl-gone-executor")
	if err := d.SetDestinationLimit(unreachable, 40); !errors.Is(err, rpc.ErrSessionUnavailable) {
		t.Fatalf("delivery to an executor without a session returned %v, want %v", err, rpc.ErrSessionUnavailable)
	}
	if got := dlCap(d, unreachable); got != 40 {
		t.Fatalf("recorded limit %s after an undeliverable share, want 40", got)
	}
}

// dlArrived lists the limits the executor received for destination, in the
// order they arrived.
func dlArrived(requests []*pb.BandwidthRequest, destination string) []bitrate.Bitrate {
	var arrived []bitrate.Bitrate
	for _, req := range requests {
		for _, limit := range req.GetLimits() {
			if limit.GetAddress() == destination {
				arrived = append(arrived, bitrate.Bitrate(limit.GetBitsLimit()))
			}
		}
	}
	return arrived
}

// TestDestinationLimitUpdatesArriveInIssueOrder states that two limit changes
// on one destination reach the holding executor in the order they were made,
// so the newest share is the one it applies last. The executor holds the
// first update until the second limit is recorded; a second update that is
// not ordered behind the first overtakes it there.
func TestDestinationLimitUpdatesArriveInIssueOrder(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	const destination = "192.0.2.96"
	const older, newer = bitrate.Bitrate(60), bitrate.Bitrate(40)
	entered := make(chan struct{})
	var calls atomic.Int32
	peer := &fairsharePeer{bandwidth: func() error {
		if calls.Add(1) != 1 {
			return nil
		}
		close(entered)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for dlCap(d, destination) != newer {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-tick.C:
			}
		}
		return nil
	}}
	fairshareStartPeer(t, ctx, d, peer)
	dlInsert(t, d, destination, fairshareExecutorID)

	first := make(chan error, 1)
	go func() { first <- d.SetDestinationLimit(destination, older) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("the first update never reached the executor")
	}
	if err := d.SetDestinationLimit(destination, newer); err != nil {
		t.Fatalf("newer limit: %v", err)
	}
	if err := <-first; err != nil {
		t.Fatalf("older limit: %v", err)
	}
	if arrived := dlArrived(peer.recorded(), destination); !slices.Equal(arrived, []bitrate.Bitrate{older, newer}) {
		t.Fatalf("updates arrived as %v, want %v: the newest limit must be applied last", arrived, []bitrate.Bitrate{older, newer})
	}
}

// TestDestinationLimitFailedDeliveryDoesNotHoldTheNext states that a delivery
// the executor refuses, or that has no client to reach it, neither blocks the
// next delivery to the same executor nor hides which executor missed it.
func TestDestinationLimitFailedDeliveryDoesNotHoldTheNext(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	const refusal = "dl-refused-once"
	var calls atomic.Int32
	peer := &fairsharePeer{bandwidth: func() error {
		if calls.Add(1) == 1 {
			return errors.New(refusal)
		}
		return nil
	}}
	fairshareStartPeer(t, ctx, d, peer)

	const refused = "192.0.2.97"
	dlInsert(t, d, refused, fairshareExecutorID)
	err := d.SetDestinationLimit(refused, 60)
	if err == nil || status.Code(err) != codes.Unknown || strings.Contains(err.Error(), refusal) || !strings.Contains(err.Error(), "executor "+fairshareExecutorID) {
		t.Fatalf("refused delivery returned %v, want the refusal naming executor %s", err, fairshareExecutorID)
	}
	if err := d.SetDestinationLimit(refused, 40); err != nil {
		t.Fatalf("delivery after a refused one: %v", err)
	}
	if arrived := dlArrived(peer.recorded(), refused); !slices.Equal(arrived, []bitrate.Bitrate{40}) {
		t.Fatalf("updates arrived as %v, want the one after the refusal", arrived)
	}

	// A registered executor without a client is a failed delivery on every
	// change, each reported at once with the executor it missed.
	const clientless, unreached = "dl-clientless-executor", "192.0.2.98"
	registryRegister(t, d, clientless)
	dlInsert(t, d, unreached, clientless)
	for _, limit := range []bitrate.Bitrate{60, 40} {
		start := time.Now()
		err := d.SetDestinationLimit(unreached, limit)
		if err == nil || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "executor "+clientless) {
			t.Fatalf("limit %s to an executor without a client returned %v, want its failure naming executor %s", limit, err, clientless)
		}
		if elapsed := time.Since(start); elapsed >= 5*time.Second {
			t.Fatalf("limit %s returned after %s, at the delivery bound", limit, elapsed)
		}
	}
}

// dlSpec is a paid fixture spec whose policy is on destination.
func dlSpec(t *testing.T, f *tgFixture, floor bitrate.Bitrate, destination string) models.DebugletSpec {
	t.Helper()
	spec := f.spec(t, floor)
	spec.Policy.Addresses = []string{destination}
	return spec
}

// dlAdmit submits spec through SubmitDebuglets. The run's floor is reserved on
// its destination for the fixture's window an hour ahead; nothing is charged
// until the run allocates.
func dlAdmit(f *tgFixture, spec models.DebugletSpec) (tgDebuglet, error) {
	ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{spec}, nil)
	if err != nil {
		return tgDebuglet{}, err
	}
	row, err := f.q.GetDebugletByUUID(f.ctx, ids[0])
	if err != nil {
		return tgDebuglet{}, err
	}
	return tgDebuglet{id: ids[0], txID: spec.TransactionID, orderID: spec.OrderID, floor: spec.Policy.FloorBW, row: row}, nil
}

// TestDestinationLimitBelowTheReservedFloorsIsRefused states that a limit
// below the floors the scheduler reserved for admitted runs whose window lies
// ahead is refused like one below the charged floors, so such a run can still
// allocate when its window starts.
func TestDestinationLimitBelowTheReservedFloorsIsRefused(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	const destination = "192.0.2.99"
	if err := f.d.SetDestinationLimit(destination, 10*tgFloorA); err != nil {
		t.Fatalf("limit of an unheld destination: %v", err)
	}
	deb, err := dlAdmit(f, dlSpec(t, f, tgFloorA, destination))
	if err != nil {
		t.Fatalf("admission: %v", err)
	}
	allocationCharged(t, f.d, destination, 0)
	before := len(dlBandwidth(peer))

	if err := f.d.SetDestinationLimit(destination, tgFloorA-1); !errors.Is(err, resource.ErrCapacityFull) {
		t.Fatalf("limit below the reserved floors returned %v, want %v", err, resource.ErrCapacityFull)
	}
	if got := dlCap(f.d, destination); got != 10*tgFloorA {
		t.Fatalf("refused limit left the limit at %s, want %s", got, 10*tgFloorA)
	}
	if err := f.d.SetDestinationLimit(destination, tgFloorA); err != nil {
		t.Fatalf("limit equal to the reserved floors: %v", err)
	}
	if got := dlCap(f.d, destination); got != tgFloorA {
		t.Fatalf("recorded limit %s, want %s", got, tgFloorA)
	}
	if pushed := dlBandwidth(peer)[before:]; len(pushed) != 0 {
		t.Fatalf("a destination nobody allocated sent %v", pushed)
	}
	ctx, cancel := context.WithTimeout(f.ctx, tgCallBound)
	defer cancel()
	if _, err := allocationClient(t, f.d).DebugletAllocate(ctx, allocationRequest(t, f, deb)); err != nil {
		t.Fatalf("allocation of the reserved run under the accepted limit: %v", err)
	}
	allocationCharged(t, f.d, destination, tgFloorA)
}

// TestDestinationLimitWithoutAllocationsSendsNothing states that the limit of
// a destination nobody holds is recorded without any executor update.
func TestDestinationLimitWithoutAllocationsSendsNothing(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	peer := &fairsharePeer{}
	fairshareStartPeer(t, ctx, d, peer)
	dlInsert(t, d, "192.0.2.93", fairshareExecutorID)

	const unheld = "192.0.2.94"
	if err := d.SetDestinationLimit(unheld, 4096); err != nil {
		t.Fatalf("limit of an unheld destination: %v", err)
	}
	if got := dlCap(d, unheld); got != 4096 {
		t.Fatalf("recorded limit %s, want 4096", got)
	}
	if requests := peer.recorded(); len(requests) != 0 {
		t.Fatalf("an unheld destination sent %v", requests)
	}
}

// TestDestinationLimitBelowTheFloorsIsRefused states that a limit below the
// floors already charged on a destination is refused before anything is
// recorded or sent, and that a limit equal to those floors is applied.
func TestDestinationLimitBelowTheFloorsIsRefused(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	const destination = "192.0.2.95"
	dlHold(t, f, destination)
	before := len(dlBandwidth(peer))
	if err := f.d.SetDestinationLimit(destination, tgFloorA-1); !errors.Is(err, resource.ErrCapacityFull) {
		t.Fatalf("limit below the floors returned %v, want %v", err, resource.ErrCapacityFull)
	}
	if got := dlCap(f.d, destination); got != 10*tgFloorA {
		t.Fatalf("refused limit left the limit at %s, want %s", got, 10*tgFloorA)
	}
	if pushed := dlBandwidth(peer)[before:]; len(pushed) != 0 {
		t.Fatalf("a refused limit sent %v", pushed)
	}
	if err := f.d.SetDestinationLimit(destination, tgFloorA); err != nil {
		t.Fatalf("limit equal to the floors: %v", err)
	}
	pushed := dlBandwidth(peer)[before:]
	if len(pushed) != 1 || len(pushed[0].GetLimits()) != 1 || pushed[0].GetLimits()[0].GetBitsLimit() != int64(tgFloorA) {
		t.Fatalf("limit equal to the floors sent %v, want one update at %s", pushed, tgFloorA)
	}
}
