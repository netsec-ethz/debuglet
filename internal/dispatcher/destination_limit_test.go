package dispatcher

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
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
	if limits := pushed[0].GetLimits(); len(limits) != 1 || limits[0].GetAddress() != destination || resource.Bitrate(limits[0].GetBitsLimit()) != want {
		t.Fatalf("pushed update %v, want %s at %s", limits, destination, want)
	}
}

func dlCap(d *Dispatcher, destination string) resource.Bitrate {
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
	if err == nil || !strings.Contains(err.Error(), refusal) {
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
