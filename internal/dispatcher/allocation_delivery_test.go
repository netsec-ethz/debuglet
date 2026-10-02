// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"strings"
	"testing"

	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAllocationDeliveryFailureIsReturnedAndReconciledByHeartbeat(t *testing.T) {
	peer := &tgPeer{bandwidthErr: status.Error(codes.Unavailable, "temporary refusal")}
	f := newTGFixture(t, peer)
	run := f.seedDirect(t, tgFloorA)
	const destination = "192.0.2.120"
	allocationBind(t, f, run, destination)
	request := allocationRequest(t, f, run)
	client := allocationClient(t, f.d)
	if _, err := client.DebugletAllocate(f.ctx, request); status.Code(err) != codes.Unavailable {
		t.Fatalf("allocation response %v", err)
	}
	allocationCharged(t, f.d, destination, tgFloorA)
	peer.mu.Lock()
	peer.bandwidthErr = nil
	peer.mu.Unlock()
	mutation := effectTestMutation(t, f.d, tgExecutorID)
	defer mutation.Finish()
	if _, err := f.d.OnHeartbeat(f.ctx, mutation, &pb.HeartbeatRequest{ExecutorId: tgExecutorID}); err != nil {
		t.Fatal(err)
	}
	f.d.mu.RLock()
	pending := f.d.executors[tgExecutorID].bandwidthPending
	f.d.mu.RUnlock()
	if pending {
		t.Fatal("successful heartbeat retry left allocation pending")
	}
	if _, err := client.DebugletAllocate(f.ctx, request); err != nil {
		t.Fatalf("retry: %v", err)
	}
	allocationCharged(t, f.d, destination, tgFloorA)
}

func TestOlderAllocationAcknowledgementCannotClearNewSnapshot(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	const destination = "192.0.2.121"
	dlHold(t, f, destination)
	mutation := effectTestMutation(t, f.d, tgExecutorID)
	defer mutation.Finish()
	older, err := f.d.captureFairshare(f.ctx, mutation, []string{destination})
	if err != nil {
		t.Fatal(err)
	}
	newer, err := f.d.captureFairshare(f.ctx, mutation, []string{destination})
	if err != nil {
		t.Fatal(err)
	}
	if err := older.send(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.d.mu.RLock()
	pending := f.d.executors[tgExecutorID].bandwidthPending
	f.d.mu.RUnlock()
	if !pending {
		t.Fatal("older acknowledgement cleared newer capture")
	}
	if err := newer.send(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.d.mu.RLock()
	pending = f.d.executors[tgExecutorID].bandwidthPending
	f.d.mu.RUnlock()
	if pending {
		t.Fatal("latest acknowledgement left delivery pending")
	}
}

func TestLegacyExecutorAllocatesButCannotConfirmOrderedLiveChange(t *testing.T) {
	f := newTGFixture(t, &tgPeer{})
	f.d.mu.Lock()
	f.d.executors[tgExecutorID].bandwidthVersion = 0
	f.d.mu.Unlock()
	const destination = "192.0.2.122"
	dlHold(t, f, destination)
	err := f.d.SetDestinationLimit(destination, tgFloorA+tgFloorA/2)
	if err == nil || !strings.Contains(err.Error(), "executor upgrade required") {
		t.Fatalf("legacy live-change response %v", err)
	}
	// The requested admission cap remains recorded, matching a failed delivery.
	if got := dlCap(f.d, destination); got != tgFloorA+tgFloorA/2 {
		t.Fatalf("recorded cap %d", got)
	}
}

func TestAllocationSnapshotIncludesUnaffectedDestinations(t *testing.T) {
	f := newTGFixture(t, &tgPeer{})
	dlHold(t, f, "192.0.2.123")
	dlHold(t, f, "192.0.2.124")
	mutation := effectTestMutation(t, f.d, tgExecutorID)
	defer mutation.Finish()
	work, err := f.d.captureFairshare(context.Background(), mutation, []string{"192.0.2.123"})
	if err != nil {
		t.Fatal(err)
	}
	if len(work.recipients) != 1 || len(work.recipients[0].updates) != 2 {
		t.Fatalf("partial snapshot: %+v", work.recipients)
	}
	if err := work.send(f.ctx); err != nil {
		t.Fatal(err)
	}
}
