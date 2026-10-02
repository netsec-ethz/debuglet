// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

type retryLimitCounter struct {
	*recordingPacketCount
	fail bool
}

func (c *retryLimitCounter) SetLimit(addr string, id uuid.UUID, limit bitrate.Bitrate) error {
	if c.fail {
		return errors.New("counter temporarily unavailable")
	}
	return c.recordingPacketCount.SetLimit(addr, id, limit)
}

func TestBandwidthRevisionFencesLateAndPartiallyAppliedUpdates(t *testing.T) {
	counter := &retryLimitCounter{recordingPacketCount: newRecordingPacketCount()}
	e := newFixtureExecutor(t, fixtureConfig(), counter, newFixtureMemoryStorage(t))
	const a, b = "192.0.2.10", "192.0.2.11"
	id := uuid.New()
	apply := func(revision uint64, av, bv int64) (*pb.BandwidthResponse, error) {
		return e.applyBandwidth(operationBinding(), &pb.BandwidthRequest{Revision: revision, Limits: []*pb.DestinationLimit{{Address: a, BitsLimit: av}, {Address: b, BitsLimit: bv}}})
	}
	// A snapshot arrives during Allocate, before the local run is registered.
	if _, err := apply(2, 300, 400); err != nil {
		t.Fatal(err)
	}
	if err := e.limiter.InsertDebuglet(id, 0, 1000, []string{a, b}); err != nil {
		t.Fatal(err)
	}
	e.running[id] = RunningDebuglet{id: id}
	e.publishLimits([]string{a, b})
	if got := counter.appliedDestination(a, id); got != 300 {
		t.Fatalf("initial limit %d", got)
	}
	if reply, err := apply(1, 800, 900); err != nil || reply.GetRevision() != 2 {
		t.Fatalf("late reply %v, %v", reply, err)
	}
	if got := counter.appliedDestination(a, id); got != 300 {
		t.Fatalf("older update overwrote latest: %d", got)
	}

	counter.fail = true
	if _, err := apply(3, 100, 200); err == nil {
		t.Fatal("failed publication was acknowledged")
	}
	counter.fail = false
	if reply, err := apply(2, 600, 700); err != nil || reply.GetRevision() != 2 {
		t.Fatalf("older reply after failure %v, %v", reply, err)
	}
	if got, _, err := e.limiter.GetAddrLimit(id, a); err != nil || got != 100 {
		t.Fatalf("older snapshot rewrote partly applied latest: %d, %v", got, err)
	}
	if reply, err := apply(3, 100, 200); err != nil || reply.GetRevision() != 3 {
		t.Fatalf("same-revision retry %v, %v", reply, err)
	}
	if got := counter.appliedDestination(b, id); got != 200 {
		t.Fatalf("retry did not publish second destination: %d", got)
	}
	// An empty newer snapshot still fences delayed work after its final run ends.
	e.unregisterDebuglet(id, nil)
	e.limiter.RemoveDebuglet(id)
	if reply, err := e.applyBandwidth(operationBinding(), &pb.BandwidthRequest{Revision: 4}); err != nil || reply.GetRevision() != 4 {
		t.Fatalf("empty snapshot: %v, %v", reply, err)
	}
	if reply, err := apply(3, 800, 900); err != nil || reply.GetRevision() != 4 {
		t.Fatalf("late retired snapshot: %v, %v", reply, err)
	}
}
