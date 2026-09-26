// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tagger

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// firstEpochPacket returns a valid IPv4 packet whose IPID and header checksum
// are both nonzero, so any rewrite of either field is visible.
func firstEpochPacket() []byte {
	pkt := buildIPv4Packet([]byte("first epoch pass-through"))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234)
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	binary.BigEndian.PutUint16(pkt[10:12], IPv4Checksum(pkt[:20]))
	return pkt
}

func firstEpochSchedule(t *testing.T, epoch time.Time) *tesla.KeySchedule {
	t.Helper()
	ks, err := tesla.NewKeySchedule(tesla.Config{
		Seed:  fixedSeed,
		Delay: 10 * time.Second,
		Epoch: epoch,
	})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}
	return ks
}

// TestTagPacketFirstEpochPassesThrough checks that while no signing key is
// usable the pure-Go tagger leaves packets untouched, and tags them once
// epoch 1 has started.
func TestTagPacketFirstEpochPassesThrough(t *testing.T) {
	pkt := firstEpochPacket()
	if binary.BigEndian.Uint16(pkt[10:12]) == 0 {
		t.Fatal("fixture checksum is zero")
	}
	original := append([]byte(nil), pkt...)

	got, err := New(firstEpochSchedule(t, time.Now()), testMeasurementID).TagPacket(pkt)
	if err != nil {
		t.Fatalf("TagPacket in epoch 0: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("TagPacket in epoch 0 changed the packet:\n got %x\nwant %x", got, original)
	}

	ks := firstEpochSchedule(t, time.Now().Add(-10*time.Second))
	tagged, err := New(ks, testMeasurementID).TagPacket(append([]byte(nil), original...))
	if err != nil {
		t.Fatalf("TagPacket in epoch 1: %v", err)
	}
	k1, _ := ks.KeyAtEpoch(1)
	if ok, err := tesla.VerifyTag(k1, 1, testMeasurementID, tagged, ReadIPID(tagged)); err != nil || !ok {
		t.Errorf("epoch-1 packet is not tagged with k_1: ok=%v err=%v (IPID %04x, original %04x)",
			ok, err, ReadIPID(tagged), ReadIPID(original))
	}
	if !validateIPv4Checksum(tagged) {
		t.Error("IPv4 checksum invalid after tagging in epoch 1")
	}

}
