// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package tagger

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// ---- helpers ----------------------------------------------------------------

var testMeasurementID = []byte("meas-00000000-test")
var fixedSeed = bytes.Repeat([]byte{0xAA}, 32)

func newTestTagger(t *testing.T) *Tagger {
	t.Helper()
	ks, err := tesla.NewKeySchedule(tesla.Config{
		Seed:  fixedSeed,
		Delay: 10 * time.Second,
		Epoch: time.Now().Add(-10 * time.Second),
	})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}
	return New(ks, testMeasurementID)
}

// buildIPv4Packet constructs a minimal valid IPv4/UDP packet (no payload
// fragmentation). header = 20 bytes, payload = provided bytes.
func buildIPv4Packet(payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45                                          // version=4, IHL=5
	pkt[1] = 0x00                                          // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen)) // total length
	binary.BigEndian.PutUint16(pkt[4:6], 0x0000)           // IPID = 0 initially
	pkt[6] = 0x00                                          // flags
	pkt[7] = 0x00                                          // fragment offset
	pkt[8] = 64                                            // TTL
	pkt[9] = 17                                            // protocol = UDP
	binary.BigEndian.PutUint16(pkt[10:12], 0x0000)         // checksum = 0 (computed later)
	binary.BigEndian.PutUint32(pkt[12:16], 0x7F000001)     // src = 127.0.0.1
	binary.BigEndian.PutUint32(pkt[16:20], 0x7F000002)     // dst = 127.0.0.2
	copy(pkt[20:], payload)
	// Compute correct initial checksum.
	binary.BigEndian.PutUint16(pkt[10:12], IPv4Checksum(pkt[:20]))
	return pkt
}

// validateIPv4Checksum returns true if the IPv4 header checksum in pkt is correct.
func validateIPv4Checksum(pkt []byte) bool {
	return IPv4Checksum(pkt[:20]) == 0x0000
}

// ---- tests ------------------------------------------------------------------

// TestTagPacketSetsIPID verifies that TagPacket writes a non-zero IPID and
// that the checksum is still valid afterwards.
func TestTagPacketSetsIPID(t *testing.T) {
	tgr := newTestTagger(t)
	payload := []byte("hello accountable world")
	pkt := buildIPv4Packet(payload)

	if ReadIPID(pkt) != 0 {
		t.Fatal("precondition: initial IPID should be 0")
	}

	tagged, err := tgr.TagPacket(pkt)
	if err != nil {
		t.Fatalf("TagPacket: %v", err)
	}

	ipid := ReadIPID(tagged)
	if ipid == 0 {
		t.Error("TagPacket left IPID at zero — tag was not applied")
	}

	if !validateIPv4Checksum(tagged) {
		t.Errorf("IPv4 checksum invalid after tagging (checksum word = %04x)", IPv4Checksum(tagged[:20]))
	}
}

// TestTagPacketDeterminism ensures that the same packet bytes (and same time
// epoch) always produce the same IPID.
func TestTagPacketDeterminism(t *testing.T) {
	ks, _ := tesla.NewKeySchedule(tesla.Config{
		Seed:  fixedSeed,
		Delay: 10 * time.Second,
		Epoch: time.Now().Add(-10 * time.Second),
	})
	tgr := New(ks, testMeasurementID)

	payload := []byte("deterministic payload")
	pkt1 := buildIPv4Packet(payload)
	pkt2 := buildIPv4Packet(payload)

	tagged1, _ := tgr.TagPacket(pkt1)
	tagged2, _ := tgr.TagPacket(pkt2)

	if ReadIPID(tagged1) != ReadIPID(tagged2) {
		t.Errorf("IPID differs for identical packets in the same epoch: %04x vs %04x",
			ReadIPID(tagged1), ReadIPID(tagged2))
	}
}

// TestTagPacketNonIPv4 ensures non-IPv4 buffers are returned unchanged.
func TestTagPacketNonIPv4(t *testing.T) {
	tgr := newTestTagger(t)
	// IPv6 header — version nibble = 6.
	pkt := make([]byte, 40)
	pkt[0] = 0x60
	original := make([]byte, len(pkt))
	copy(original, pkt)

	result, err := tgr.TagPacket(pkt)
	if err != nil {
		t.Fatalf("TagPacket on non-IPv4: %v", err)
	}
	if !bytes.Equal(result, original) {
		t.Error("non-IPv4 packet was modified")
	}
}

// TestTagPacketTooShort ensures packets shorter than 20 bytes are returned unmodified.
func TestTagPacketTooShort(t *testing.T) {
	tgr := newTestTagger(t)
	pkt := []byte{0x45, 0x00, 0x00}
	result, err := tgr.TagPacket(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, pkt) {
		t.Error("short packet was modified")
	}
}

// TestAccountabilityRoundTrip performs a full end-to-end accountability check:
//  1. Tag an IPv4 packet using the current key.
//  2. Read back the IPID.
//  3. Verify the tag using the same key (simulating the verifier after disclosure).
func TestAccountabilityRoundTrip(t *testing.T) {
	// Anchor the epoch at now so that TagPacket (which calls time.Now()) falls
	// in epoch 1, making the key index predictable.
	now := time.Now()
	ks, _ := tesla.NewKeySchedule(tesla.Config{
		Seed:  fixedSeed,
		Delay: 10 * time.Second,
		Epoch: now.Add(-10 * time.Second),
	})
	tgr := New(ks, testMeasurementID)

	payload := []byte("accountability test payload")
	pkt := buildIPv4Packet(payload)

	tagged, err := tgr.TagPacket(pkt)
	if err != nil {
		t.Fatalf("TagPacket: %v", err)
	}

	observedTag := ReadIPID(tagged)

	// Simulate verifier: executor discloses the key for epoch 1.
	// The tagger used time.Now(), which is in epoch 1.
	disclosedKey := ks.CurrentKey(now) // key for epoch 1
	ok, err := tesla.VerifyTag(disclosedKey, 1, testMeasurementID, tagged, observedTag)
	if err != nil {
		t.Fatalf("VerifyTag: %v", err)
	}
	if !ok {
		t.Error("VerifyTag returned false — accountability verification failed")
	}
}

// TestAccountabilityBPFRoundTrip performs a BPF end-to-end accountability check:
//  1. Compute a BPF tag for a packet using the current key.
//  2. Verify the tag using VerifyBPFTag.
func TestAccountabilityBPFRoundTrip(t *testing.T) {
	now := time.Now()
	ks, _ := tesla.NewKeySchedule(tesla.Config{
		Seed:  fixedSeed,
		Delay: 10 * time.Second,
		Epoch: now.Add(-10 * time.Second),
	})

	payload := []byte("bpf accountability test payload")
	pkt := buildIPv4Packet(payload)

	// In BPF-mode, mutable fields (IPID, checksum) are zeroed during tagging.
	binary.BigEndian.PutUint16(pkt[4:6], 0)   // IPID
	binary.BigEndian.PutUint16(pkt[10:12], 0) // IPv4 checksum

	tag, err := ks.ComputeBPFTagForPacket(now, testMeasurementID, pkt)
	if err != nil {
		t.Fatalf("ComputeBPFTagForPacket: %v", err)
	}

	// Write tag to packet IPID (to mirror kernel behavior)
	writeIPID(pkt, tag)
	recomputeIPv4Checksum(pkt)

	observedTag := ReadIPID(pkt)

	disclosedKey := ks.CurrentKey(now) // key for epoch 1
	ok, err := tesla.VerifyBPFTag(disclosedKey, 1, testMeasurementID, pkt, observedTag)
	if err != nil {
		t.Fatalf("VerifyBPFTag: %v", err)
	}
	if !ok {
		t.Error("VerifyBPFTag returned false — BPF accountability verification failed")
	}
}

// TestAccountabilityRealDelayedDisclosure simulates the real delayed key disclosure flow:
//  1. Tag a packet at time T = now + delay (Epoch 1).
//  2. At time T = now + 3*delay (Epoch 3), the disclosed key is for Epoch 2.
//  3. Derive Epoch 1's key from the disclosed Epoch 2 key.
//  4. Verify the Epoch 1 packet using the derived key.
func TestAccountabilityRealDelayedDisclosure(t *testing.T) {
	delay := 100 * time.Millisecond
	now := time.Now()
	ks, _ := tesla.NewKeySchedule(tesla.Config{
		Seed:  fixedSeed,
		Delay: delay,
		Epoch: now,
	})

	payload := []byte("delayed disclosure payload")
	pkt := buildIPv4Packet(payload)

	// Zero mutable fields
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[10:12], 0)

	// Tag packet at T = now + delay (Epoch 1)
	tag, err := ks.ComputeTagForPacket(now.Add(delay), testMeasurementID, pkt)
	if err != nil {
		t.Fatalf("ComputeTagForPacket: %v", err)
	}
	writeIPID(pkt, tag)
	recomputeIPv4Checksum(pkt)

	observedTag := ReadIPID(pkt)

	// At T = now + 3*delay (Epoch 3), the disclosed key is for Epoch 2.
	disclosedEpoch, disclosedKey, ok := ks.DisclosedKey(now.Add(3 * delay))
	if !ok {
		t.Fatal("expected disclosed key at Epoch 3")
	}
	if disclosedEpoch != 2 {
		t.Fatalf("expected disclosed epoch index 2, got %d", disclosedEpoch)
	}

	// We want to verify the packet from Epoch 1.
	// We derive the key for Epoch 1 from the disclosed Epoch 2 key.
	targetKey, err := tesla.DeriveFromDisclosed(disclosedKey, disclosedEpoch, 1)
	if err != nil {
		t.Fatalf("DeriveFromDisclosed: %v", err)
	}

	ok, err = tesla.VerifyTag(targetKey, 1, testMeasurementID, pkt, observedTag)
	if err != nil {
		t.Fatalf("VerifyTag: %v", err)
	}
	if !ok {
		t.Error("VerifyTag failed using delayed disclosed key")
	}
}

// TestAccountabilityBPFRealDelayedDisclosure simulates the real delayed disclosure flow for BPF tags:
//  1. Compute BPF tag at time T = now + delay (Epoch 1).
//  2. At time T = now + 3*delay (Epoch 3), the disclosed key is for Epoch 2.
//  3. Derive Epoch 1's key from the disclosed Epoch 2 key.
//  4. Verify the BPF tag using the derived key.
func TestAccountabilityBPFRealDelayedDisclosure(t *testing.T) {
	delay := 100 * time.Millisecond
	now := time.Now()
	ks, _ := tesla.NewKeySchedule(tesla.Config{
		Seed:  fixedSeed,
		Delay: delay,
		Epoch: now,
	})

	payload := []byte("delayed disclosure BPF payload")
	pkt := buildIPv4Packet(payload)

	// Zero mutable fields
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[10:12], 0)

	// Compute BPF tag at T = now + delay (Epoch 1)
	tag, err := ks.ComputeBPFTagForPacket(now.Add(delay), testMeasurementID, pkt)
	if err != nil {
		t.Fatalf("ComputeBPFTagForPacket: %v", err)
	}
	writeIPID(pkt, tag)
	recomputeIPv4Checksum(pkt)

	observedTag := ReadIPID(pkt)

	// At T = now + 3*delay (Epoch 3), the disclosed key is for Epoch 2.
	disclosedEpoch, disclosedKey, ok := ks.DisclosedKey(now.Add(3 * delay))
	if !ok {
		t.Fatal("expected disclosed key at Epoch 3")
	}
	if disclosedEpoch != 2 {
		t.Fatalf("expected disclosed epoch index 2, got %d", disclosedEpoch)
	}

	// Derive target key for Epoch 1 from disclosed Epoch 2 key
	targetKey, err := tesla.DeriveFromDisclosed(disclosedKey, disclosedEpoch, 1)
	if err != nil {
		t.Fatalf("DeriveFromDisclosed: %v", err)
	}

	ok, err = tesla.VerifyBPFTag(targetKey, 1, testMeasurementID, pkt, observedTag)
	if err != nil {
		t.Fatalf("VerifyBPFTag: %v", err)
	}
	if !ok {
		t.Error("VerifyBPFTag failed using delayed disclosed key")
	}
}

// TestAccountabilityTamperedPacket ensures a tampered packet fails verification.
func TestAccountabilityTamperedPacket(t *testing.T) {
	now := time.Now()
	ks, _ := tesla.NewKeySchedule(tesla.Config{
		Seed:  fixedSeed,
		Delay: 10 * time.Second,
		Epoch: now.Add(-10 * time.Second),
	})
	tgr := New(ks, testMeasurementID)

	payload := []byte("original payload")
	pkt := buildIPv4Packet(payload)
	tagged, _ := tgr.TagPacket(pkt)
	observedTag := ReadIPID(tagged)

	// Tamper with the packet payload (byte after the IP header).
	tampered := make([]byte, len(tagged))
	copy(tampered, tagged)
	tampered[20] ^= 0xFF

	disclosedKey := ks.CurrentKey(now)
	ok, err := tesla.VerifyTag(disclosedKey, 1, testMeasurementID, tampered, observedTag)
	if err != nil {
		t.Fatalf("VerifyTag (tampered): %v", err)
	}
	if ok {
		t.Error("VerifyTag returned true for a tampered packet — verification is broken")
	}
}

// ---- WrappedConn tests ------------------------------------------------------

// mockConn is a net.Conn stub that captures written bytes.
type mockConn struct {
	net.Conn
	written []byte
}

func (m *mockConn) Write(b []byte) (int, error) {
	m.written = make([]byte, len(b))
	copy(m.written, b)
	return len(b), nil
}

func TestWrappedConnTagsPacket(t *testing.T) {
	tgr := newTestTagger(t)
	mock := &mockConn{}
	wc := WrapConn(mock, tgr)

	payload := []byte("wrapped conn test")
	pkt := buildIPv4Packet(payload)

	_, err := wc.Write(pkt)
	if err != nil {
		t.Fatalf("WrappedConn.Write: %v", err)
	}

	if len(mock.written) < 20 {
		t.Fatal("WrappedConn did not write enough bytes")
	}
	ipid := ReadIPID(mock.written)
	if ipid == 0 {
		t.Error("WrappedConn did not apply IPID tag")
	}
	if !validateIPv4Checksum(mock.written) {
		t.Error("IPv4 checksum invalid after WrappedConn.Write")
	}
}

// ---- WrappedPacketConn tests ------------------------------------------------

// mockPacketConn captures WriteTo calls.
type mockPacketConn struct {
	net.PacketConn
	written []byte
	dst     net.Addr
}

func (m *mockPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	m.written = make([]byte, len(b))
	copy(m.written, b)
	m.dst = addr
	return len(b), nil
}

func TestWrappedPacketConnTagsPacket(t *testing.T) {
	tgr := newTestTagger(t)
	mock := &mockPacketConn{}
	wpc := WrapPacketConn(mock, tgr)

	payload := []byte("wrapped packet conn test")
	pkt := buildIPv4Packet(payload)
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 1234}

	_, err := wpc.WriteTo(pkt, addr)
	if err != nil {
		t.Fatalf("WrappedPacketConn.WriteTo: %v", err)
	}

	if len(mock.written) < 20 {
		t.Fatal("not enough bytes written")
	}
	if ReadIPID(mock.written) == 0 {
		t.Error("WrappedPacketConn did not apply IPID tag")
	}
	if !validateIPv4Checksum(mock.written) {
		t.Error("IPv4 checksum invalid after WrappedPacketConn.WriteTo")
	}
}
