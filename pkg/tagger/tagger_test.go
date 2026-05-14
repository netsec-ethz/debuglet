// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tagger

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"debuglet/pkg/tesla"
)

// ---- helpers ----------------------------------------------------------------

var testMeasurementID = []byte("meas-00000000-test")
var fixedSeed = bytes.Repeat([]byte{0xAA}, 32)

func newTestTagger(t *testing.T) *Tagger {
	t.Helper()
	ks, err := tesla.NewKeySchedule(tesla.Config{
		Seed:  fixedSeed,
		Delay: 10 * time.Second,
		Epoch: time.Now(),
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
	pkt[0] = 0x45                                                         // version=4, IHL=5
	pkt[1] = 0x00                                                         // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))               // total length
	binary.BigEndian.PutUint16(pkt[4:6], 0x0000)                         // IPID = 0 initially
	pkt[6] = 0x00                                                         // flags
	pkt[7] = 0x00                                                         // fragment offset
	pkt[8] = 64                                                           // TTL
	pkt[9] = 17                                                           // protocol = UDP
	binary.BigEndian.PutUint16(pkt[10:12], 0x0000)                       // checksum = 0 (computed later)
	binary.BigEndian.PutUint32(pkt[12:16], 0x7F000001)                   // src = 127.0.0.1
	binary.BigEndian.PutUint32(pkt[16:20], 0x7F000002)                   // dst = 127.0.0.2
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
		Epoch: time.Now(),
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
	// in epoch 0, making the key index predictable.
	now := time.Now()
	ks, _ := tesla.NewKeySchedule(tesla.Config{
		Seed:  fixedSeed,
		Delay: 10 * time.Second,
		Epoch: now,
	})
	tgr := New(ks, testMeasurementID)

	payload := []byte("accountability test payload")
	pkt := buildIPv4Packet(payload)

	tagged, err := tgr.TagPacket(pkt)
	if err != nil {
		t.Fatalf("TagPacket: %v", err)
	}

	observedTag := ReadIPID(tagged)

	// Simulate verifier: executor discloses the key for epoch 0.
	// The tagger used time.Now(), which is in epoch 0 (epoch anchored at now).
	disclosedKey := ks.CurrentKey(now) // key for epoch 0
	ok, err := tesla.VerifyTag(disclosedKey, 0, testMeasurementID, tagged, observedTag)
	if err != nil {
		t.Fatalf("VerifyTag: %v", err)
	}
	if !ok {
		t.Error("VerifyTag returned false — accountability verification failed")
	}
}

// TestAccountabilityTamperedPacket ensures a tampered packet fails verification.
func TestAccountabilityTamperedPacket(t *testing.T) {
	now := time.Now()
	ks, _ := tesla.NewKeySchedule(tesla.Config{
		Seed:  fixedSeed,
		Delay: 10 * time.Second,
		Epoch: now,
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
	ok, err := tesla.VerifyTag(disclosedKey, 0, testMeasurementID, tampered, observedTag)
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
