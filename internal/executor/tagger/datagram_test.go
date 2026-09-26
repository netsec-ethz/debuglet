// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tagger

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// onesComplementSum folds b into a 16-bit one's-complement sum.
func onesComplementSum(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

// A built UDP packet is what the kernel would send: a well-formed IPv4 header
// with DF set, and a UDP checksum a receiver accepts. Tagging it produces a
// tag the verifier accepts for the packet as it leaves.
func TestBuiltUDPPacketIsValidAndTagged(t *testing.T) {
	now := time.Now()
	ks, _ := tesla.NewKeySchedule(tesla.Config{Seed: fixedSeed, Delay: time.Hour, Epoch: now.Add(-time.Hour)})
	src, dst := net.IPv4(192, 0, 2, 10), net.IPv4(198, 51, 100, 7)
	for _, n := range []int{0, 1, 7, 64, 1200} {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i + n)
		}
		pkt := buildUDPPacket(src, dst, 40000, 53, payload)
		if got := binary.BigEndian.Uint16(pkt[2:4]); int(got) != len(pkt) {
			t.Fatalf("payload %d: total length %d, want %d", n, got, len(pkt))
		}
		if binary.BigEndian.Uint16(pkt[6:8]) != flagDontFrag || pkt[9] != protoUDP || pkt[8] != defaultTTL {
			t.Fatalf("payload %d: unexpected header % x", n, pkt[:20])
		}
		segment := pkt[ipv4HeaderLen:]
		sum := onesComplementSum(0, pkt[12:20])
		sum += protoUDP + uint32(len(segment))
		sum = onesComplementSum(sum, segment)
		for sum>>16 != 0 {
			sum = (sum & 0xFFFF) + (sum >> 16)
		}
		if sum != 0xFFFF {
			t.Errorf("payload %d: the UDP checksum does not verify (%#x)", n, sum)
		}

		tagged, err := New(ks, testMeasurementID).TagPacket(pkt)
		if err != nil {
			t.Fatal(err)
		}
		if IPv4Checksum(tagged[:ipv4HeaderLen]) != 0 {
			t.Errorf("payload %d: the IPv4 header checksum does not verify", n)
		}
		ok, err := tesla.VerifyTag(ks.CurrentKey(now), 1, testMeasurementID, tagged, ReadIPID(tagged))
		if err != nil || !ok {
			t.Errorf("payload %d: VerifyTag = %v, %v", n, ok, err)
		}
	}
}

func TestBuiltICMPPacketCarriesTheMessage(t *testing.T) {
	message := []byte{8, 0, 0, 0, 0x12, 0x34, 0, 1, 'p', 'i', 'n', 'g'}
	pkt := buildICMPPacket(net.IPv4(192, 0, 2, 10), net.IPv4(198, 51, 100, 7), message)
	if pkt[9] != protoICMP || int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) || string(pkt[ipv4HeaderLen:]) != string(message) {
		t.Fatalf("unexpected ICMP packet % x", pkt)
	}
}

// Connections the pure-Go tagger cannot tag are refused and stay usable.
func TestWrapDatagramRefusesOtherConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ks, _ := tesla.NewKeySchedule(tesla.Config{Seed: fixedSeed, Delay: time.Hour})
	if wrapped, err := New(ks, testMeasurementID).WrapDatagram(conn); wrapped != nil || err == nil {
		t.Fatalf("a TCP connection was wrapped: %v, %v", wrapped, err)
	}

	udp6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		// A host without IPv6 has no IPv6 connection to refuse. This is not
		// a skip, which the kernel lane would reject.
		t.Logf("no IPv6 loopback, IPv6 refusal not exercised: %v", err)
		return
	}
	defer udp6.Close()
	dialed, err := net.DialUDP("udp6", nil, udp6.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer dialed.Close()
	if wrapped, err := New(ks, testMeasurementID).WrapDatagram(dialed); wrapped != nil || err == nil {
		t.Fatalf("an IPv6 UDP connection was wrapped: %v, %v", wrapped, err)
	}
}
