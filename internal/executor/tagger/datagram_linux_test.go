// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package tagger

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// captureSocket returns a raw socket that receives a copy of every IPv4
// packet of protocol arriving on this host, IP header included.
func captureSocket(t *testing.T, protocol int) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if errors.Is(err, unix.EPERM) {
		t.Skipf("skipping test: raw sockets need CAP_NET_RAW: %v", err)
	}
	if err != nil {
		t.Fatalf("capture socket: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	timeout := unix.NsecToTimeval(int64(2 * time.Second))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		t.Fatalf("capture timeout: %v", err)
	}
	return fd
}

// capture returns the first captured packet match accepts.
func capture(t *testing.T, fd int, match func(pkt []byte) bool) []byte {
	t.Helper()
	buf := make([]byte, 65536)
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			t.Fatalf("capture: %v", err)
		}
		if pkt := buf[:n]; n >= ipv4HeaderLen && match(pkt) {
			return append([]byte(nil), pkt...)
		}
	}
	t.Fatal("the packet was not captured")
	return nil
}

func verifyCaptured(t *testing.T, what string, ks *tesla.KeySchedule, now time.Time, pkt []byte) {
	t.Helper()
	tag := ReadIPID(pkt)
	ok, err := tesla.VerifyTag(ks.CurrentKey(now), 1, testMeasurementID, pkt, tag)
	if err != nil || !ok {
		t.Errorf("%s: the tag %04x on the wire does not verify: %v, %v", what, tag, ok, err)
	}
}

// TestTaggedDatagramsReachTheWire sends UDP and ICMP through WrapDatagram on
// loopback and checks the packets as the host receives them: each carries a
// tag the verifier accepts, and the UDP payload reaches its socket intact.
func TestTaggedDatagramsReachTheWire(t *testing.T) {
	now := time.Now()
	ks, err := tesla.NewKeySchedule(tesla.Config{Seed: fixedSeed, Delay: time.Hour, Epoch: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	tgr := New(ks, testMeasurementID)

	t.Run("udp", func(t *testing.T) {
		captured := captureSocket(t, unix.IPPROTO_UDP)
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		port := listener.LocalAddr().(*net.UDPAddr).Port
		dialed, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		wrapped, err := tgr.WrapDatagram(dialed)
		if err != nil {
			t.Fatalf("WrapDatagram: %v", err)
		}
		defer wrapped.Close()

		payload := []byte("tagged in user space")
		if n, err := wrapped.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("Write = %d, %v", n, err)
		}
		pkt := capture(t, captured, func(pkt []byte) bool {
			return pkt[9] == protoUDP && int(binary.BigEndian.Uint16(pkt[22:24])) == port &&
				bytes.Equal(pkt[ipv4HeaderLen+udpHeaderLen:], payload)
		})
		verifyCaptured(t, "udp", ks, now, pkt)

		if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 64)
		n, from, err := listener.ReadFromUDP(got)
		if err != nil || !bytes.Equal(got[:n], payload) {
			t.Fatalf("the listener received %q, %v", got[:n], err)
		}
		if from.Port != wrapped.LocalAddr().(*net.UDPAddr).Port {
			t.Errorf("the datagram came from port %d, not the connection's %d", from.Port, wrapped.LocalAddr().(*net.UDPAddr).Port)
		}
	})

	t.Run("write deadline", func(t *testing.T) {
		captureSocket(t, unix.IPPROTO_UDP) // skips without CAP_NET_RAW
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		dialed, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		wrapped, err := tgr.WrapDatagram(dialed)
		if err != nil {
			t.Fatalf("WrapDatagram: %v", err)
		}
		defer wrapped.Close()
		if err := wrapped.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := wrapped.Write([]byte("late")); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write after its deadline = %v, want os.ErrDeadlineExceeded", err)
		}
	})

	t.Run("icmp", func(t *testing.T) {
		captured := captureSocket(t, unix.IPPROTO_ICMP)
		dialed, err := net.DialIP("ip4:icmp", nil, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		wrapped, err := tgr.WrapDatagram(dialed)
		if err != nil {
			t.Fatalf("WrapDatagram: %v", err)
		}
		defer wrapped.Close()

		// An echo request of even length; its checksum is the same
		// one's-complement sum as an IPv4 header's.
		echo := []byte{8, 0, 0, 0, 0xDE, 0xB1, 0, 1, 't', 'a', 'g', 's'}
		binary.BigEndian.PutUint16(echo[2:4], IPv4Checksum(echo))
		if n, err := wrapped.Write(echo); err != nil || n != len(echo) {
			t.Fatalf("Write = %d, %v", n, err)
		}
		pkt := capture(t, captured, func(pkt []byte) bool {
			return pkt[9] == protoICMP && pkt[ipv4HeaderLen] == 8 &&
				bytes.Equal(pkt[ipv4HeaderLen+4:ipv4HeaderLen+6], echo[4:6])
		})
		verifyCaptured(t, "icmp", ks, now, pkt)
	})
}
