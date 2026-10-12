// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

const (
	countedDatagrams   = 100
	countedPayloadSize = 1400
	// On loopback the counter sees the Ethernet, IPv4 and UDP headers too.
	countedPacketSize = 14 + 20 + 8 + countedPayloadSize
	// A small limit, so that nothing beyond the initial burst is refilled
	// while the datagrams are sent.
	countedLimit = 8000 * bitrate.Bit // 1000 bytes/s
	initialBurst = 65536
)

// loopbackCounter loads the packet counter on the loopback interface, or
// skips like TestBPFCounterLinuxLoad when the kernel refuses the load.
func loopbackCounter(t *testing.T) *BpfCount {
	t.Helper()
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	count, err := NewBPFCount(iface)
	if err != nil {
		for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EACCES, syscall.EINVAL} {
			if errors.Is(err, errno) {
				t.Skipf("counter load requires kernel capabilities (%s): %v", errno, err)
			}
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := count.Close(); err != nil {
			t.Errorf("counter cleanup: %v", err)
		}
	})
	return count
}

// udpCapture returns a raw socket that receives a copy of every UDP packet
// arriving on this host, IP header included.
func udpCapture(t *testing.T) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
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

// capturedTo returns the first captured UDP packet to port.
func capturedTo(t *testing.T, fd int, port int) []byte {
	t.Helper()
	buf := make([]byte, 65536)
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			t.Fatalf("capture: %v", err)
		}
		if n >= 28 && buf[9] == unix.IPPROTO_UDP && int(binary.BigEndian.Uint16(buf[22:24])) == port {
			return append([]byte(nil), buf[:n]...)
		}
	}
	t.Fatal("no datagram was captured")
	return nil
}

// receiveAll counts the datagrams listener receives until it has been quiet
// for a while. It reads while the datagrams are sent, so that the socket's
// receive buffer does not drop any of those the counter lets through.
func receiveAll(listener *net.UDPConn) <-chan int {
	received := make(chan int, 1)
	go func() {
		buf := make([]byte, 2*countedPayloadSize)
		n := 0
		for {
			_ = listener.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if _, _, err := listener.ReadFromUDP(buf); err != nil {
				received <- n
				return
			}
			n++
		}
	}()
	return received
}

// TestBPFCounterChargesDatagramSockets sends more than the initial burst to
// a rate-limited destination on loopback, once through a plain connected UDP
// socket and once through the same socket wrapped by the user-space tagger,
// which sends its datagrams through a raw socket of its own. In both cases
// the counter charges the run's per-destination and executor buckets and
// drops what exceeds them. The receiver never replies, so only the egress
// accounting is observed.
func TestBPFCounterChargesDatagramSockets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tagged bool
	}{
		{"connected socket", false},
		{"tagged datagram socket", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count := loopbackCounter(t)
			captured := udpCapture(t)
			id := uuid.New()

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

			var conn net.Conn = dialed
			var ks *tesla.KeySchedule
			now := time.Now()
			if tc.tagged {
				ks, err = tesla.NewKeySchedule(tesla.Config{Seed: bytes.Repeat([]byte{0x5A}, 32), EpochLength: time.Hour, DisclosureDelay: tesla.MinDisclosureDelay, Epoch: now.Add(-time.Hour)})
				if err != nil {
					t.Fatal(err)
				}
				conn, err = tagger.New(ks, []byte(id.String())).WrapDatagram(dialed)
				if err != nil {
					_ = dialed.Close()
					t.Fatalf("WrapDatagram: %v", err)
				}
			}
			attached, err := count.Attach(conn, id, "127.0.0.1")
			if err != nil {
				_ = conn.Close()
				t.Fatalf("Attach: %v", err)
			}
			if err := count.SetLimit("127.0.0.1", id, countedLimit); err != nil {
				t.Fatal(err)
			}
			if err := count.SetExecLimit(id, countedLimit); err != nil {
				t.Fatal(err)
			}

			received := receiveAll(listener)
			payload := bytes.Repeat([]byte{0xD1}, countedPayloadSize)
			for i := 0; i < countedDatagrams; i++ {
				// A dropped datagram is not a send error: the counter drops it
				// on the interface, after the socket accepted it.
				if _, err := attached.Write(payload); err != nil {
					t.Fatalf("Write %d: %v", i, err)
				}
			}
			got := <-received

			key := countDebugletKey{Uuid: [16]byte(id), Ipv6: netip.MustParseAddr("::ffff:127.0.0.1").As16()}
			var destination, executor countTbState
			destErr := count.objs.PacketSizeMap.Lookup(&key, &destination)
			execErr := count.objs.ExecPacketSizeMap.Lookup(&countExecKey{Uuid: [16]byte(id)}, &executor)
			t.Logf("sent=%d received=%d destination bucket: err=%v tokens=%d; executor bucket: err=%v tokens=%d",
				countedDatagrams, got, destErr, destination.Tokens, execErr, executor.Tokens)

			if tc.tagged {
				pkt := capturedTo(t, captured, port)
				tag := tagger.ReadIPID(pkt)
				ok, err := tesla.VerifyTag(ks.CurrentKey(now), 1, []byte(id.String()), pkt, tag)
				t.Logf("captured datagram tag %04x verifies: %t, %v", tag, ok, err)
				if err != nil || !ok {
					t.Errorf("the datagram on the wire carries tag %04x, which does not verify: %t, %v", tag, ok, err)
				}
			}

			closeErr := attached.Close()
			t.Logf("BpfConn.Close: %v", closeErr)

			if errors.Is(destErr, ebpf.ErrKeyNotExist) || errors.Is(execErr, ebpf.ErrKeyNotExist) {
				t.Fatalf("the datagrams were not charged to the run: destination bucket %v, executor bucket %v", destErr, execErr)
			}
			if destErr != nil || execErr != nil {
				t.Fatalf("bucket lookup: %v, %v", destErr, execErr)
			}
			if destination.Tokens >= initialBurst-countedPacketSize || executor.Tokens >= initialBurst-countedPacketSize {
				t.Errorf("buckets not charged: destination %d, executor %d tokens left of %d", destination.Tokens, executor.Tokens, initialBurst)
			}
			// The burst admits initialBurst/countedPacketSize datagrams; the
			// limit refills less than one more while the test runs.
			if limit := initialBurst/countedPacketSize + 1; got > limit {
				t.Errorf("the receiver got %d of %d datagrams, more than the %d the limit admits", got, countedDatagrams, limit)
			}
			if got == 0 {
				t.Error("the receiver got no datagram: the initial burst should pass")
			}
		})
	}
}
