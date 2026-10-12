// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// socketFD returns the descriptor number of conn's socket.
func socketFD(t *testing.T, conn interface {
	SyscallConn() (syscall.RawConn, error)
}) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	fd := -1
	if err := raw.Control(func(s uintptr) { fd = int(s) }); err != nil {
		t.Fatal(err)
	}
	return fd
}

// TestBPFConnCloseSucceeds closes counted connections under the eBPF
// counter: the close of a counted socket reports no error.
func TestBPFConnCloseSucceeds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tagged bool
	}{
		{"connected socket", false},
		{"tagged datagram socket", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count := loopbackCounter(t)
			if tc.tagged {
				udpCapture(t) // skips without CAP_NET_RAW, which the tagger's raw socket needs
			}
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			dialed, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			var conn net.Conn = dialed
			id := uuid.New()
			if tc.tagged {
				now := time.Now()
				ks, err := tesla.NewKeySchedule(tesla.Config{Seed: bytes.Repeat([]byte{0x5A}, 32), EpochLength: time.Hour, DisclosureDelay: tesla.MinDisclosureDelay, Epoch: now.Add(-time.Hour)})
				if err != nil {
					t.Fatal(err)
				}
				if conn, err = tagger.New(ks, []byte(id.String())).WrapDatagram(dialed); err != nil {
					_ = dialed.Close()
					t.Fatalf("WrapDatagram: %v", err)
				}
			}
			attached, err := count.Attach(conn, id, "127.0.0.1")
			if err != nil {
				_ = conn.Close()
				t.Fatalf("Attach: %v", err)
			}
			// As a run's connection does, the counted connection has a limit.
			if err := count.SetLimit("127.0.0.1", id, countedLimit); err != nil {
				t.Fatal(err)
			}
			if _, err := attached.Write([]byte("counted")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := attached.Close(); err != nil {
				t.Errorf("Close of a counted connection: %v", err)
			}
		})
	}
}

// reopeningConn runs reopen right after its socket is closed, before the
// counted connection that wraps it has finished closing.
type reopeningConn struct {
	*net.UDPConn
	reopen func()
}

func (c *reopeningConn) Close() error {
	err := c.UDPConn.Close()
	c.reopen()
	return err
}

// TestBPFConnCloseKeepsReusedDescriptor closes a counted socket A while
// another run's socket B is registered under the descriptor number A just
// released. Closing A must leave B's association intact, so B's egress is
// still charged to B's run.
func TestBPFConnCloseKeepsReusedDescriptor(t *testing.T) {
	count := loopbackCounter(t)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dst := listener.LocalAddr().(*net.UDPAddr)

	dialedA, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		t.Fatal(err)
	}
	fdA := socketFD(t, dialedA)
	idA, idB := uuid.New(), uuid.New()

	var attachedB net.Conn
	var fdB int
	var errB error
	connA := &reopeningConn{UDPConn: dialedA, reopen: func() {
		// The kernel hands out the lowest free descriptor number, so the
		// next socket normally takes the one A released. Another
		// descriptor opened concurrently in the process may take it first;
		// try a few times.
		var spare []*net.UDPConn
		defer func() {
			for _, c := range spare {
				_ = c.Close()
			}
		}()
		for attempt := 0; attempt < 5; attempt++ {
			dialedB, err := net.DialUDP("udp4", nil, dst)
			if err != nil {
				errB = err
				return
			}
			if fdB = socketFD(t, dialedB); fdB != fdA {
				spare = append(spare, dialedB)
				continue
			}
			attachedB, errB = count.Attach(dialedB, idB, "127.0.0.1")
			if errB != nil {
				_ = dialedB.Close()
				return
			}
			var info countDebugletUuid
			if err := count.objs.DebugletSkMap.Lookup(uint32(fdB), &info); err != nil {
				errB = fmt.Errorf("B's socket association before A's Close finished: %w", err)
			}
			return
		}
		errB = errors.New("no new socket reused the released descriptor number")
	}}
	attachedA, err := count.Attach(connA, idA, "127.0.0.1")
	if err != nil {
		_ = dialedA.Close()
		t.Fatalf("Attach A: %v", err)
	}
	if err := count.SetLimit("127.0.0.1", idA, countedLimit); err != nil {
		t.Fatal(err)
	}
	closeErr := attachedA.Close()
	if attachedB != nil {
		defer attachedB.Close()
	}
	if errB != nil {
		t.Fatalf("socket B: %v", errB)
	}
	t.Logf("socket A had descriptor %d, socket B has %d; A.Close: %v", fdA, fdB, closeErr)
	if closeErr != nil {
		t.Errorf("Close of A: %v", closeErr)
	}

	var info countDebugletUuid
	if err := count.objs.DebugletSkMap.Lookup(uint32(fdB), &info); err != nil {
		t.Fatalf("B's socket association after A's Close: %v", err)
	}
	if info.Uuid != [16]byte(idB) {
		t.Fatalf("B's socket is associated with run %x, want %x", info.Uuid, idB)
	}

	if err := count.SetLimit("127.0.0.1", idB, countedLimit); err != nil {
		t.Fatal(err)
	}
	if err := count.SetExecLimit(idB, countedLimit); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0xD1}, countedPayloadSize)
	for i := 0; i < 3; i++ {
		if _, err := attachedB.Write(payload); err != nil {
			t.Fatalf("Write %d through B: %v", i, err)
		}
	}
	key := countDebugletKey{Uuid: [16]byte(idB), Ipv6: netip.MustParseAddr("::ffff:127.0.0.1").As16()}
	var destination, executor countTbState
	if err := count.objs.PacketSizeMap.Lookup(&key, &destination); err != nil {
		t.Fatalf("B's destination bucket: %v", err)
	}
	if err := count.objs.ExecPacketSizeMap.Lookup(&countExecKey{Uuid: [16]byte(idB)}, &executor); err != nil {
		t.Fatalf("B's executor bucket: %v", err)
	}
	t.Logf("B's buckets: destination %d, executor %d tokens left of %d", destination.Tokens, executor.Tokens, initialBurst)
	if destination.Tokens >= initialBurst-countedPacketSize || executor.Tokens >= initialBurst-countedPacketSize {
		t.Errorf("B's buckets not charged: destination %d, executor %d tokens left of %d", destination.Tokens, executor.Tokens, initialBurst)
	}
}
