// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket/netutil"
)

// closeRecorder counts closes of the wrapped connection.
type closeRecorder struct {
	net.Conn
	closes int
	err    error
}

func (c *closeRecorder) Close() error {
	c.closes++
	if err := c.Conn.Close(); err != nil {
		return err
	}
	return c.err
}

// loopbackConn returns one end of an unprivileged loopback TCP or UDP pair.
func loopbackConn(t *testing.T, network string) net.Conn {
	t.Helper()
	switch network {
	case "tcp":
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		conn, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	case "udp":
		receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { receiver.Close() })
		conn, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	t.Fatalf("unknown network %q", network)
	return nil
}

// Regression for #412. Close must not touch debuglet_sk_map: deleting by the
// closed descriptor fails (EBADF) and deleting before close lets the socket's
// remaining data leave unattributed. The counter here has no maps, so any map
// access panics; the destination is registered twice so that a single Detach
// leaves no rate-map delete either.
func TestBpfConnCloseLeavesSocketStorageToTheKernel(t *testing.T) {
	ip := netutil.ToIPv6(netip.MustParseAddr("127.0.0.1"))
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			conn := loopbackConn(t, network)
			recorder := &closeRecorder{Conn: conn}
			counter := new(BpfCount)
			id := uuid.New()
			counter.destinations.Add("127.0.0.1", id, ip)
			counter.destinations.Add("127.0.0.1", id, ip)
			bc := &BpfConn{count: counter, conn: recorder, domain: "127.0.0.1", id: id, resolvedIPv6: ip}
			closeOnce := func() (err error) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Close touched a counter map: %v", r)
					}
				}()
				return bc.Close()
			}
			if err := closeOnce(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if err := closeOnce(); err != nil {
				t.Fatalf("second Close: %v", err)
			}
			if recorder.closes != 1 {
				t.Fatalf("socket closed %d times, want 1", recorder.closes)
			}
			if _, err := conn.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("socket still open after Close: %v", err)
			}
			// Exactly one of the two attachments was detached: one is left.
			if remaining, ok := counter.destinations.Remove("127.0.0.1", id, ip); !ok || remaining != 0 {
				t.Fatalf("attachments left after Close = %d (ok %v), want one detached", remaining, ok)
			}
		})
	}
}

func TestBpfConnClosePrefersCloseError(t *testing.T) {
	closeFailed := errors.New("close failed")
	conn := loopbackConn(t, "tcp")
	recorder := &closeRecorder{Conn: conn, err: closeFailed}
	bc := &BpfConn{count: new(BpfCount), conn: recorder, domain: "127.0.0.1", id: uuid.New()}
	if err := bc.Close(); !errors.Is(err, closeFailed) {
		t.Fatalf("Close = %v, want %v", err, closeFailed)
	}
	if err := bc.Close(); !errors.Is(err, closeFailed) || recorder.closes != 1 {
		t.Fatalf("second Close = %v after %d closes, want the first result once", err, recorder.closes)
	}
}

// TestKernelCounterClosesCountedConns attaches the counter to loopback and
// closes counted TCP (both the dialed and the accepted end) and UDP sockets.
// Each Close must succeed and detach its rate limit, its descriptor number
// must carry no entry once reused, and data a TCP socket still holds when it
// is closed must stay attributed to its run instead of leaving unthrottled.
func TestKernelCounterClosesCountedConns(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	counter, err := NewBPFCount(iface)
	if err != nil {
		for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EACCES, syscall.EINVAL} {
			if errors.Is(err, errno) {
				t.Skipf("counter load requires kernel capabilities: %v", err)
			}
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := counter.Close(); err != nil {
			t.Error(err)
		}
	})
	const addr = "127.0.0.1"
	attach := func(t *testing.T, conn net.Conn, limit bitrate.Bitrate) (net.Conn, uuid.UUID) {
		t.Helper()
		id := uuid.New()
		attached, err := counter.Attach(conn, id, addr)
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		if err := counter.SetLimit(addr, id, limit); err != nil {
			t.Fatal(err)
		}
		if err := counter.SetExecLimit(id, 1<<30); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = counter.DeleteExecLimit(id) })
		return attached, id
	}
	fdOf := func(t *testing.T, conn net.Conn) uint32 {
		t.Helper()
		raw, err := conn.(*BpfConn).conn.(syscall.Conn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var socketFD uint32
		if err := raw.Control(func(fd uintptr) { socketFD = uint32(fd) }); err != nil {
			t.Fatal(err)
		}
		return socketFD
	}
	stored := func(t *testing.T, conn net.Conn) (uuid.UUID, error) {
		t.Helper()
		raw, err := conn.(*BpfConn).conn.(syscall.Conn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var value countDebugletUuid
		var lookupErr error
		if err := raw.Control(func(fd uintptr) {
			lookupErr = counter.objs.DebugletSkMap.Lookup(uint32(fd), &value)
		}); err != nil {
			t.Fatal(err)
		}
		return uuid.UUID(value.Uuid), lookupErr
	}
	exchange := func(t *testing.T, from, to net.Conn) {
		t.Helper()
		payload := []byte("debuglet #412")
		if _, err := from.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := to.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(to, got); err != nil {
			t.Fatalf("counted traffic not delivered: %v", err)
		}
	}
	// reusedFDHasNoEntry opens sockets until one gets the closed descriptor's
	// number and checks that the number does not carry the old entry.
	reusedFDHasNoEntry := func(t *testing.T, fd uint32) {
		t.Helper()
		for range 64 {
			fresh, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { syscall.Close(fresh) })
			if uint32(fresh) > fd {
				break
			}
			if uint32(fresh) == fd {
				var value countDebugletUuid
				if err := counter.objs.DebugletSkMap.Lookup(fd, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("socket reusing descriptor %d has entry %v: %v", fd, uuid.UUID(value.Uuid), err)
				}
				return
			}
		}
		t.Fatalf("descriptor %d was not reused", fd)
	}
	closeCounted := func(t *testing.T, conn net.Conn, id uuid.UUID) {
		t.Helper()
		fd := fdOf(t, conn)
		if err := conn.Close(); err != nil {
			t.Fatalf("Close of counted %s conn: %v", conn.LocalAddr().Network(), err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		var rate uint64
		key := countDebugletKey{Uuid: [16]byte(id), Ipv6: [16]byte{10: 0xff, 11: 0xff, 12: 127, 15: 1}}
		if err := counter.objs.RatesMap.Lookup(&key, &rate); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("rate limit left after Close: %v", err)
		}
		reusedFDHasNoEntry(t, fd)
	}

	t.Run("tcp", func(t *testing.T) {
		listener, err := net.Listen("tcp4", addr+":0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		dialed, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := listener.Accept()
		if err != nil {
			dialed.Close()
			t.Fatal(err)
		}
		client, clientID := attach(t, dialed, 1<<30)
		server, serverID := attach(t, accepted, 1<<30)
		for conn, id := range map[net.Conn]uuid.UUID{client: clientID, server: serverID} {
			if got, err := stored(t, conn); err != nil || got != id {
				t.Fatalf("socket storage = %v, %v; want %v", got, err, id)
			}
		}
		exchange(t, client, server)
		exchange(t, server, client)
		closeCounted(t, client, clientID)
		if got, err := stored(t, server); err != nil || got != serverID {
			t.Fatalf("other socket's storage after Close = %v, %v; want %v", got, err, serverID)
		}
		closeCounted(t, server, serverID)
	})

	t.Run("udp", func(t *testing.T) {
		receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(addr)})
		if err != nil {
			t.Fatal(err)
		}
		defer receiver.Close()
		dialed, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		sender, id := attach(t, dialed, 1<<30)
		if got, err := stored(t, sender); err != nil || got != id {
			t.Fatalf("socket storage = %v, %v; want %v", got, err, id)
		}
		exchange(t, sender, receiver)
		closeCounted(t, sender, id)
	})

	// A guest that fills its send buffer under a low limit and closes must not
	// get the buffered remainder delivered: it keeps the run's UUID and is
	// dropped once the rate entry is gone, instead of leaving unattributed.
	t.Run("write-then-close tail", func(t *testing.T) {
		listener, err := net.Listen("tcp4", addr+":0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		dialed, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := listener.Accept()
		if err != nil {
			dialed.Close()
			t.Fatal(err)
		}
		defer accepted.Close()
		if err := dialed.(*net.TCPConn).SetWriteBuffer(4 << 20); err != nil {
			t.Fatal(err)
		}
		const limit = 16 * 1024 * 8 * bitrate.Bit // 16 KiB/s
		client, _ := attach(t, dialed, limit)

		var received atomic.Int64
		done := make(chan struct{})
		go func() {
			defer close(done)
			buffer := make([]byte, 64<<10)
			for {
				n, err := accepted.Read(buffer)
				received.Add(int64(n))
				if err != nil {
					return
				}
			}
		}()
		if err := client.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		written, _ := client.Write(make([]byte, 8<<20))
		atClose := received.Load()
		dropsBefore, _, err := counter.DropTotals()
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		time.Sleep(time.Second)
		tail := received.Load() - atClose
		dropsAfter, _, err := counter.DropTotals()
		if err != nil {
			t.Fatal(err)
		}
		_ = accepted.SetReadDeadline(time.Now())
		<-done
		t.Logf("written %d, delivered %d before Close, %d after; egress drops %d -> %d",
			written, atClose, tail, dropsBefore[1], dropsAfter[1])
		if unsent := int64(written) - atClose; unsent < 128<<10 {
			t.Fatalf("fixture buffered only %d unsent bytes at Close; the check needs at least 128 KiB", unsent)
		}
		// At most one burst may follow Close; the buffered remainder may not.
		if tail > 64<<10 {
			t.Fatalf("%d bytes left the closed socket after Close, past its rate limit", tail)
		}
		if dropsAfter[1] <= dropsBefore[1] {
			t.Fatalf("no egress drop after Close (%d -> %d): the tail left unattributed", dropsBefore[1], dropsAfter[1])
		}
	})
}
