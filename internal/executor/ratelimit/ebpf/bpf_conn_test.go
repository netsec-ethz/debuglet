// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// closeRecorder notes when the wrapped connection is closed.
type closeRecorder struct {
	net.Conn
	events *[]string
	err    error
}

func (c *closeRecorder) Close() error {
	*c.events = append(*c.events, "close")
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

// testBpfConn wraps conn the way Attach does, with deleter in place of the
// kernel map and a recorder on the connection's Close.
func testBpfConn(t *testing.T, conn net.Conn, events *[]string, closeErr error, deleter func(fd uint32) error) *BpfConn {
	t.Helper()
	raw, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	return &BpfConn{
		count: new(BpfCount), conn: &closeRecorder{Conn: conn, events: events, err: closeErr}, raw: raw,
		deleteStorage: func(fd uint32) error {
			*events = append(*events, "delete")
			return deleter(fd)
		},
		domain: "127.0.0.1", id: uuid.New(),
	}
}

// Regression for #412: the SK_STORAGE entry is keyed by the descriptor, so it
// must be deleted while the descriptor is open and still names this socket.
func TestBpfConnDeletesSocketStorageBeforeClosing(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			conn := loopbackConn(t, network)
			local := conn.LocalAddr().String()
			var events []string
			var deletedFDs []uint32
			bc := testBpfConn(t, conn, &events, nil, func(fd uint32) error {
				deletedFDs = append(deletedFDs, fd)
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
					return fmt.Errorf("descriptor %d not open at delete: %w", fd, err)
				}
				name, err := unix.Getsockname(int(fd))
				if err != nil {
					return fmt.Errorf("descriptor %d: %w", fd, err)
				}
				in4, ok := name.(*unix.SockaddrInet4)
				if !ok || fmt.Sprintf("%s:%d", net.IP(in4.Addr[:]), in4.Port) != local {
					return fmt.Errorf("descriptor %d names %v, not this socket %s", fd, name, local)
				}
				return nil
			})
			if err := bc.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if fmt.Sprint(events) != "[delete close]" {
				t.Fatalf("order = %v, want [delete close]", events)
			}
			// A second Close neither deletes by a descriptor number that may
			// already name another socket nor closes again.
			if err := bc.Close(); err != nil {
				t.Fatalf("second Close: %v", err)
			}
			if fmt.Sprint(events) != "[delete close]" || len(deletedFDs) != 1 {
				t.Fatalf("second Close acted again: events %v, deletes %v", events, deletedFDs)
			}
			if _, err := conn.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("socket still open after Close: %v", err)
			}
		})
	}
}

func TestBpfConnCloseErrors(t *testing.T) {
	deleteFailed := errors.New("map delete failed")
	closeFailed := errors.New("close failed")
	for _, tc := range []struct {
		name               string
		deleteErr, connErr error
		want               error
	}{
		{name: "entry already gone", deleteErr: fmt.Errorf("lookup: %w", ebpf.ErrKeyNotExist)},
		{name: "delete fails", deleteErr: deleteFailed, want: deleteFailed},
		{name: "close error preferred", deleteErr: deleteFailed, connErr: closeFailed, want: closeFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := loopbackConn(t, "tcp")
			var events []string
			bc := testBpfConn(t, conn, &events, tc.connErr, func(uint32) error { return tc.deleteErr })
			err := bc.Close()
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Close = %v, want %v", err, tc.want)
			}
			if fmt.Sprint(events) != "[delete close]" {
				t.Fatalf("order = %v, want [delete close]", events)
			}
			if _, werr := conn.Write([]byte{1}); !errors.Is(werr, net.ErrClosed) {
				t.Fatalf("socket left open after failed delete: %v", werr)
			}
			if again := bc.Close(); again != err {
				t.Fatalf("second Close = %v, want first result %v", again, err)
			}
		})
	}
}

// TestKernelCounterClosesCountedConns attaches the counter to loopback and
// closes counted TCP (both the dialed and the accepted end) and UDP sockets:
// each Close must succeed and remove only its own socket's entry.
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
	attach := func(t *testing.T, conn net.Conn) (net.Conn, uuid.UUID) {
		t.Helper()
		id := uuid.New()
		attached, err := counter.Attach(conn, id, addr)
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		if err := counter.SetLimit(addr, id, 1<<30); err != nil {
			t.Fatal(err)
		}
		if err := counter.SetExecLimit(id, 1<<30); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = counter.DeleteExecLimit(id) })
		return attached, id
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
	closeCounted := func(t *testing.T, conn net.Conn, id uuid.UUID) {
		t.Helper()
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
		client, clientID := attach(t, dialed)
		server, serverID := attach(t, accepted)
		for conn, id := range map[net.Conn]uuid.UUID{client: clientID, server: serverID} {
			if got, err := stored(t, conn); err != nil || got != id {
				t.Fatalf("socket storage = %v, %v; want %v", got, err, id)
			}
		}
		exchange(t, client, server)
		exchange(t, server, client)
		closeCounted(t, client, clientID)
		// Closing one socket must not remove another socket's entry.
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
		sender, id := attach(t, dialed)
		if got, err := stored(t, sender); err != nil || got != id {
			t.Fatalf("socket storage = %v, %v; want %v", got, err, id)
		}
		exchange(t, sender, receiver)
		closeCounted(t, sender, id)
	})
}
