// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package hostconn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/ebpf"
	"golang.org/x/sys/unix"
)

// Withholding allowance for the first data packet forces an actual TCP retry.
// Before the fix Drain saw only the accounting wrapper, returned immediately,
// and Close removed the destination rate, so no retransmission could arrive.
func TestDrainKeepsCountedTCPRetransmissionAlive(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	counter, err := ebpf.NewBPFCount(iface)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EINVAL) {
			t.Skipf("eBPF capabilities required: %v", err)
		}
		t.Fatal(err)
	}
	defer counter.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	raw, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := listener.Accept()
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	defer peer.Close()
	id := uuid.New()
	host, err := NewConnection(context.Background(), counter, id, raw, HostConnOpts{ConnAddr: "127.0.0.1", MaximumBandwidth: bitrate.Gigabit, SocketType: socket.SocketTypeTCP})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	payload := bytes.Repeat([]byte("native-message"), 32)
	// No executor-rate entry exists yet: the first data segment is dropped.
	if _, err := host.Write(payload); err != nil {
		t.Fatal(err)
	}
	restored := make(chan error, 1)
	go func() { time.Sleep(150 * time.Millisecond); restored <- counter.SetExecLimit(id, bitrate.Gigabit) }()
	start := time.Now()
	host.Drain(context.Background())
	elapsed := time.Since(start)
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-restored; err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	actual := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, actual); err != nil {
		t.Fatalf("frame lost after successful write and close: %v (drain %s)", err, elapsed)
	}
	if !bytes.Equal(actual, payload) {
		t.Fatal("frame changed")
	}
	if elapsed < 100*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("drain did not wait for bounded retransmission: %s", elapsed)
	}
	drops, _, err := counter.DropTotals()
	if err != nil {
		t.Fatal(err)
	}
	if drops[1] == 0 {
		t.Fatal("fixture did not observe the forced egress drop")
	}
	t.Logf("complete %d-byte frame received after %s; egress drops=%d", len(payload), elapsed, drops[1])
}

// Native messages are one frame per connection. The receiver closes as soon as
// it has read that frame, while the sender may still be waiting for its ACK.
// Exercise both counted ends, including delayed ACKs, rather than a raw peer.
func TestDrainCountedReceiverClose(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	counter, err := ebpf.NewBPFCount(iface)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EINVAL) {
			t.Skipf("eBPF capabilities required: %v", err)
		}
		t.Fatal(err)
	}
	defer counter.Close()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for round := range 64 {
		client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		server, err := listener.AcceptTCP()
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		attach := func(conn *net.TCPConn) *HostConn {
			id := uuid.New()
			host, err := NewConnection(context.Background(), counter, id, conn, HostConnOpts{ConnAddr: "127.0.0.1", MaximumBandwidth: bitrate.Gigabit, SocketType: socket.SocketTypeTCP})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { host.Close(); counter.DeleteExecLimit(id) })
			if err := counter.SetExecLimit(id, bitrate.Gigabit); err != nil {
				t.Fatal(err)
			}
			return host
		}
		sender, receiver := attach(client), attach(server)
		raw, err := server.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var optionErr error
		if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, 0) }); err != nil || optionErr != nil {
			t.Fatalf("set delayed ACK: %v, %v", err, optionErr)
		}
		payload := bytes.Repeat([]byte("native-message"), 32)
		if _, err := sender.Write(payload); err != nil {
			t.Fatal(err)
		}
		_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
		actual := make([]byte, len(payload))
		if _, err := io.ReadFull(receiver, actual); err != nil || !bytes.Equal(actual, payload) {
			t.Fatalf("round %d receive: %v", round, err)
		}
		if err := receiver.DrainTCP(context.Background()); err != nil {
			t.Fatalf("round %d receiver drain: %v", round, err)
		}
		if err := receiver.Close(); err != nil {
			t.Fatalf("round %d receiver close: %v", round, err)
		}
		if err := sender.DrainTCP(context.Background()); err != nil {
			t.Fatalf("round %d sender lost receiver ACK: %v", round, err)
		}
		if err := sender.Close(); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("64 complete frames acknowledged with immediate counted receiver close")
}

func TestDrainTCPReportsPeerReset(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if _, err := client.Write([]byte("unconsumed frame")); err != nil {
		t.Fatal(err)
	}
	if err := server.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	// Observe the reset without consuming SO_ERROR, as DrainTCP is the first
	// operation after Write in the native send path.
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		var info *unix.TCPInfo
		var infoErr error
		if err := raw.Control(func(fd uintptr) { info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) }); err != nil || infoErr != nil {
			t.Fatalf("TCP info: %v, %v", err, infoErr)
		}
		if info.State == unix.BPF_TCP_CLOSE {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("peer reset did not arrive")
		}
		time.Sleep(time.Millisecond)
	}
	host := &HostConn{conn: client, tcp: client}
	if err := host.DrainTCP(context.Background()); err == nil {
		t.Fatal("drain reported successful delivery after peer reset")
	}
}
