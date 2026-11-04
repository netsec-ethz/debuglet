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
