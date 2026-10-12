// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux && counter_matrix

package ebpf

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"golang.org/x/sys/unix"
)

func TestCounterMatrixHandshakeBoundary(t *testing.T) {
	isolatedCounterMatrix(t)
	counter := loopbackCounter(t)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	capture := matrixPacketCapture(t, "lo", unix.IPPROTO_TCP, listener.Addr().(*net.TCPAddr).Port)
	id := uuid.New()
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
	observed := <-capture
	if observed.SYN != 2 || observed.Packets < 3 || observed.Error != "" {
		t.Fatalf("incomplete handshake capture: %+v", observed)
	}
	var state countTbState
	if err := counter.objs.ExecPacketSizeMap.Lookup(&countExecKey{Uuid: [16]byte(id)}, &state); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("unexpected pre-Attach bucket: %v", err)
	}
	conn, err := counter.Attach(client, id, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	t.Logf("captured handshake before Attach: %+v; connection/accepted socket exists before per-run association", observed)
}

func TestCounterMatrixOversizedBufferBoundary(t *testing.T) {
	isolatedCounterMatrix(t)
	counter := loopbackCounter(t)
	client, server, _ := matrixTCPPair(t, 0)
	id := uuid.New()
	conn, err := counter.Attach(client, id, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := counter.SetLimit("127.0.0.1", id, bitrate.Gigabit); err != nil {
		t.Fatal(err)
	}
	if err := counter.SetExecLimit(id, bitrate.Gigabit); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	written := make(chan error, 1)
	go func() { _, err := conn.Write(make([]byte, 1024*1024)); written <- err }()
	n, readErr := io.ReadFull(server, make([]byte, 1024*1024))
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if readErr == nil {
		t.Fatal("fixture did not reach the large-buffer boundary")
	}
	previousVerdicts, previousBytes, err := counter.DropTotals()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(2500 * time.Millisecond)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			verdicts, bytes, err := counter.DropTotals()
			if err != nil {
				t.Fatal(err)
			}
			dropped := verdicts[1] - previousVerdicts[1]
			droppedBytes := bytes[1] - previousBytes[1]
			if dropped > 0 && droppedBytes > initialBurst*dropped {
				info := matrixTCPInfo(t, client)
				t.Logf("large loopback buffer cannot fit64KiB burst: read=%d bytes; isolated retry drops=%d skb_bytes=%d mean=%d snd_mss=%d path_mtu=%d", n, dropped, droppedBytes, droppedBytes/dropped, info.Snd_mss, info.Pmtu)
				return
			}
			previousVerdicts, previousBytes = verdicts, bytes
		case <-deadline.C:
			t.Fatalf("did not isolate an oversized retry; partial_read=%d err=%v", n, readErr)
		}
	}
}
