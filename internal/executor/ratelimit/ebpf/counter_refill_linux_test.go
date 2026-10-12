// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"golang.org/x/sys/unix"
)

func monotonicCounterTime(t *testing.T) uint64 {
	t.Helper()
	var stamp unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &stamp); err != nil {
		t.Fatal(err)
	}
	return uint64(stamp.Nano())
}

func TestBPFCounterRefillConservesRejectedTraffic(t *testing.T) {
	counter := loopbackCounter(t)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	conn, err := counter.Attach(client, id, "127.0.0.1")
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	defer conn.Close()
	if err := counter.SetLimit("127.0.0.1", id, 4000*bitrate.Bit); err != nil {
		t.Fatal(err)
	}
	if err := counter.SetExecLimit(id, 0); err != nil {
		t.Fatal(err)
	}
	now := monotonicCounterTime(t)
	key := countDebugletKey{Uuid: [16]byte(id), Ipv6: netip.MustParseAddr("127.0.0.1").As16()}
	if err := counter.objs.PacketSizeMap.Update(&key, &countTbState{T_last: now - uint64(time.Second)}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := counter.objs.ExecPacketSizeMap.Update(&countExecKey{Uuid: [16]byte(id)}, &countTbState{Tokens: initialBurst, T_last: now}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	received := receiveAll(listener)
	for range 20 {
		if _, err := conn.Write(make([]byte, countedPayloadSize)); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Duration(monotonicCounterTime(t) - now)
	maximum := int((500 * (time.Second + elapsed)) / time.Second / countedPacketSize)
	got := <-received
	t.Logf("20 attempts in %s; 500 B/s budget permits at most %d datagrams, observed %d", elapsed, maximum, got)
	if got > maximum {
		t.Fatalf("rejected packets minted allowance: delivered %d, budget permits %d", got, maximum)
	}
	for _, phase := range []struct {
		name string
		age  time.Duration
		want int
	}{
		{"refill eventually admits a packet", 4 * time.Second, 1},
		{"older packet timestamp cannot refill", -time.Second, 0},
	} {
		t.Run(phase.name, func(t *testing.T) {
			stamp := uint64(int64(monotonicCounterTime(t)) - int64(phase.age))
			if err := counter.objs.PacketSizeMap.Update(&key, &countTbState{T_last: stamp}, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			received := receiveAll(listener)
			for range 20 {
				if _, err := conn.Write(make([]byte, countedPayloadSize)); err != nil {
					t.Fatal(err)
				}
			}
			if got := <-received; got != phase.want {
				t.Fatalf("delivered %d packets, want %d", got, phase.want)
			}
		})
	}
}

func TestBPFCounterExecutorRefillUsesSharedTimestamp(t *testing.T) {
	counter := loopbackCounter(t)
	id := uuid.New()
	if err := counter.SetExecLimit(id, 4000*bitrate.Bit); err != nil {
		t.Fatal(err)
	}
	type peer struct {
		conn     net.Conn
		received <-chan int
	}
	peers := make([]peer, 0, 3)
	now := monotonicCounterTime(t)
	for _, ip := range []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"} {
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		client, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		conn, err := counter.Attach(client, id, ip)
		if err != nil {
			_ = client.Close()
			t.Fatal(err)
		}
		defer conn.Close()
		if err := counter.SetLimit(ip, id, 0); err != nil {
			t.Fatal(err)
		}
		key := countDebugletKey{Uuid: [16]byte(id), Ipv6: netip.MustParseAddr(ip).As16()}
		if err := counter.objs.PacketSizeMap.Update(&key, &countTbState{Tokens: initialBurst, T_last: now - uint64(time.Second)}, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		peers = append(peers, peer{conn, receiveAll(listener)})
	}
	now = monotonicCounterTime(t)
	if err := counter.objs.ExecPacketSizeMap.Update(&countExecKey{Uuid: [16]byte(id)}, &countTbState{T_last: now}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for _, peer := range peers {
		if _, err := peer.conn.Write(make([]byte, countedPayloadSize)); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Duration(monotonicCounterTime(t) - now)
	maximum := int((500 * elapsed) / time.Second / countedPacketSize)
	got := 0
	for _, peer := range peers {
		got += <-peer.received
	}
	t.Logf("3 targets in %s; shared 500 B/s budget permits at most %d datagrams, observed %d", elapsed, maximum, got)
	if got > maximum {
		t.Fatalf("destination ages minted executor allowance: delivered %d, budget permits %d", got, maximum)
	}
}
