// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package tagger

import (
	"bytes"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"net"
	"testing"
	"time"
)

func TestTaggedProbePreservesTTL(t *testing.T) {
	fd := captureSocket(t, unix.IPPROTO_ICMP)
	now := time.Now()
	schedule, err := tesla.NewKeySchedule(tesla.Config{Seed: fixedSeed, EpochLength: time.Hour, Epoch: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("ip4:icmp", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := New(schedule, testMeasurementID).WrapDatagram(conn)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	defer wrapped.Close()
	if err := wrapped.(*taggedDatagramConn).SetTTL(3); err != nil {
		t.Fatal(err)
	}
	payload, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 31781, Seq: 1, Data: []byte("explicit-hop-ttl")}}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.Write(payload); err != nil {
		t.Fatal(err)
	}
	packet := capture(t, fd, func(packet []byte) bool { return len(packet) >= 20 && bytes.Equal(packet[20:], payload) })
	if packet[8] != 3 {
		t.Fatalf("TTL = %d", packet[8])
	}
	verifyCaptured(t, "hop", schedule, now, packet)
}
