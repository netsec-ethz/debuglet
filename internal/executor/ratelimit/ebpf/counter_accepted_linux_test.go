// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBPFCounterAcceptedConnections(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1"} {
		t.Run(ip, func(t *testing.T) {
			counter := loopbackCounter(t)
			listener, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			accepted, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer accepted.Close()
			id := uuid.New()
			conn, err := counter.Attach(accepted, id, ip)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := counter.SetLimit(ip, id, 0); err != nil {
				t.Fatal(err)
			}
			if err := counter.SetExecLimit(id, 0); err != nil {
				t.Fatal(err)
			}
			for _, c := range []net.Conn{client, conn} {
				if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			previous := uint64(initialBurst)
			for _, direction := range []struct{ from, to net.Conn }{{client, conn}, {conn, client}} {
				payload := bytes.Repeat([]byte{'x'}, 1024)
				if _, err := direction.from.Write(payload); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(direction.to, got); err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("stream mismatch: %v", err)
				}
				key := countDebugletKey{Uuid: [16]byte(id), Ipv6: netip.MustParseAddr(ip).As16()}
				var destination, executor countTbState
				if err := counter.objs.PacketSizeMap.Lookup(&key, &destination); err != nil {
					t.Fatal(err)
				}
				if err := counter.objs.ExecPacketSizeMap.Lookup(&countExecKey{Uuid: [16]byte(id)}, &executor); err != nil {
					t.Fatal(err)
				}
				if destination.Tokens > previous-uint64(len(payload)) || executor.Tokens > previous-uint64(len(payload)) {
					t.Fatalf("accepted stream not charged: before=%d destination=%d executor=%d", previous, destination.Tokens, executor.Tokens)
				}
				previous = destination.Tokens
			}
			t.Logf("accepted socket charged ingress and egress after handshake: at least %d skb bytes", initialBurst-previous)
		})
	}
}
