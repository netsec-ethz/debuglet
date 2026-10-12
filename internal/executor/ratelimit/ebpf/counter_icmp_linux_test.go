// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func countEchoes(conn *net.IPConn, typ ipv4.ICMPType, id int) <-chan int {
	result := make(chan int, 1)
	go func() {
		count := 0
		data := make([]byte, 4096)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := conn.Read(data)
			if err != nil {
				result <- count
				return
			}
			payload := data[:n]
			if n >= 20 && payload[0]>>4 == 4 {
				headerLen := int(payload[0]&15) * 4
				if headerLen < 20 || headerLen > n {
					continue
				}
				payload = payload[headerLen:]
			}
			message, err := icmp.ParseMessage(1, payload)
			if err != nil || message.Type != typ {
				continue
			}
			if echo, ok := message.Body.(*icmp.Echo); ok && echo.ID == id {
				count++
			}
		}
	}()
	return result
}

func TestBPFCounterICMPEgressAndIngressBoundary(t *testing.T) {
	counter := loopbackCounter(t)
	server, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialIP("ip4:icmp", &net.IPAddr{IP: net.ParseIP("127.0.0.2")}, &net.IPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	id := uuid.New()
	conn, err := counter.Attach(client, id, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := counter.SetLimit("127.0.0.1", id, 0); err != nil {
		t.Fatal(err)
	}
	if err := counter.SetExecLimit(id, 0); err != nil {
		t.Fatal(err)
	}
	const echoID = 23194
	requests := countEchoes(server, ipv4.ICMPTypeEcho, echoID)
	replies := countEchoes(client, ipv4.ICMPTypeEchoReply, echoID)
	for seq := range 100 {
		msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: echoID, Seq: seq, Data: make([]byte, countedPayloadSize)}}
		payload, err := msg.Marshal(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	gotRequests, gotReplies := <-requests, <-replies
	want := initialBurst / countedPacketSize
	if gotRequests != want || gotReplies != want {
		t.Fatalf("requests=%d replies=%d, want %d each", gotRequests, gotReplies, want)
	}
	key := countDebugletKey{Uuid: [16]byte(id), Ipv6: netip.MustParseAddr("127.0.0.1").As16()}
	var destination, executor countTbState
	if err := counter.objs.PacketSizeMap.Lookup(&key, &destination); err != nil {
		t.Fatal(err)
	}
	if err := counter.objs.ExecPacketSizeMap.Lookup(&countExecKey{Uuid: [16]byte(id)}, &executor); err != nil {
		t.Fatal(err)
	}
	remaining := uint64(initialBurst - want*countedPacketSize)
	if destination.Tokens != remaining || executor.Tokens != remaining {
		t.Fatalf("destination=%d executor=%d, want egress-only remainder %d", destination.Tokens, executor.Tokens, remaining)
	}
	t.Logf("owned ICMP: %d requests charged; %d replies received without ingress charge", gotRequests, gotReplies)
}
