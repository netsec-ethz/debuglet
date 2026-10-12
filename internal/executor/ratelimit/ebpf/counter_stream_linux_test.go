// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBPFCounterStreamConnections(t *testing.T) {
	for _, fixture := range []struct {
		ip        string
		encrypted bool
	}{{"127.0.0.1", false}, {"127.0.0.1", true}, {"::1", false}, {"::1", true}} {
		t.Run(fmt.Sprintf("%s/tls=%t", fixture.ip, fixture.encrypted), func(t *testing.T) {
			counter := loopbackCounter(t)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "counter fixture\n")
			}))
			_ = server.Listener.Close()
			listener, err := net.Listen("tcp", net.JoinHostPort(fixture.ip, "0"))
			if err != nil {
				t.Fatal(err)
			}
			server.Listener = listener
			if fixture.encrypted {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			addr := server.Listener.Addr().String()
			var client net.Conn
			if fixture.encrypted {
				cfg := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
				client, err = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, cfg)
			} else {
				client, err = net.DialTimeout("tcp", addr, time.Second)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			id := uuid.New()
			conn, err := counter.Attach(client, id, fixture.ip)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := counter.SetLimit(fixture.ip, id, 0); err != nil {
				t.Fatal(err)
			}
			if err := counter.SetExecLimit(id, 0); err != nil {
				t.Fatal(err)
			}
			if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", addr); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || string(body) != "counter fixture\n" {
				t.Fatalf("body=%q err=%v", body, err)
			}
			var destination, executor countTbState
			key := countDebugletKey{Uuid: [16]byte(id), Ipv6: netip.MustParseAddr(fixture.ip).As16()}
			if err := counter.objs.PacketSizeMap.Lookup(&key, &destination); err != nil {
				t.Fatal(err)
			}
			if err := counter.objs.ExecPacketSizeMap.Lookup(&countExecKey{Uuid: [16]byte(id)}, &executor); err != nil {
				t.Fatal(err)
			}
			if destination.Tokens >= initialBurst || executor.Tokens >= initialBurst {
				t.Fatalf("stream not charged: destination=%d executor=%d", destination.Tokens, executor.Tokens)
			}
			t.Logf("HTTP round trip charged destination=%d executor=%d skb bytes", initialBurst-destination.Tokens, initialBurst-executor.Tokens)
		})
	}
}
