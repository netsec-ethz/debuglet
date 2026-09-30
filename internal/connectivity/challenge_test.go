// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package connectivity

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestOwnedDualStackListenerChallenges(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(host+"/"+transport, func(t *testing.T) {
				token := bytes.Repeat([]byte{7}, TokenSize)
				var endpoint string
				var stop func()
				if transport == "tcp" {
					listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(host)})
					if err != nil {
						t.Fatal(err)
					}
					endpoint, stop = listener.Addr().String(), ServeTCP(listener, token)
				} else {
					conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
					if err != nil {
						t.Fatal(err)
					}
					endpoint, stop = conn.LocalAddr().String(), ServeUDP(conn, token)
				}
				t.Cleanup(stop)
				if err := Check(t.Context(), transport, endpoint, token); err != nil {
					t.Fatal(err)
				}
				if err := Check(t.Context(), transport, endpoint, bytes.Repeat([]byte{9}, TokenSize)); err == nil {
					t.Fatal("wrong listener identity accepted")
				}
				stop()
				if err := Check(t.Context(), transport, endpoint, token); err == nil {
					t.Fatal("closed listener remained reachable")
				}
			})
		}
	}
}

func TestChallengeCancellationJoins(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Check(ctx, "tcp", listener.Addr().String(), make([]byte, TokenSize)) }()
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled challenge succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled challenge did not join")
	}
}
