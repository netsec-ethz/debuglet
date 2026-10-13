// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package connectivity

import (
	"bytes"
	"context"
	"errors"
	"io"
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

func TestTCPChallengeDelayedAuthenticatedReply(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	token := bytes.Repeat([]byte{7}, TokenSize)
	done := make(chan error, 1)
	go func() { done <- Check(t.Context(), "tcp", listener.Addr().String(), token) }()
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	_ = peer.SetDeadline(time.Now().Add(2 * time.Second))
	challenge := make([]byte, TokenSize)
	if _, err := io.ReadFull(peer, challenge); err != nil {
		t.Fatal(err)
	}
	// A valid reply delayed beyond the former 400ms budget remains reachable.
	time.Sleep(550 * time.Millisecond)
	if _, err := peer.Write(answer(token, challenge)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("delayed authenticated reply refused: %v", err)
	}
}

func TestTCPChallengeSilentPeerBounded(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Check(ctx, "tcp", listener.Addr().String(), make([]byte, TokenSize)) }()
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	select {
	case err := <-done:
		if err == nil || ctx.Err() != nil {
			t.Fatalf("silent peer did not fail within the challenge budget: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("silent peer outlasted the heartbeat call budget")
	}
}

func TestTCPResponderSilentPeerBounded(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{7}, TokenSize)
	t.Cleanup(ServeTCP(listener, token))
	peer, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("responder did not close its silent peer within the heartbeat budget: %v", err)
	}
	if err := Check(t.Context(), "tcp", listener.Addr().String(), token); err != nil {
		t.Fatalf("silent peer blocked the next authenticated challenge: %v", err)
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
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(peer, make([]byte, TokenSize)); err != nil {
		t.Fatal(err)
	}
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
