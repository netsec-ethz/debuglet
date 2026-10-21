// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestInspectTLSVerifiedAndUntrusted(t *testing.T) {
	cert, roots := smSelfSigned(t)
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 2 {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()
	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}})
	env.TlsCfg = &tls.Config{RootCAs: roots}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	info, err := inspectTLS(ctx, env, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if !info.Verified || info.Version == "" || info.Cipher == "" || len(info.Certificates) != 1 || info.PeerAddress != listener.Addr().String() || len(info.Certificates[0].SHA256) != 64 {
		t.Fatalf("incomplete verified result: %+v", info)
	}
	env.TlsCfg = nil
	if result, err := inspectTLS(ctx, env, listener.Addr().String()); err == nil || result.Verified {
		t.Fatalf("untrusted certificate accepted: %+v %v", result, err)
	}
	<-done
}

func TestInspectTLSPolicyAndDeadline(t *testing.T) {
	spec := localSpec()
	spec.TLS = false
	env := policyEnv(t, spec, netpolicy.Run{Addresses: []string{"127.0.0.1"}})
	if _, err := inspectTLS(t.Context(), env, "127.0.0.1:443"); !errors.Is(err, netpolicy.ErrTransportUnavailable) {
		t.Fatalf("TLS policy: %v", err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	env = policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := inspectTLS(ctx, env, listener.Addr().String()); !errors.Is(err, context.Canceled) {
		t.Fatalf("TLS cancellation: %v", err)
	}
}

func TestMatchHopReply(t *testing.T) {
	target := net.IPv4(203, 0, 113, 9)
	echo := &icmp.Echo{ID: 1234, Seq: 5689, Data: []byte("random per-probe nonce")}
	request, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: echo}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	header, err := (&ipv4.Header{Version: 4, Len: 20, TotalLen: 20 + len(request), Protocol: 1, TTL: 1, Src: net.IPv4(198, 51, 100, 3), Dst: target}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	quote := append(header, request[:8]...)
	router := &net.IPAddr{IP: net.IPv4(198, 51, 100, 1)}
	packet := func(kind ipv4.ICMPType, body icmp.MessageBody) []byte {
		b, err := (&icmp.Message{Type: kind, Body: body}).Marshal(nil)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	typeID, _, reached, ok := matchHopReply(packet(ipv4.ICMPTypeTimeExceeded, &icmp.TimeExceeded{Data: quote}), router, target, echo)
	if !ok || reached || typeID != int(ipv4.ICMPTypeTimeExceeded) {
		t.Fatal("matching time exceeded rejected")
	}
	_, _, reached, ok = matchHopReply(packet(ipv4.ICMPTypeEchoReply, echo), &net.IPAddr{IP: target}, target, echo)
	if !ok || !reached {
		t.Fatal("matching target reply rejected")
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[16]++ },
		func(b []byte) { b[24]++ },
		func(b []byte) { b[26]++ },
		func(b []byte) { b[9] = 17 },
		func(b []byte) { binary.BigEndian.PutUint16(b[6:8], 1) },
		func(b []byte) { b[0] = 0x4f },
	} {
		bad := append([]byte(nil), quote...)
		mutate(bad)
		if _, _, _, ok := matchHopReply(packet(ipv4.ICMPTypeTimeExceeded, &icmp.TimeExceeded{Data: bad}), router, target, echo); ok {
			t.Fatal("unrelated or malformed quote accepted")
		}
	}
	if _, _, _, ok := matchHopReply(packet(ipv4.ICMPTypeEchoReply, echo), router, target, echo); ok {
		t.Fatal("echo reply from wrong source accepted")
	}
	if _, _, _, ok := matchHopReply([]byte{1, 2, 3}, router, target, echo); ok {
		t.Fatal("malformed ICMP accepted")
	}
}

func TestHopProbeLoopback(t *testing.T) {
	capability, err := net.ListenPacket("ip4:icmp", "127.0.0.1")
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skip("raw ICMP unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	capability.Close()
	for _, tagged := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "tagged"}[tagged], func(t *testing.T) {
			env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}, RequireICMP: true})
			if tagged {
				schedule, err := tesla.NewKeySchedule(tesla.Config{Seed: make([]byte, 32), EpochLength: time.Hour, Epoch: time.Now().Add(-time.Hour)})
				if err != nil {
					t.Fatal(err)
				}
				env.Tagger = tagger.New(schedule, env.DebugletID[:])
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			reply, err := probeHop(ctx, env, "127.0.0.1", 1)
			if err != nil {
				t.Fatal(err)
			}
			if !reply.Reached || reply.Address != "127.0.0.1" || reply.Type != 0 || reply.DurationMS < 0 {
				t.Fatalf("reply: %+v", reply)
			}
		})
	}
}

func TestHopProbePolicy(t *testing.T) {
	spec := localSpec()
	spec.ICMP = false
	env := policyEnv(t, spec, netpolicy.Run{Addresses: []string{"127.0.0.1"}, RequireICMP: true})
	if _, err := probeHop(t.Context(), env, "127.0.0.1", 1); !errors.Is(err, netpolicy.ErrTransportUnavailable) {
		t.Fatalf("ICMP policy: %v", err)
	}
}

func TestHopProbeBandwidthDeadline(t *testing.T) {
	capability, err := net.ListenPacket("ip4:icmp", "127.0.0.1")
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skip("raw ICMP unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	capability.Close()
	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}, RequireICMP: true})
	env.Limiter.SetAddrCapacity("127.0.0.1", 1)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := probeHop(ctx, env, "127.0.0.1", 1); done <- err }()
	select {
	case err := <-done:
		var timed net.Error
		if !errors.Is(err, context.DeadlineExceeded) && !(errors.As(err, &timed) && timed.Timeout()) {
			t.Fatalf("expected bounded bandwidth wait: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bandwidth wait ignored probe deadline")
	}
}

// This fixture must be an isolated namespace: no packets leave the test host.
// Its source is 11.120.1.1, router 11.120.1.2/11.120.2.1, target 11.120.2.2.
func TestHopProbeRouted(t *testing.T) {
	if os.Getenv("DEBUGLET_ISOLATED_HOP_FIXTURE") != "yes" {
		t.Skip("requires the isolated two-link routing fixture")
	}
	fixture, err := net.InterfaceByName("source0")
	if err != nil {
		t.Fatal("isolated fixture source0 interface missing")
	}
	addresses, err := fixture.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	valid := false
	for _, address := range addresses {
		valid = valid || address.String() == "11.120.1.1/30"
	}
	if !valid {
		t.Fatal("isolated fixture source address missing")
	}
	for _, tagged := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "tagged"}[tagged], func(t *testing.T) {
			env := policyEnv(t, netpolicy.Defaults(), netpolicy.Run{Addresses: []string{"11.120.2.2"}, RequireICMP: true})
			if tagged {
				schedule, err := tesla.NewKeySchedule(tesla.Config{Seed: make([]byte, 32), EpochLength: time.Hour, Epoch: time.Now().Add(-time.Hour)})
				if err != nil {
					t.Fatal(err)
				}
				env.Tagger = tagger.New(schedule, env.DebugletID[:])
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			first, err := probeHop(ctx, env, "11.120.2.2", 1)
			if err != nil || first.Reached || first.Type != int(ipv4.ICMPTypeTimeExceeded) || first.Address != "11.120.1.2" {
				t.Fatalf("first hop: %+v %v", first, err)
			}
			second, err := probeHop(ctx, env, "11.120.2.2", 2)
			if err != nil || !second.Reached || second.Address != "11.120.2.2" {
				t.Fatalf("target: %+v %v", second, err)
			}
		})
	}
}
