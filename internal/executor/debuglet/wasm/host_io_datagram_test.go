// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func datagramEnv(t *testing.T, spec netpolicy.Spec) (*WasmEnv, *net.UDPConn) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	env := policyEnv(t, spec, netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenUDP: true})
	env.UdpServer = server
	peer, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	return env, peer
}

func TestUDPReceiveTimeoutTruncationAndEmpty(t *testing.T) {
	env, peer := datagramEnv(t, localSpec())
	mem := newGuestModule(t).Memory()
	receive := HostIOReceiveUDP(env)
	for _, timeout := range []time.Duration{-1, time.Millisecond} {
		result := receive(context.Background(), mem, 1024, 8, 2048, 128, 4096, int64(timeout))
		if uint32(result>>32) != guestio.Timeout {
			t.Fatalf("timeout result: %x", result)
		}
	}
	large := bytes.Repeat([]byte("x"), 12000)
	if _, err := peer.Write(large); err != nil {
		t.Fatal(err)
	}
	result := receive(context.Background(), mem, 1024, 8, 2048, 128, 4096, int64(time.Second))
	if result != 8 {
		t.Fatalf("truncated receive: %x", result)
	}
	length, _ := mem.ReadUint32Le(4100)
	truncated, _ := mem.ReadUint32Le(4104)
	if length != uint32(len(large)) || truncated != 1 {
		t.Fatalf("size=%d truncated=%d", length, truncated)
	}
	sourceLen, _ := mem.ReadUint32Le(4096)
	source, _ := mem.Read(2048, sourceLen)
	if string(source) != peer.LocalAddr().String() {
		t.Fatalf("source=%s", source)
	}
	if _, err := peer.Write(nil); err != nil {
		t.Fatal(err)
	}
	result = receive(context.Background(), mem, 1024, 8, 2048, 128, 4096, int64(time.Second))
	length, _ = mem.ReadUint32Le(4100)
	truncated, _ = mem.ReadUint32Le(4104)
	if result != 0 || length != 0 || truncated != 0 {
		t.Fatalf("empty datagram: %x size=%d truncated=%d", result, length, truncated)
	}
}

func TestUDPReceiveRefusedPeerNeverReachesGuest(t *testing.T) {
	env, peer := datagramEnv(t, localSpec())
	refused, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(secondLoopback)}, env.UdpServer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		aliasUnavailable(t, err)
	}
	defer refused.Close()
	if _, err := refused.Write([]byte("PRIVATE")); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	mem := newGuestModule(t).Memory()
	mem.Write(1024, bytes.Repeat([]byte("!"), 16))
	result := HostIOReceiveUDP(env)(context.Background(), mem, 1024, 16, 2048, 128, 4096, int64(time.Second))
	got, _ := mem.Read(1024, 16)
	if result != 2 || string(got) != "ok!!!!!!!!!!!!!!" {
		t.Fatalf("result=%x payload=%q", result, got)
	}
}

func TestUDPReplyPreservesListenerAndEmptyPackets(t *testing.T) {
	env, peer := datagramEnv(t, localSpec())
	mem := newGuestModule(t).Memory()
	address := peer.LocalAddr().String()
	mem.Write(1024, []byte(address))
	mem.Write(2048, []byte("reply"))
	if _, err := peer.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if result := HostIOReceiveUDP(env)(context.Background(), mem, 4096, 32, 8192, 128, 12288, int64(time.Second)); result != 7 {
		t.Fatalf("request=%x", result)
	}
	for _, size := range []uint32{5, 0, 5} {
		result := HostIOReplyUDP(env)(context.Background(), mem, 1024, uint32(len(address)), 2048, size, int64(time.Second))
		if result != uint64(size) {
			t.Fatalf("reply result: %x", result)
		}
		peer.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 32)
		n, err := peer.Read(buf)
		if err != nil || n != int(size) || string(buf[:n]) != "reply"[:size] {
			t.Fatalf("reply=%q err=%v", buf[:n], err)
		}
		// Replies are written by the same port, so this connected peer accepts
		// them. It can then send again to the still-open listener.
		if _, err := peer.Write([]byte("next")); err != nil {
			t.Fatal(err)
		}
		result = HostIOReceiveUDP(env)(context.Background(), mem, 4096, 32, 8192, 128, 12288, int64(time.Second))
		if result != 4 {
			t.Fatalf("listener after reply: %x", result)
		}
	}
}

func TestUDPReplyRequiresOutboundAdmissionAndBandwidth(t *testing.T) {
	for _, mode := range []string{"no receipt", "port", "destination", "bandwidth", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			spec := localSpec()
			if mode == "port" {
				spec.PermittedPorts = "1"
			}
			env, peer := datagramEnv(t, spec)
			mem := newGuestModule(t).Memory()
			address := peer.LocalAddr().String()
			if mode == "destination" {
				address = net.JoinHostPort(secondLoopback, "1234")
			}
			mem.Write(1024, []byte(address))
			mem.Write(2048, []byte("no"))
			if mode != "no receipt" {
				if _, err := peer.Write([]byte("request")); err != nil {
					t.Fatal(err)
				}
				if result := HostIOReceiveUDP(env)(context.Background(), mem, 4096, 32, 8192, 128, 12288, int64(time.Second)); result != 7 {
					t.Fatalf("request=%x", result)
				}
			}
			if mode == "bandwidth" {
				env.Limiter.SetAddrCapacity("127.0.0.1", bitrate.Bitrate(0))
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			result := HostIOReplyUDP(env)(ctx, mem, 1024, uint32(len(address)), 2048, 2, int64(10*time.Millisecond))
			status := uint32(result >> 32)
			want := uint32(guestio.Denied)
			if mode == "bandwidth" {
				want = guestio.Failure
			}
			if mode == "canceled" {
				want = guestio.Canceled
			}
			if status != want {
				t.Fatalf("status=%d want=%d", status, want)
			}
			peer.SetReadDeadline(time.Now())
			if n, err := peer.Read(make([]byte, 32)); n != 0 || err == nil {
				t.Fatalf("refused reply sent %d bytes: %v", n, err)
			}
		})
	}
}

func TestUDPReplyRejectsOversizedRawGuestPayload(t *testing.T) {
	env, peer := datagramEnv(t, localSpec())
	mem := newGuestModule(t).Memory()
	address := peer.LocalAddr().String()
	mem.Write(1024, []byte(address))
	mem.Write(2048, bytes.Repeat([]byte("x"), 9000))
	trap := hostTrap(func() {
		HostIOReplyUDP(env)(context.Background(), mem, 1024, uint32(len(address)), 2048, 9000, int64(time.Second))
	})
	if trap == nil {
		t.Fatal("oversized raw datagram was silently shortened")
	}
	peer.SetReadDeadline(time.Now())
	if n, err := peer.Read(make([]byte, 10000)); n != 0 || err == nil {
		t.Fatalf("oversized reply sent %d bytes: %v", n, err)
	}
}

func TestUDPReceiveRechecksRevocationAfterAccounting(t *testing.T) {
	env, peer := datagramEnv(t, localSpec())
	revoked := netpolicy.NewRevocations()
	op, err := netpolicy.Parse(localSpec())
	if err != nil {
		t.Fatal(err)
	}
	env.Net = netpolicy.New(op.WithRevocations(revoked), netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenUDP: true})
	accounting := make(chan struct{})
	resume := make(chan struct{})
	core, _ := observer.New(zapcore.DebugLevel)
	limiter := app.NewLimiter(zap.New(core, zap.Hooks(func(entry zapcore.Entry) error {
		if entry.Message == "Ratelimit debuglet by sleeping" {
			close(accounting)
			<-resume
		}
		return nil
	})))
	limiter.SetExecutorCapacity(bitrate.Gigabit)
	limiter.SetAddrCapacity("127.0.0.1", bitrate.Gigabit)
	if err := limiter.InsertDebuglet(env.DebugletID, 0, bitrate.Gigabit, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	env.Accountant = ratelimit.NewAccountant(limiter, env.DebugletID)
	mem := newGuestModule(t).Memory()
	mem.Write(1024, []byte("untouched"))
	if _, err := peer.Write([]byte("PRIVATE")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan uint64, 1)
	go func() { done <- HostIOReceiveUDP(env)(ctx, mem, 1024, 16, 2048, 128, 4096, int64(time.Second)) }()
	select {
	case <-accounting:
	case <-time.After(time.Second):
		close(resume)
		t.Fatal("receive did not reach accounting")
	}
	revoked.Update([]string{"127.0.0.1"}, false)
	close(resume)
	// Revoked traffic is discarded and receive waits until its ordinary deadline.
	select {
	case result := <-done:
		if uint32(result>>32) != guestio.Timeout {
			t.Fatalf("revoked packet result=%x", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("receive did not finish")
	}
	got, _ := mem.Read(1024, 9)
	if string(got) != "untouched" || env.udpReplyPeer.IsValid() {
		t.Fatalf("revoked payload escaped: %q peer=%s", got, env.udpReplyPeer)
	}
}
