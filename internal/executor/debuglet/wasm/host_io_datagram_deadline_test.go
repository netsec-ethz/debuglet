// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"net/netip"
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

type deadlineResolver struct{}

func (deadlineResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestUDPReceiveDoesNotChargeAgainAfterAdmissionTimeout(t *testing.T) {
	env, peer := datagramEnv(t, localSpec())
	revoked := netpolicy.NewRevocations()
	op, err := netpolicy.Parse(localSpec())
	if err != nil {
		t.Fatal(err)
	}
	env.Net = netpolicy.New(op.WithRevocations(revoked), netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenUDP: true}, netpolicy.WithResolver(deadlineResolver{}))
	// Accounting succeeds, then its policy recheck must resolve a newly
	// revoked hostname. That lookup expires without exposing the packet.
	core, _ := observer.New(zapcore.DebugLevel)
	charges := 0
	limiter := app.NewLimiter(zap.New(core, zap.Hooks(func(entry zapcore.Entry) error {
		if entry.Message == "Ratelimit debuglet by sleeping" {
			charges++
			revoked.Update([]string{"unrelated.invalid"}, false)
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
	if _, err := peer.Write([]byte("paid")); err != nil {
		t.Fatal(err)
	}
	receive := HostIOReceiveUDP(env)
	if result := receive(context.Background(), mem, 1024, 16, 2048, 128, 4096, int64(200*time.Millisecond)); uint32(result>>32) != guestio.Timeout {
		t.Fatalf("policy lookup did not time out: %x", result)
	}
	if got, _ := mem.Read(1024, 9); string(got) != "untouched" || charges != 1 {
		t.Fatalf("payload=%q charges=%d", got, charges)
	}
	revoked.Update(nil, false)
	// No new packet may be charged, but this packet was already paid for.
	limiter.SetAddrCapacity("127.0.0.1", 0)
	result := receive(context.Background(), mem, 1024, 16, 2048, 128, 4096, int64(time.Second))
	if got, _ := mem.Read(1024, 4); result != 4 || string(got) != "paid" || charges != 1 {
		t.Fatalf("already-accounted packet result=%x payload=%q charges=%d", result, got, charges)
	}
}

func TestUDPReceiveRetainsPacketAcrossAccountingTimeout(t *testing.T) {
	for _, mode := range []string{"retry", "revoked", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			env, peer := datagramEnv(t, localSpec())
			revoked := netpolicy.NewRevocations()
			op, err := netpolicy.Parse(localSpec())
			if err != nil {
				t.Fatal(err)
			}
			env.Net = netpolicy.New(op.WithRevocations(revoked), netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenUDP: true})
			// A received packet cannot fit into this one-bit-per-second budget
			// before the polling deadline. Accounting must refund that attempt.
			env.Limiter.SetAddrCapacity("127.0.0.1", 1)
			mem := newGuestModule(t).Memory()
			mem.Write(1024, []byte("untouched"))
			if _, err := peer.Write([]byte("preserved")); err != nil {
				t.Fatal(err)
			}
			receive := HostIOReceiveUDP(env)
			if result := receive(context.Background(), mem, 1024, 16, 2048, 128, 4096, int64(20*time.Millisecond)); uint32(result>>32) != guestio.Timeout {
				t.Fatalf("accounting did not time out: %x", result)
			}
			if got, _ := mem.Read(1024, 9); string(got) != "untouched" || env.udpReplyPeer.IsValid() {
				t.Fatalf("unaccounted packet escaped: %q", got)
			}
			env.Limiter.SetAddrCapacity("127.0.0.1", bitrate.Gigabit)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "revoked" {
				revoked.Update([]string{"127.0.0.1"}, false)
			}
			if mode == "canceled" {
				cancel()
			}
			result := receive(ctx, mem, 1024, 16, 2048, 128, 4096, int64(100*time.Millisecond))
			if mode == "retry" {
				if got, _ := mem.Read(1024, 9); result != 9 || string(got) != "preserved" {
					t.Fatalf("packet consumed before timeout was lost: result=%x payload=%q", result, got)
				}
			} else {
				want := uint32(guestio.Timeout)
				if mode == "canceled" {
					want = guestio.Canceled
				}
				if got, _ := mem.Read(1024, 9); uint32(result>>32) != want || string(got) != "untouched" || env.udpReplyPeer.IsValid() {
					t.Fatalf("refused pending packet escaped: result=%x payload=%q", result, got)
				}
			}
			// Cancellation discards the pending packet; successful delivery
			// consumes it once. Neither can replay it in a later call.
			if mode != "revoked" {
				if result := receive(context.Background(), mem, 1024, 16, 2048, 128, 4096, int64(time.Millisecond)); uint32(result>>32) != guestio.Timeout {
					t.Fatalf("packet replayed: %x", result)
				}
			}
		})
	}
}
