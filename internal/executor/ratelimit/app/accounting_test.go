package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/time/rate"
)

func TestLimiterAccountingAfterPublication(t *testing.T) {
	l := NewLimiter(zap.NewNop())
	l.SetExecutorCapacity(800)
	l.SetAddrCapacity(limiterAddrA, 800)
	id := insertLimiterRun(t, l, limiterAddrA)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	for _, capacity := range []Bitrate{800, 400, 600} {
		l.SetExecutorCapacity(capacity)
		l.SetAddrCapacity(limiterAddrA, capacity/2)
		// Registration and packet-counter publication read both dimensions
		// before listener traffic reaches its accountant.
		if _, _, err := l.GetExecLimit(id); err != nil {
			t.Fatal(err)
		}
		if _, _, err := l.GetAddrLimit(id, limiterAddrA); err != nil {
			t.Fatal(err)
		}
		if limit, err := l.GetLimit(id, limiterAddrA); err != nil || limit.Updated {
			t.Fatalf("publication did not cache limits: %+v, %v", limit, err)
		}
		for _, direction := range []TransferDirection{TransferIn, TransferOut} {
			if err := l.Wait(ctx, direction, id, limiterAddrA, 8); err != nil {
				t.Fatalf("accounting after publication: %v", err)
			}
		}
		tracker := l.stores[id].tracker
		for _, usage := range []map[string]*rate.Limiter{tracker.usageIn, tracker.usageOut} {
			if got := usage[""].Limit(); got != rate.Limit(capacity) {
				t.Fatalf("executor accounting rate = %v, want %v", got, capacity)
			}
			if got := usage[limiterAddrA].Limit(); got != rate.Limit(capacity/2) {
				t.Fatalf("destination accounting rate = %v, want %v", got, capacity/2)
			}
		}
	}
}

func TestUsageTrackerUpsertPreservesBalances(t *testing.T) {
	u := NewUsageTracker(zap.NewNop())
	// With no replenishment, balances can be checked without clock timing.
	limits := UsageLimits{ExecutorBurst: 100, DestinationBurst: 100}
	u.Upsert(limiterAddrA, limits)
	for _, direction := range []TransferDirection{TransferIn, TransferOut} {
		for _, size := range []Bitrate{90, 0, -8} {
			if err := u.Wait(context.Background(), direction, limiterAddrA, size); err != nil {
				t.Fatal(err)
			}
		}
	}
	u.Upsert(limiterAddrA, limits)
	limits.ExecutorBurst, limits.DestinationBurst = 50, 50
	u.Upsert(limiterAddrA, limits)
	// Another destination shares the same per-direction executor balance.
	u.Upsert(limiterAddrB, limits)
	for _, usage := range []map[string]*rate.Limiter{u.usageIn, u.usageOut} {
		for _, addr := range []string{"", limiterAddrA} {
			if got := usage[addr].Tokens(); got != 10 {
				t.Errorf("balance for %q = %v, want 10", addr, got)
			}
		}
	}
}

func TestLimiterAccountingZeroBudget(t *testing.T) {
	for _, dimension := range []string{"executor", "destination"} {
		t.Run(dimension, func(t *testing.T) {
			l := NewLimiter(zap.NewNop())
			l.SetExecutorCapacity(800)
			l.SetAddrCapacity(limiterAddrA, 800)
			id := insertLimiterRun(t, l, limiterAddrA)
			if dimension == "executor" {
				l.SetExecutorCapacity(0)
			} else {
				l.SetAddrCapacity(limiterAddrA, 0)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := l.Wait(ctx, TransferIn, id, limiterAddrA, 8); err == nil {
				t.Fatal("nonempty traffic passed a zero budget")
			}
			if ctx.Err() != nil {
				t.Fatal("zero budget did not return before the context expired")
			}
			if err := l.Wait(ctx, TransferIn, id, limiterAddrA, 0); err != nil {
				t.Fatalf("empty traffic consumed bandwidth: %v", err)
			}
			cancel()
			if err := l.Wait(ctx, TransferIn, id, limiterAddrA, 8); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled accounting returned %v", err)
			}
			l.SetExecutorCapacity(800)
			l.SetAddrCapacity(limiterAddrA, 800)
			if err := l.Wait(context.Background(), TransferIn, id, limiterAddrA, 8); err != nil {
				t.Fatalf("restored budget did not admit traffic: %v", err)
			}
		})
	}
}

func TestUsageTrackerCancellationRefundsPendingReservations(t *testing.T) {
	for _, tc := range []struct {
		name              string
		rate, burst, size Bitrate
		drain             bool
	}{
		{"multiple_chunks", 1, 100, 201, true},
		{"fractional_duration", 3, 3, 7, true},
		{"initial_burst", 3, 3, 7, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			core, logs := observer.New(zap.DebugLevel)
			logger := zap.New(core, zap.Hooks(func(zapcore.Entry) error {
				// Wait logs after reserving both dimensions and before sleeping.
				cancel()
				return nil
			}))
			u := NewUsageTracker(logger)
			u.Upsert(limiterAddrA, UsageLimits{
				ExecutorRatelimit: tc.rate, ExecutorBurst: tc.burst,
				DestinationRatelimit: tc.rate, DestinationBurst: tc.burst,
			})
			started := time.Now()
			initialBalance := float64(tc.burst)
			if tc.drain {
				initialBalance = 0
				for _, addr := range []string{"", limiterAddrA} {
					if !u.usageIn[addr].AllowN(time.Now(), int(tc.burst)) {
						t.Fatal("could not consume the initial burst")
					}
				}
			}
			// Oversized packets must reserve their full demand and refund it on cancellation.
			if err := u.Wait(ctx, TransferIn, limiterAddrA, tc.size); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled accounting returned %v", err)
			}
			entries := logs.All()
			if len(entries) != 1 {
				t.Fatalf("got %d reservation logs, want 1", len(entries))
			}
			wait := entries[0].ContextMap()["duration"].(time.Duration)
			want := time.Duration((float64(tc.size) - initialBalance) / float64(tc.rate) * float64(time.Second))
			if wait > want+time.Nanosecond || wait < want-time.Since(started)-time.Nanosecond {
				t.Errorf("packet delay %v differs from demand delay %v beyond elapsed time", wait, want)
			}
			for _, addr := range []string{"", limiterAddrA} {
				limiter := u.usageIn[addr]
				if got := limiter.Burst(); got != int(tc.burst) {
					t.Errorf("configured burst changed to %d for %q", got, addr)
				}
				got := limiter.Tokens()
				// Replenishment can add only the elapsed-time credit.
				// Allow rounding at the nanosecond boundaries used by rate.Limiter.
				maximum := min(float64(tc.burst), initialBalance+time.Since(started).Seconds()*float64(tc.rate))
				if got < initialBalance-1e-6 || got > maximum+1e-6 {
					t.Errorf("canceled reservation left unexpected balance %v for %q", got, addr)
				}
			}
		})
	}
}
