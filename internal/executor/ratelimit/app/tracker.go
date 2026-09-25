// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

type TransferDirection = int

const (
	TransferIn TransferDirection = iota
	TransferOut
)

// UsageTracker tracks the amount of bandwidth that is being used
// by an individual debuglet. The idea is to set the executor and destination
// specific limit that is allowed by the debuglet and then [UsageTracker.Wait]
// will block the caller for the amount of time to ratelimit the bandwidth usage.
type UsageTracker struct {
	// { destination: rateLimit }
	usageIn map[string]*rate.Limiter
	// { destination: rateLimit }
	usageOut map[string]*rate.Limiter
	capacity map[string]Bitrate
	logger   *zap.Logger

	mu sync.Mutex
}

func NewUsageTracker(l *zap.Logger) *UsageTracker {
	return &UsageTracker{
		usageIn:  make(map[string]*rate.Limiter),
		usageOut: make(map[string]*rate.Limiter),
		capacity: make(map[string]Bitrate),
		logger:   l,
	}
}

type UsageLimits struct {
	ExecutorRatelimit    Bitrate
	ExecutorBurst        Bitrate
	DestinationRatelimit Bitrate
	DestinationBurst     Bitrate
}

func (u *UsageTracker) Upsert(destination string, limits UsageLimits) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.upsert(TransferIn, destination, limits)
	u.upsert(TransferOut, destination, limits)
}

func (u *UsageTracker) upsert(dir TransferDirection, destination string, limits UsageLimits) {
	var usage map[string]*rate.Limiter
	if dir == TransferIn {
		usage = u.usageIn
	} else {
		usage = u.usageOut
	}

	destinationUsage, dExists := usage[destination]
	executorUsage, eExists := usage[""]

	if !dExists {
		usage[destination] = rate.NewLimiter(
			rate.Limit(limits.DestinationRatelimit), int(limits.DestinationBurst),
		)
	} else {
		if destinationUsage.Limit() != rate.Limit(limits.DestinationRatelimit) {
			destinationUsage.SetLimit(rate.Limit(limits.DestinationRatelimit))
		}
		if destinationUsage.Burst() != int(limits.DestinationBurst) {
			destinationUsage.SetBurst(int(limits.DestinationBurst))
		}
	}

	if !eExists {
		usage[""] = rate.NewLimiter(
			rate.Limit(limits.ExecutorRatelimit), int(limits.ExecutorBurst),
		)
	} else {
		if executorUsage.Limit() != rate.Limit(limits.ExecutorRatelimit) {
			executorUsage.SetLimit(rate.Limit(limits.ExecutorRatelimit))
		}
		if executorUsage.Burst() != int(limits.ExecutorBurst) {
			executorUsage.SetBurst(int(limits.ExecutorBurst))
		}
	}
}

// Wait uses a token bucket to sleep until either the context finishes or a packet of a given size has enough space
func (u *UsageTracker) Wait(ctx context.Context, dir TransferDirection, destination string, size Bitrate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	waitFor, reservations, err := func() (time.Duration, []*rate.Reservation, error) {
		u.mu.Lock()
		defer u.mu.Unlock()

		var usage map[string]*rate.Limiter
		if dir == TransferIn {
			usage = u.usageIn
		} else {
			usage = u.usageOut
		}

		limiterDestination, exists := usage[destination]
		if !exists {
			return 0, nil, errors.New("cannot track destination usage, unregistered destination")
		}
		limiterExecutor, exists := usage[""]
		if !exists {
			return 0, nil, errors.New("cannot track executor usage, not registered")
		}

		if size <= 0 {
			return 0, nil, nil
		}
		if limiterDestination.Burst() <= 0 || limiterExecutor.Burst() <= 0 {
			return 0, nil, errors.New("cannot account traffic with zero bandwidth")
		}

		var reservations []*rate.Reservation
		var waitFor time.Duration
		now := time.Now()
		for _, limiter := range []*rate.Limiter{limiterDestination, limiterExecutor} {
			// Reserve the whole packet once. Raising the burst at the same
			// timestamp preserves the balance; restoring it retains the debt.
			burst := limiter.Burst()
			limiter.SetBurstAt(now, max(burst, int(size)))
			reservation := limiter.ReserveN(now, int(size))
			limiter.SetBurstAt(now, burst)
			if !reservation.OK() {
				for _, prior := range reservations {
					prior.CancelAt(now)
				}
				return 0, nil, fmt.Errorf("cannot reserve bandwidth for %d bits", size)
			}
			reservations = append(reservations, reservation)
			waitFor = max(waitFor, reservation.DelayFrom(now))
		}
		return waitFor, reservations, nil
	}()

	if err != nil {
		return err
	}

	u.logger.Debug("Ratelimit debuglet by sleeping", zap.String("destination", destination), zap.Duration("duration", waitFor), zap.Int64("size", int64(size)))

	select {
	case <-time.After(waitFor):
	case <-ctx.Done():
		u.mu.Lock()
		for _, reservation := range reservations {
			reservation.Cancel()
		}
		u.mu.Unlock()
		return ctx.Err()
	}

	return nil
}
