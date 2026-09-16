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
		destinationUsage.SetLimit(rate.Limit(limits.DestinationRatelimit))
		destinationUsage.SetBurst(int(limits.DestinationBurst))
	}

	if !eExists {
		usage[""] = rate.NewLimiter(
			rate.Limit(limits.ExecutorRatelimit), int(limits.ExecutorBurst),
		)
	} else {
		executorUsage.SetLimit(rate.Limit(limits.ExecutorRatelimit))
		executorUsage.SetBurst(int(limits.ExecutorBurst))
	}
}

// Wait uses a token bucket to sleep until either the context finishes or a packet of a given size has enough space
func (u *UsageTracker) Wait(ctx context.Context, dir TransferDirection, destination string, size Bitrate) error {
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

		var revs []*rate.Reservation

		// NOTE: [rate.Limiter] only permits a max reservation of the burst size. To support ratelimiting greater
		// sizes multiple reservations are added if required.
		failedToReserve := false
		var totalDestDelay time.Duration
		remDestSize := int(size)
		for remDestSize > 0 {
			resFor := min(remDestSize, limiterDestination.Burst())
			res := limiterDestination.ReserveN(time.Now(), resFor)
			if !res.OK() {
				failedToReserve = true
				return 0, nil, fmt.Errorf("cannot reserve destination, size is greater than burst (Got %d, Want %d)", int(size), limiterDestination.Burst())
			}
			revs = append(revs, res)
			totalDestDelay += res.Delay()
			remDestSize -= resFor
			defer func() {
				if failedToReserve {
					res.Cancel()
				}
			}()
		}

		var totalExecDelay time.Duration
		remExecSize := int(size)
		for remExecSize > 0 {
			resFor := min(remExecSize, limiterExecutor.Burst())
			res := limiterExecutor.ReserveN(time.Now(), resFor)
			if !res.OK() {
				failedToReserve = true
				return 0, nil, fmt.Errorf("cannot reserve executor, size is greater than burst (Got %d, Want %d)", int(size), limiterExecutor.Burst())
			}
			revs = append(revs, res)
			totalExecDelay += res.Delay()
			remExecSize -= resFor
			defer func() {
				if failedToReserve {
					res.Cancel()
				}
			}()
		}

		return max(totalDestDelay, totalExecDelay), revs, nil
	}()

	if err != nil {
		return err
	}

	u.logger.Debug("Ratelimit debuglet by sleeping", zap.String("destination", destination), zap.Duration("duration", waitFor), zap.Int64("size", int64(size)))

	select {
	case <-time.After(waitFor):
	case <-ctx.Done():
		for _, r := range reservations {
			r.Cancel()
		}
		return errors.New("context closed")
	}

	return nil
}
