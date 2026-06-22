package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

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

	mu sync.Mutex
}

func NewUsageTracker() *UsageTracker {
	return &UsageTracker{
		usageIn:  make(map[string]*rate.Limiter),
		usageOut: make(map[string]*rate.Limiter),
		capacity: make(map[string]Bitrate),
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
	reserveDestination, reserveExecutor, err := func() (*rate.Reservation, *rate.Reservation, error) {
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
			return nil, nil, errors.New("cannot track destination usage, unregistered destination")
		}
		limiterExecutor, exists := usage[""]
		if !exists {
			return nil, nil, errors.New("cannot track executor usage, not registered")
		}

		reserveDestination := limiterDestination.ReserveN(time.Now(), int(size))
		if !reserveDestination.OK() {
			return nil, nil, fmt.Errorf("cannot reserve destination, size is greater than burst (Got %d, Want %d)", int(size), limiterDestination.Burst())
		}

		reserveExecutor := limiterExecutor.ReserveN(time.Now(), int(size))
		if !reserveExecutor.OK() {
			reserveDestination.Cancel()
			return nil, nil, fmt.Errorf("cannot reserve executor, size is greater than burst (Got %d, Want %d)", int(size), limiterExecutor.Burst())
		}

		return reserveDestination, reserveExecutor, nil
	}()

	if err != nil {
		return err
	}

	waitFor := max(reserveDestination.Delay(), reserveExecutor.Delay())

	select {
	case <-time.After(waitFor):
	case <-ctx.Done():
		reserveDestination.Cancel()
		reserveExecutor.Cancel()
		return errors.New("context closed")
	}

	return nil
}
