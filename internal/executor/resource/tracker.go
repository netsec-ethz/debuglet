package resource

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
	ExecutorUsageKey string = ""
)

type UsageTracker struct {
	// { destination: rateLimit }
	usageIn map[string]*rate.Limiter
	// { destination: rateLimit }
	usageOut map[string]*rate.Limiter
	capacity map[string]int64

	mu sync.Mutex
}

func NewUsageTracker() *UsageTracker {
	return &UsageTracker{
		usageIn:  make(map[string]*rate.Limiter),
		usageOut: make(map[string]*rate.Limiter),
		capacity: make(map[string]int64),
	}
}

type UsageLimits struct {
	ExecutorRatelimit    int64
	ExecutorBurst        int64
	DestinationRatelimit int64
	DestinationBurst     int64
}

func (u *UsageTracker) Register(destination string, limits UsageLimits) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.register(TransferIn, destination, limits)
	u.register(TransferOut, destination, limits)
}

func (u *UsageTracker) register(dir TransferDirection, destination string, limits UsageLimits) {
	var usage map[string]*rate.Limiter
	if dir == TransferIn {
		usage = u.usageIn
	} else {
		usage = u.usageOut
	}

	destinationUsage, dExists := usage[destination]
	executorUsage, eExists := usage[destination]
	if !dExists || !eExists {
		usage[destination] = rate.NewLimiter(
			rate.Limit(limits.DestinationRatelimit), int(limits.DestinationBurst),
		)
		usage[ExecutorUsageKey] = rate.NewLimiter(
			rate.Limit(limits.ExecutorRatelimit), int(limits.ExecutorBurst),
		)
	} else {
		destinationUsage.SetLimit(rate.Limit(limits.DestinationRatelimit))
		destinationUsage.SetBurst(int(limits.DestinationBurst))
		executorUsage.SetLimit(rate.Limit(limits.ExecutorRatelimit))
		executorUsage.SetBurst(int(limits.ExecutorBurst))
	}
}

func (u *UsageTracker) Unregister(ID, destination string) {
	// TODO
}

// Wait uses a token bucket to sleep until either the context finishes or a packet of a given size has enough space
func (u *UsageTracker) Wait(ctx context.Context, dir TransferDirection, destination string, size int64) error {
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
		limiterExecutor, exists := usage[ExecutorUsageKey]
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
	if waitFor > 0 {
		select {
		case <-time.After(waitFor):
		case <-ctx.Done():
			reserveDestination.Cancel()
			reserveExecutor.Cancel()
			return errors.New("context closed")
		}
	}

	return nil
}
