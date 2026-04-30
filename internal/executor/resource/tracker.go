package resource

import (
	"context"
	"errors"
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
	// ID: { destination: rateLimit }
	usageIn map[string]map[string]*rate.Limiter
	// ID: { destination: rateLimit }
	usageOut map[string]map[string]*rate.Limiter
	capacity map[string]map[string]int64

	mu sync.Mutex
}

func NewUsageTracker() *UsageTracker {
	return &UsageTracker{
		usageIn:  make(map[string]map[string]*rate.Limiter),
		usageOut: make(map[string]map[string]*rate.Limiter),
		capacity: make(map[string]map[string]int64),
	}
}

type UsageLimits struct {
	ExecutorRatelimit    int64
	ExecutorBurst        int64
	DestinationRatelimit int64
	DestinationBurst     int64
}

func (u *UsageTracker) Register(ID, destination string, limits UsageLimits) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.register(TransferIn, ID, destination, limits)
	u.register(TransferOut, ID, destination, limits)
}

func (u *UsageTracker) register(dir TransferDirection, ID, destination string, limits UsageLimits) {
	var usage map[string]map[string]*rate.Limiter
	if dir == TransferIn {
		usage = u.usageIn
	} else {
		usage = u.usageOut
	}

	_, exists := usage[ID]
	if !exists {
		usage[ID] = map[string]*rate.Limiter{
			destination: rate.NewLimiter(
				rate.Limit(limits.DestinationRatelimit), int(limits.DestinationBurst),
			),
			ExecutorUsageKey: rate.NewLimiter(
				rate.Limit(limits.ExecutorRatelimit), int(limits.ExecutorBurst),
			),
		}
	}
}

func (u *UsageTracker) Unregister(ID, destination string) {
	// TODO
}

// Wait uses a token bucket to sleep until either the context finishes or a packet of a given size has enough space
func (u *UsageTracker) Wait(ctx context.Context, dir TransferDirection, ID, destination string, size int64) error {
	reserveDestination, reserveExecutor, err := func() (*rate.Reservation, *rate.Reservation, error) {
		u.mu.Lock()
		defer u.mu.Unlock()

		var usage map[string]map[string]*rate.Limiter
		if dir == TransferIn {
			usage = u.usageIn
		} else {
			usage = u.usageOut
		}

		dests, exists := usage[ID]
		if !exists {
			return nil, nil, errors.New("cannot track usage, unknown ID")
		}
		limiterDestination, exists := dests[destination]
		if !exists {
			return nil, nil, errors.New("cannot track destination usage, unregistered destination")
		}
		limiterExecutor, exists := dests[destination]
		if !exists {
			return nil, nil, errors.New("cannot track executor usage, not registered")
		}

		reserveDestination := limiterDestination.ReserveN(time.Now(), int(size))
		if !reserveDestination.OK() {
			return nil, nil, errors.New("cannot reserve destination, size is greater than burst")
		}

		reserveExecutor := limiterExecutor.ReserveN(time.Now(), int(size))
		if !reserveExecutor.OK() {
			reserveDestination.Cancel()
			return nil, nil, errors.New("cannot reserve executor, size is greater than burst")
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
