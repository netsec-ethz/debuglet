package controlsession

import (
	"errors"
	"time"
)

// ProtocolVersion requires both channel binding and control lease enforcement.
// It is independent of the guest WASI ABI and the public HTTP API version.
const ProtocolVersion uint32 = 3

const (
	MinLeaseDuration = time.Second
	MaxLeaseDuration = 5 * time.Minute
)

// LeaseTiming is a validated value copied into one control session. These
// durations bound local admission and stop signals, not remote quiescence.
type LeaseTiming struct {
	Duration         time.Duration
	RenewInterval    time.Duration
	RequestTimeout   time.Duration
	WatchdogInterval time.Duration
}

func NewLeaseTiming(duration time.Duration) (LeaseTiming, error) {
	if duration < MinLeaseDuration || duration > MaxLeaseDuration || duration%time.Millisecond != 0 {
		return LeaseTiming{}, errors.New("control lease duration must be whole milliseconds between one second and five minutes")
	}
	return LeaseTiming{
		Duration:         duration,
		RenewInterval:    duration / 5,
		RequestTimeout:   min(2*time.Second, duration/5),
		WatchdogInterval: min(250*time.Millisecond, duration/20),
	}, nil
}

// LeaseTimingFromMillis validates before multiplication, including signed wire
// values which would otherwise overflow time.Duration.
func LeaseTimingFromMillis(milliseconds int64) (LeaseTiming, error) {
	if milliseconds < MinLeaseDuration.Milliseconds() || milliseconds > MaxLeaseDuration.Milliseconds() {
		return LeaseTiming{}, errors.New("control lease duration is outside the supported range")
	}
	return NewLeaseTiming(time.Duration(milliseconds) * time.Millisecond)
}
