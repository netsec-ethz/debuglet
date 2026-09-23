package controlsession

import (
	"errors"
	"math"
	"testing"
	"time"
)

func TestLeaseTimingBoundaries(t *testing.T) {
	for _, duration := range []time.Duration{time.Second, 1001 * time.Millisecond, 2 * time.Second, time.Minute, 5 * time.Minute} {
		value, err := NewLeaseTiming(duration)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := LeaseTimingFromMillis(duration.Milliseconds())
		if err != nil || wire != value {
			t.Fatalf("wire timing differs for %v", duration)
		}
		if value.Duration != duration || value.RenewInterval != duration/5 || value.RequestTimeout != min(2*time.Second, duration/5) || value.WatchdogInterval != min(250*time.Millisecond, duration/20) {
			t.Fatalf("incorrect timing for %v", duration)
		}
		if value.RenewInterval+value.RequestTimeout+value.WatchdogInterval >= value.Duration {
			t.Fatalf("no lease safety margin for %v", duration)
		}
	}
	for _, duration := range []time.Duration{0, -1, time.Second - time.Nanosecond, time.Second + time.Nanosecond, 5*time.Minute + time.Millisecond, time.Duration(math.MaxInt64)} {
		if got, err := NewLeaseTiming(duration); err == nil || got != (LeaseTiming{}) {
			t.Fatalf("invalid duration accepted: %v", duration)
		}
	}
	for _, ms := range []int64{math.MinInt64, -1, 0, 999, 300001, math.MaxInt64} {
		if got, err := LeaseTimingFromMillis(ms); err == nil || got != (LeaseTiming{}) {
			t.Fatalf("invalid/overflowing wire duration accepted: %d", ms)
		}
	}
}

func TestSessionEndCauseIdentity(t *testing.T) {
	cause := errors.New("owned operation failure")
	for _, kind := range []EndKind{TransportUnavailable, LeaseExpired, ParentStopped, IncompatibleProfile, LocalFailure} {
		original := &EndError{Kind: kind, Err: cause}
		wrapped := errors.Join(errors.New("joining attempt"), original)
		var got *EndError
		if !errors.As(wrapped, &got) || got != original || got.Kind != kind || !errors.Is(wrapped, cause) {
			t.Fatalf("lost typed cause for %v", kind)
		}
	}
	var empty *EndError
	if empty.Unwrap() != nil || empty.Error() != "<nil>" {
		t.Fatal("nil end error is unsafe")
	}
}
