// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tesla

import (
	"bytes"
	"testing"
	"time"
)

// steppedClock treats an instant as its monotonic reading. From the instant at
// on, the wall clock reads offset more than the monotonic clock: a forward
// step, or the time of a suspend the monotonic clock did not count, or with a
// negative offset a backward step.
type steppedClock struct {
	at     time.Time
	offset time.Duration
}

func (c steppedClock) Elapsed(origin, t time.Time) (time.Duration, time.Duration) {
	monotonic := t.Sub(origin)
	if t.Before(c.at) {
		return monotonic, monotonic
	}
	return monotonic, monotonic + c.offset
}

// sequenceClock returns its monotonic readings in order, whatever the instant,
// with the wall clock agreeing, so only the epoch it maps to moves.
type sequenceClock struct{ readings []time.Duration }

func (c *sequenceClock) Elapsed(time.Time, time.Time) (time.Duration, time.Duration) {
	r := c.readings[0]
	c.readings = c.readings[1:]
	return r, r
}

const clockEpoch = 10 * time.Second

var clockStart = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func clockSchedule(t *testing.T, unready bool, clock Clock) (*KeySchedule, func(epoch int64) time.Time) {
	t.Helper()
	ks, err := NewKeySchedule(Config{Seed: bytes.Repeat([]byte{0x6B}, 32), ChainLength: 1 << 10, EpochLength: clockEpoch,
		DisclosureDelay: MinDisclosureDelay, Epoch: clockStart, ClockUnready: unready, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return ks, func(epoch int64) time.Time { return clockStart.Add(time.Duration(epoch) * clockEpoch) }
}

func wantKey(t *testing.T, ks *KeySchedule, at time.Time, epoch int64) {
	t.Helper()
	want, _ := ks.KeyAtEpoch(epoch)
	if got := ks.CurrentKey(at); !bytes.Equal(got, want) {
		t.Fatalf("CurrentKey(%v) = %x, want k_%d", at.Sub(clockStart), got, epoch)
	}
}

func wantNoKey(t *testing.T, ks *KeySchedule, at time.Time) {
	t.Helper()
	if got := ks.CurrentKey(at); got != nil {
		t.Fatalf("CurrentKey(%v) = %x, want none", at.Sub(clockStart), got)
	}
	if _, err := ks.ComputeTagForPacket(at, []byte("clock-measurement"), make([]byte, 28)); err == nil {
		t.Fatalf("ComputeTagForPacket(%v) tagged without a usable key", at.Sub(clockStart))
	}
}

func wantAttribution(t *testing.T, ks *KeySchedule, at time.Time, epoch int64, reason string) {
	t.Helper()
	if a := ks.Attribution(at); a.Epoch != epoch || a.Reason != reason {
		t.Fatalf("Attribution(%v) = epoch %d reason %q, want epoch %d reason %q", at.Sub(clockStart), a.Epoch, a.Reason, epoch, reason)
	}
}

// The bound is half an epoch and at most the verifier's 1 s tolerance.
func TestMaxDriftBound(t *testing.T) {
	for _, tc := range []struct{ epoch, want time.Duration }{
		{10 * time.Second, time.Second},
		{2 * time.Second, time.Second},
		{time.Second, 500 * time.Millisecond},
	} {
		ks, err := NewKeySchedule(Config{Seed: fixedSeed, ChainLength: 8, EpochLength: tc.epoch})
		if err != nil {
			t.Fatal(err)
		}
		if got := ks.MaxDrift(); got != tc.want {
			t.Errorf("epoch %v: MaxDrift %v, want %v", tc.epoch, got, tc.want)
		}
	}
}

// Wall and monotonic clocks advancing together, or apart by no more than the
// bound, leave attribution and the key as they are.
func TestClockWithinBoundSigns(t *testing.T) {
	ks, at := clockSchedule(t, false, nil)
	if d := ks.Drift(at(3)); d != 0 {
		t.Fatalf("Drift with the instants' own readings = %v", d)
	}
	wantAttribution(t, ks, at(3), 3, "")
	wantKey(t, ks, at(3), 3)

	for _, offset := range []time.Duration{time.Second, -time.Second} {
		ks, at := clockSchedule(t, false, steppedClock{at: clockStart.Add(4 * clockEpoch), offset: offset})
		if d := ks.Drift(at(4)); d != offset {
			t.Fatalf("Drift = %v, want %v", d, offset)
		}
		wantAttribution(t, ks, at(4), 4, "")
		wantKey(t, ks, at(4), 4)
		wantKey(t, ks, at(5), 5)
	}
}

// A backward wall step beyond the bound leaves the local epoch where the
// monotonic clock has it, so no earlier key comes back, but a verifier would
// map capture times an hour too early: attribution is unavailable and no key
// signs, for as long as the step stands.
func TestBackwardWallStepStopsSigning(t *testing.T) {
	step := clockStart.Add(5*clockEpoch + time.Second)
	ks, at := clockSchedule(t, false, steppedClock{at: step, offset: -time.Hour})
	wantKey(t, ks, at(4), 4)
	wantAttribution(t, ks, at(5), 5, "")

	if d := ks.Drift(step); d != -time.Hour {
		t.Fatalf("Drift after the step = %v", d)
	}
	for _, later := range []time.Time{step, at(6), at(40)} {
		wantAttribution(t, ks, later, ks.EpochOf(later), UnattributableClockDrift)
		wantNoKey(t, ks, later)
	}
	if e := ks.EpochOf(step); e != 5 {
		t.Fatalf("local epoch after the step = %d, want 5", e)
	}
	// Disclosure keeps following the monotonic clock.
	if idx, _, _ := ks.DisclosedKey(at(6)); idx != 6-MinDisclosureDelay {
		t.Fatalf("disclosed %d after the step, want %d", idx, 6-MinDisclosureDelay)
	}
}

// A suspend the monotonic clock did not count puts the wall clock 30 s ahead
// on resume: attribution is unavailable and no key signs from then on, since
// nothing brings the clocks back together short of a new chain.
func TestSuspendStopsSigningUntilRestart(t *testing.T) {
	resume := clockStart.Add(5 * clockEpoch)
	ks, at := clockSchedule(t, false, steppedClock{at: resume, offset: 30 * time.Second})
	wantKey(t, ks, at(4), 4)
	for _, later := range []time.Time{resume, at(6), at(100)} {
		wantAttribution(t, ks, later, ks.EpochOf(later), UnattributableClockDrift)
		wantNoKey(t, ks, later)
	}
}

// A chain whose clock was not ready at its start is unattributable from its
// first instant, before epoch_zero would apply, and never signs.
func TestUnreadyOriginNeverSigns(t *testing.T) {
	ks, at := clockSchedule(t, true, nil)
	for _, e := range []int64{0, 1, 500} {
		wantAttribution(t, ks, at(e), e, UnattributableClockUnready)
		wantNoKey(t, ks, at(e))
	}
	wantAttribution(t, ks, at(1<<10), 1<<10, UnattributableChainExhausted)
}

// Whatever the clock maps a later call to, CurrentKey never returns the key
// of an epoch below one it has already returned.
func TestCurrentKeyNeverGoesBack(t *testing.T) {
	readings := []time.Duration{5, 3, 5, 6, 5, 1}
	clock := &sequenceClock{}
	for _, r := range readings {
		clock.readings = append(clock.readings, time.Duration(r)*clockEpoch+time.Second)
	}
	ks, _ := clockSchedule(t, false, clock)
	k5, _ := ks.KeyAtEpoch(5)
	k6, _ := ks.KeyAtEpoch(6)
	for i, want := range [][]byte{k5, nil, k5, k6, nil, nil} {
		if got := ks.CurrentKey(clockStart); !bytes.Equal(got, want) {
			t.Fatalf("call %d (epoch %d): CurrentKey = %x, want %x", i, readings[i], got, want)
		}
	}
}
