// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// CaptureClockTrust is a receiver's independently obtained clock observation.
// It binds the normalized packet bytes AND capture timestamps, not just a time
// window. Source identifies the reference and observation record. MaxErrorNS
// bounds receiver time relative to every listed TESLA schedule authority. It
// includes both hosts' reference error, timestamping error and drift throughout
// the covered interval; a synchronization flag or kernel estimate is not a bound.
// Supply this record separately from the evidence, through a trusted channel.
type CaptureClockTrust struct {
	PacketsDigest string                 `json:"packets_digest"`
	Source        string                 `json:"source"`
	ObservedAt    time.Time              `json:"observed_at"`
	ValidUntil    time.Time              `json:"valid_until"`
	Schedules     []CaptureClockSchedule `json:"schedules"`
	MaxErrorNS    int64                  `json:"max_error_ns"`
}

// CaptureClockSchedule identifies a signed schedule origin covered by the
// relative-clock observation. Other origins require their own observation.
type CaptureClockSchedule struct {
	ExecutorID   string `json:"executor_id"`
	ChainID      string `json:"chain_id"`
	OriginUnixNS int64  `json:"origin_unix_ns"`
}

// ReadCaptureClockTrust reads a record supplied independently by the receiver.
// Parsing validates its shape; it cannot establish the observer's honesty.
func ReadCaptureClockTrust(data []byte) (CaptureClockTrust, error) {
	var clock CaptureClockTrust
	if len(data) > 128<<10 {
		return clock, errors.New("client: capture clock record exceeds 128 KiB")
	}
	if err := json.Unmarshal(data, &clock); err != nil {
		return clock, err
	}
	_, err := clock.tolerance()
	return clock, err
}

func (clock CaptureClockTrust) tolerance() (time.Duration, error) {
	if clock.Source == "" || len(clock.Source) > 1024 || clock.ObservedAt.IsZero() || !clock.ValidUntil.After(clock.ObservedAt) || clock.MaxErrorNS <= 0 || clock.MaxErrorNS > int64(24*time.Hour) || len(clock.Schedules) == 0 || len(clock.Schedules) > 128 {
		return 0, errors.New("client: capture clock needs a reference, observation interval and positive error bound of at most 24 hours")
	}
	// Evidence records milliseconds; rounding upward preserves the applied
	// conservative bound when the bundle is read back later.
	return time.Duration((clock.MaxErrorNS+int64(time.Millisecond)-1)/int64(time.Millisecond)) * time.Millisecond, nil
}

func (clock CaptureClockTrust) check(ev Evidence) error {
	bound, err := clock.tolerance()
	if err != nil {
		return err
	}
	if ev.At != nil {
		return errors.New("client: overridden capture timestamps cannot carry receiver clock trust")
	}
	if clock.PacketsDigest != ev.Packets.Digest || clock.PacketsDigest == "" {
		return errors.New("client: receiver clock record does not bind these packets and timestamps")
	}
	if ev.ClockToleranceMS < int64(bound/time.Millisecond) {
		return errors.New("client: capture tolerance is smaller than the measured receiver clock bound")
	}
	for _, lookup := range ev.Lookups {
		for _, candidate := range lookup.Candidates {
			want := CaptureClockSchedule{ExecutorID: candidate.ExecutorID, ChainID: candidate.Schedule.ChainID, OriginUnixNS: candidate.Schedule.T0UnixNs}
			if !slices.Contains(clock.Schedules, want) {
				return errors.New("client: receiver clock observation does not cover this schedule authority")
			}
		}
	}
	for i, packet := range ev.Packets.Items {
		// Bounds include uncertainty on both sides of the timestamp. A delayed
		// verification may run later; freshness matters when the packet arrived.
		if packet.CapturedAt.Add(-bound).Before(clock.ObservedAt) || !packet.CapturedAt.Add(bound).Before(clock.ValidUntil) {
			return fmt.Errorf("client: packet %d is outside the receiver clock observation interval", i)
		}
	}
	return nil
}
