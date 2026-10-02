// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"math"
	"time"
)

// ExecutorHealthMetrics aggregates the registry's validated reports. Missing,
// expired or disconnected observations count as unknown, not healthy. Counter
// mode is the executor's selection; it does not prove continuous enforcement.
type ExecutorHealthMetrics struct {
	EBPF, Fallback, EnforcementUnknown int

	AttributionAvailable  int
	EpochZero             int
	ChainExhausted        int
	RefreshFailing        int
	DisclosureHeld        int
	AttributionUnknown    int
	DisclosureHeldSeconds float64

	ClockReady, ClockDegraded, ClockUnknown int
	ClockEstimateUnknown                    int
	ClockEstimatedErrorSeconds              *float64

	ScheduleUnknown, ScheduleExpired int
	ScheduleRemainingSeconds         *float64
}

// observe runs under the registry lock and performs no I/O, probes or key
// verification. The report lifetime is the same one used by executor discovery.
func (m *ExecutorHealthMetrics) observe(e *executorEntry, now time.Time, connected bool) {
	fresh := func(at time.Time) bool {
		return connected && !now.Before(at) && now.Sub(at) < capabilityLifetime
	}
	c := e.Capabilities
	if c == nil || !fresh(e.capabilityObserved) {
		m.EnforcementUnknown++
		m.AttributionUnknown++
	} else {
		switch c.EnforcementMode {
		case "ebpf":
			m.EBPF++
		case "fallback":
			m.Fallback++
		default:
			m.EnforcementUnknown++
		}
		if a := c.Attribution; a == nil {
			m.AttributionUnknown++
		} else {
			switch a.Reason {
			case "":
				m.AttributionAvailable++
			case "epoch_zero":
				m.EpochZero++
			case "chain_exhausted":
				m.ChainExhausted++
			case "refresh_failing":
				m.RefreshFailing++
			case "disclosure_held":
				m.DisclosureHeld++
			}
			if a.DisclosureHeldSince != nil {
				m.DisclosureHeldSeconds = max(m.DisclosureHeldSeconds, now.Sub(time.Unix(*a.DisclosureHeldSince, 0)).Seconds())
			}
		}
	}
	if e.vantage == nil || e.vantage.clock == nil || !fresh(e.vantageObserved) {
		m.ClockUnknown++
		m.ClockEstimateUnknown++
	} else {
		c := e.vantage.clock
		switch c.Readiness {
		case "ready":
			m.ClockReady++
		case "degraded":
			m.ClockDegraded++
		default:
			m.ClockUnknown++
		}
		if c.EstimatedErrorNS == nil {
			m.ClockEstimateUnknown++
		} else {
			seconds := float64(*c.EstimatedErrorNS) / float64(time.Second)
			if m.ClockEstimatedErrorSeconds == nil || seconds > *m.ClockEstimatedErrorSeconds {
				m.ClockEstimatedErrorSeconds = &seconds
			}
		}
	}
	// Guard arithmetic on the announced schedule. Older executors omit its
	// length, which cannot be treated as an expired zero-length chain.
	if !fresh(e.capabilityObserved) || e.TeslaChainLength <= 0 || e.TeslaDelay <= 0 ||
		e.TeslaChainLength > math.MaxInt64/int64(e.TeslaDelay) || e.TeslaAnchorTimestamp.IsZero() {
		m.ScheduleUnknown++
		return
	}
	remaining := e.TeslaAnchorTimestamp.Add(time.Duration(e.TeslaChainLength) * e.TeslaDelay).Sub(now).Seconds()
	if remaining <= 0 {
		m.ScheduleExpired++
	}
	remaining = max(remaining, 0)
	if m.ScheduleRemainingSeconds == nil || remaining < *m.ScheduleRemainingSeconds {
		m.ScheduleRemainingSeconds = &remaining
	}
}
