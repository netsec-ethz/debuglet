// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"fmt"
	"math"
	"slices"
	"time"
)

// Scheduling is sequential. Network services own their background I/O; a graph
// does not create goroutines or recursively call itself to keep running.
type scheduleState struct {
	anchor, tick, end, turnEnd time.Time
	used, active, inTurn       bool
	traceEvents, traceBytes    int
	clock                      func() time.Time
	sleep                      func(time.Duration)
}

func (s *scheduleState) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

func (s *scheduleState) wait(until time.Time) {
	// WASI nanosleep can occupy its host call until the sleep ends. Return to
	// guest execution frequently so executor cancellation can interrupt a long
	// scheduled wait instead of holding a terminated run for hours.
	for d := until.Sub(s.now()); d > 0; d = until.Sub(s.now()) {
		if d > 100*time.Millisecond {
			d = 100 * time.Millisecond
		}
		if s.sleep != nil {
			s.sleep(d)
		} else {
			time.Sleep(d)
		}
	}
}

// SetScheduleAnchor uses the admitted common start for cross-participant slots.
// This is an agreed timestamp, not a guarantee that host clocks are synchronized.
func (r *Runtime) SetScheduleAnchor(start time.Time) { r.schedule.anchor = start }

// ActionDeadline bounds network actions by both the current pair slot and the
// periodic campaign end. Zero means the ordinary per-action policy applies.
func (r *Runtime) ActionDeadline() time.Time {
	end := r.schedule.end
	if !r.schedule.turnEnd.IsZero() && (end.IsZero() || r.schedule.turnEnd.Before(end)) {
		end = r.schedule.turnEnd
	}
	return end
}

func scheduleMillis(in map[string]any, key string, min, max float64) (time.Duration, error) {
	n, ok := in[key].(float64)
	if !ok || math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n || n < min || n > max {
		return 0, fmt.Errorf("%s must be an integer from %.0f to %.0f ms", key, min, max)
	}
	return time.Duration(n) * time.Millisecond, nil
}

// Every runs at most 86,400 fixed-cadence iterations over at most 24 hours.
// Late work skips elapsed ticks instead of producing a catch-up traffic burst.
func (r *Runtime) Every(in map[string]any, body func(map[string]any) error) error {
	if r.schedule.used {
		return fmt.Errorf("only one Every execution is allowed per workflow")
	}
	interval, err := scheduleMillis(in, "interval_ms", 1000, 86400000)
	if err != nil {
		return err
	}
	duration, err := scheduleMillis(in, "duration_ms", 1, 86400000)
	if err != nil {
		return err
	}
	delay, err := scheduleMillis(in, "start_delay_ms", 0, 60000)
	if err != nil {
		return err
	}
	immediate, ok := in["immediate"].(bool)
	if !ok {
		return fmt.Errorf("immediate must be boolean")
	}
	start := r.schedule.anchor
	if start.IsZero() {
		start = r.schedule.now()
	}
	start = start.Add(delay)
	end := start.Add(duration)
	r.schedule.used, r.schedule.active, r.schedule.end = true, true, end
	previousSteps := r.steps
	defer func() {
		r.steps = previousSteps
		r.schedule.active = false
		r.schedule.end = time.Time{}
		r.schedule.tick = time.Time{}
	}()
	first := int64(0)
	if !immediate {
		first = 1
	}
	index, missed := first, int64(0)
	for index < 86400 {
		tick := start.Add(time.Duration(index) * interval)
		if !tick.Before(end) {
			break
		}
		now := r.schedule.now()
		if !now.Before(end) {
			break
		}
		if behind := now.Sub(tick) / interval; behind > 0 {
			index += int64(behind)
			missed += int64(behind)
			continue
		}
		r.schedule.wait(tick)
		if !r.schedule.now().Before(end) {
			break
		}
		r.schedule.tick, r.steps = tick, 0
		values := map[string]any{"iteration": float64(index - first + 1), "elapsed_ms": float64(tick.Sub(start) / time.Millisecond), "missed_intervals": float64(missed)}
		if err := body(values); err != nil {
			return err
		}
		index++
	}
	r.schedule.wait(end)
	return nil
}

// ForEachPeer assigns a distinct slot to every ordered pair. All participants
// walk the same sorted roster, but only a slot's sender executes the body. TCP
// transfer uses ActionDeadline so it cannot continue into the following slot.
func (r *Runtime) ForEachPeer(in map[string]any, self string, participants []string, body func(map[string]any) error) error {
	if r.schedule.inTurn {
		return fmt.Errorf("peer turns cannot be nested")
	}
	slot, err := scheduleMillis(in, "slot_ms", 1000, 60000)
	if err != nil {
		return err
	}
	ids := append([]string(nil), participants...)
	slices.Sort(ids)
	if len(ids) < 2 || len(ids) > 16 || !slices.Contains(ids, self) {
		return fmt.Errorf("peer turns require 2–16 admitted participants")
	}
	for i, id := range ids {
		if id == "" || i > 0 && ids[i-1] == id {
			return fmt.Errorf("peer turns require unique participants")
		}
	}
	start := r.schedule.tick
	if start.IsZero() {
		start = r.schedule.anchor
	}
	if start.IsZero() {
		return fmt.Errorf("peer turns require an admitted common start")
	}
	r.schedule.inTurn = true
	defer func() { r.schedule.inTurn = false; r.schedule.turnEnd = time.Time{} }()
	turn := 0
	for _, from := range ids {
		for _, to := range ids {
			if from == to {
				continue
			}
			begin := start.Add(time.Duration(turn) * slot)
			end := begin.Add(slot)
			turn++
			if !r.schedule.end.IsZero() && !begin.Before(r.schedule.end) {
				return nil
			}
			if from != self || !r.schedule.now().Before(end) {
				continue
			}
			r.schedule.wait(begin)
			r.schedule.turnEnd = end
			if !r.schedule.now().Before(r.ActionDeadline()) {
				continue
			}
			if err := body(map[string]any{"peer": to, "turn": float64(turn)}); err != nil {
				return err
			}
		}
	}
	finish := start.Add(time.Duration(turn) * slot)
	if !r.schedule.end.IsZero() && r.schedule.end.Before(finish) {
		finish = r.schedule.end
	}
	r.schedule.wait(finish)
	return nil
}
