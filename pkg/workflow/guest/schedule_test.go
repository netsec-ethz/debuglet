// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func scheduledRuntime() (*Runtime, *time.Time) {
	r := New("schedule")
	now := time.Unix(1000, 0)
	r.schedule.clock = func() time.Time { return now }
	r.schedule.sleep = func(d time.Duration) { now = now.Add(d) }
	r.writer = &bytes.Buffer{}
	r.SetScheduleAnchor(now)
	return r, &now
}

func everyInputs() map[string]any {
	return map[string]any{"interval_ms": float64(1000), "duration_ms": float64(6000), "start_delay_ms": float64(0), "immediate": true}
}

func TestEveryKeepsCadenceSkipsMissedTicksAndResetsOnlyIterationBudget(t *testing.T) {
	r, now := scheduledRuntime()
	var ticks, missed []float64
	err := r.Every(everyInputs(), func(v map[string]any) error {
		ticks = append(ticks, v["elapsed_ms"].(float64))
		missed = append(missed, v["missed_intervals"].(float64))
		for i := 0; i < 300; i++ {
			if err := r.Step(); err != nil {
				return err
			}
		}
		if len(ticks) == 2 {
			*now = now.Add(2600 * time.Millisecond)
		}
		return nil
	})
	if err != nil || !reflect.DeepEqual(ticks, []float64{0, 1000, 3000, 4000, 5000}) || missed[2] != 1 {
		t.Fatalf("ticks=%v missed=%v err=%v", ticks, missed, err)
	}
	if !now.Equal(time.Unix(1006, 0)) {
		t.Fatal("campaign did not wait until its end")
	}
	if err := r.Every(everyInputs(), func(map[string]any) error { return nil }); err == nil {
		t.Fatal("Every could reset budgets again")
	}
	r, _ = scheduledRuntime()
	if err := r.Every(everyInputs(), func(map[string]any) error {
		for i := 0; i < 1001; i++ {
			if err := r.Step(); err != nil {
				return err
			}
		}
		return nil
	}); err == nil {
		t.Fatal("per-iteration action limit missing")
	}
}

func TestPeerTurnsCoverEachDirectedPairOnceAndBoundLateTransfer(t *testing.T) {
	seen := map[int]string{}
	for _, self := range []string{"c", "a", "b"} {
		r, now := scheduledRuntime()
		err := r.ForEachPeer(map[string]any{"slot_ms": float64(1000)}, self, []string{"b", "c", "a"}, func(v map[string]any) error {
			turn := int(v["turn"].(float64))
			if _, ok := seen[turn]; ok {
				return fmt.Errorf("overlapping turn %d", turn)
			}
			seen[turn] = self + v["peer"].(string)
			if !now.Equal(time.Unix(1000+int64(turn-1), 0)) || !r.ActionDeadline().Equal(time.Unix(1000+int64(turn), 0)) {
				return fmt.Errorf("wrong slot bounds")
			}
			return nil
		})
		if err != nil || !now.Equal(time.Unix(1006, 0)) {
			t.Fatalf("%s: %v time=%v", self, err, now)
		}
	}
	if !reflect.DeepEqual(seen, map[int]string{1: "ab", 2: "ac", 3: "ba", 4: "bc", 5: "ca", 6: "cb"}) {
		t.Fatal(seen)
	}
	r, now := scheduledRuntime()
	*now = now.Add(1500 * time.Millisecond)
	count := 0
	if err := r.ForEachPeer(map[string]any{"slot_ms": float64(1000)}, "a", []string{"a", "b", "c"}, func(v map[string]any) error {
		count++
		if v["peer"] != "c" || r.ActionDeadline().Sub(*now) != 500*time.Millisecond {
			t.Fatal("late slot was restarted")
		}
		return nil
	}); err != nil || count != 1 {
		t.Fatalf("late turns=%d err=%v", count, err)
	}
}

func TestPeriodicTraceIsBoundedButSamplesAndFailuresRemainVisible(t *testing.T) {
	r, _ := scheduledRuntime()
	var out bytes.Buffer
	r.writer = &out
	in := everyInputs()
	in["duration_ms"] = float64(100000)
	err := r.Every(in, func(v map[string]any) error {
		for i := 0; i < 20; i++ {
			if err := r.Record("math", "add", map[string]any{"value": v["iteration"]}); err != nil {
				return err
			}
		}
		_, err := r.PlotSample(sampleInputs())
		return err
	})
	if err != nil || r.events != 164 || r.values["math"]["value"] != float64(100) {
		t.Fatalf("events=%d outputs=%v err=%v", r.events, r.values, err)
	}
	before := out.Len()
	_ = r.Fail("late", "network", fmt.Errorf("visible failure"))
	if out.Len() == before {
		t.Fatal("failure suppressed")
	}
	r.events = 100000
	if _, err := r.PlotSample(sampleInputs()); err == nil {
		t.Fatal("periodic result cap missing")
	}
}

func TestScheduleRejectsUnboundedAndNestedInputs(t *testing.T) {
	for _, change := range []func(map[string]any){func(v map[string]any) { v["duration_ms"] = float64(86400001) }, func(v map[string]any) { v["interval_ms"] = float64(0) }, func(v map[string]any) { v["start_delay_ms"] = float64(-1) }} {
		r, _ := scheduledRuntime()
		v := everyInputs()
		change(v)
		if err := r.Every(v, func(map[string]any) error { return nil }); err == nil {
			t.Fatal("invalid schedule accepted")
		}
	}
	r, _ := scheduledRuntime()
	if err := r.ForEachPeer(map[string]any{"slot_ms": float64(1000)}, "a", []string{"a", "a"}, func(map[string]any) error { return nil }); err == nil {
		t.Fatal("ambiguous roster accepted")
	}
}
