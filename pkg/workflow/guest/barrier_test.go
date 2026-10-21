// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func barrierIncoming(e *Experiment, peer, phase string, generation, sequence uint64) experimentFrame {
	f := experimentIncoming(e, peer, "", "", sequence, nil)
	f.Barrier = &experimentBarrierArrival{phase, generation}
	return f
}

func TestBarrierSeparatesEarlyRepeatedAndLateArrivals(t *testing.T) {
	e := experimentFixture(t, "a")
	queueExperiment(t, e, barrierIncoming(e, "b", "sample", 1, 1))
	state := e.barriers["sample"]
	if state.generation != 0 || len(state.current) != 0 || !state.next["b"] {
		t.Fatal("arrival before local phase entry was lost")
	}
	state.generation++
	state.current, state.next = state.next, map[string]bool{}
	queueExperiment(t, e, barrierIncoming(e, "b", "sample", 2, 2))
	if got := e.barrierMissing(state); !reflect.DeepEqual(got, []any{"c"}) {
		t.Fatalf("next arrival replaced current generation: %#v", got)
	}
	queueExperiment(t, e, barrierIncoming(e, "c", "sample", 1, 1))
	if len(e.barrierMissing(state)) != 0 {
		t.Fatal("not every current arrival was retained")
	}
	state.generation++
	state.current, state.next = state.next, map[string]bool{}
	queueExperiment(t, e, barrierIncoming(e, "c", "sample", 1, 1))
	if got := e.barrierMissing(state); !reflect.DeepEqual(got, []any{"c"}) {
		t.Fatalf("stale arrival satisfied the next generation: %#v", got)
	}
	queueExperiment(t, e, barrierIncoming(e, "b", "sample", 2, 2))
	if got := e.barrierMissing(state); !reflect.DeepEqual(got, []any{"c"}) {
		t.Fatalf("duplicate arrival changed membership: %#v", got)
	}
	queueExperiment(t, e, barrierIncoming(e, "c", "sample", 2, 2))
	if len(e.barrierMissing(state)) != 0 || len(e.inbox) != 0 || e.inboxBytes != 0 {
		t.Fatal("barrier arrivals must not occupy the application inbox")
	}
}

func TestBarrierPreservesUserMessagesAndOtherPhases(t *testing.T) {
	e := experimentFixture(t, "b")
	queueExperiment(t, e, experimentIncoming(e, "c", "other", "", 1, true))
	queueExperiment(t, e, barrierIncoming(e, "c", "sample", 1, 2))
	queueExperiment(t, e, barrierIncoming(e, "a", "finished", 1, 1))
	if !e.barriers["sample"].next["c"] || e.barriers["sample"].next["a"] || !e.barriers["finished"].next["a"] {
		t.Fatal("separate phases mixed arrivals")
	}
	out, err := e.Await(map[string]any{"source": "c", "channel": "other"})
	if err != nil || out["ok"] != true || out["value"] != true {
		t.Fatalf("user message was consumed by barrier: %#v, %v", out, err)
	}
}

func TestBarrierRejectsMisdirectedMalformedAndFarFutureArrivals(t *testing.T) {
	for name, edit := range map[string]func(*experimentFrame){
		"other group":         func(f *experimentFrame) { f.ExperimentID = "other" },
		"other run":           func(f *experimentFrame) { f.FromRunID = "other" },
		"other participant":   func(f *experimentFrame) { f.To = "c" },
		"application channel": func(f *experimentFrame) { f.Channel = "other" },
		"application value":   func(f *experimentFrame) { f.Value = true },
		"request id":          func(f *experimentFrame) { f.RequestID = strings.Repeat("a", 32) },
		"empty phase":         func(f *experimentFrame) { f.Barrier.Phase = "" },
		"long phase":          func(f *experimentFrame) { f.Barrier.Phase = strings.Repeat("x", 65) },
		"zero generation":     func(f *experimentFrame) { f.Barrier.Generation = 0 },
		"zero sequence":       func(f *experimentFrame) { f.Sequence = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			e := experimentFixture(t, "b")
			f := barrierIncoming(e, "c", "sample", 1, 1)
			edit(&f)
			if err := e.enqueue(f, 400); err == nil {
				t.Fatal("accepted invalid arrival")
			}
			if len(e.inbox) != 0 || len(e.received) != 0 || len(e.barriers) != 0 {
				t.Fatal("invalid arrival changed state")
			}
		})
	}
}

func TestBarrierStateAndInputBounds(t *testing.T) {
	e := experimentFixture(t, "a")
	for i := 1; i <= experimentBarrierLimit; i++ {
		queueExperiment(t, e, barrierIncoming(e, "b", fmt.Sprint("phase", i), 1, uint64(i)))
	}
	if err := e.enqueue(barrierIncoming(e, "b", "overflow", 1, 65), 400); err == nil || len(e.barriers) != 64 {
		t.Fatal("phase state grew beyond its limit")
	}
	for _, inputs := range []map[string]any{
		{}, {"phase": ""}, {"phase": " sample"}, {"phase": strings.Repeat("x", 65)},
		{"phase": "sample", "timeout_ms": float64(-1)},
	} {
		if _, err := e.Barrier(inputs); err == nil {
			t.Fatalf("accepted invalid barrier inputs %#v", inputs)
		}
	}
}

func TestBarrierIgnoresSkippedFutureGenerations(t *testing.T) {
	e := experimentFixture(t, "b")
	queueExperiment(t, e, barrierIncoming(e, "c", "skipped", 2, 2))
	if len(e.barriers) != 0 || len(e.received) != 0 {
		t.Fatal("far future arrival allocated state or advanced application replay state")
	}
	queueExperiment(t, e, barrierIncoming(e, "c", "skipped", 1, 1))
	queueExperiment(t, e, barrierIncoming(e, "c", "skipped", 2, 2))
	if len(e.barriers) != 1 || len(e.barriers["skipped"].next) != 1 {
		t.Fatal("future arrival changed the queued generation")
	}
	queueExperiment(t, e, experimentIncoming(e, "c", "other", "", 1, true))
	out, err := e.Await(map[string]any{"source": "c", "channel": "other"})
	if err != nil || out["ok"] != true {
		t.Fatalf("phase generation consumed an application sequence: %#v, %v", out, err)
	}
}
