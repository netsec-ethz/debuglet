// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTimersAreMonotonicRunLocalAndBounded(t *testing.T) {
	r := New("test")
	out, err := r.StartTimer()
	if err != nil {
		t.Fatal(err)
	}
	id := out["timer"].(string)
	r.timers[id] = time.Now().Add(-20 * time.Millisecond)
	first, err := r.Elapsed(out)
	if err != nil || first["duration_ms"].(float64) < 20 {
		t.Fatalf("elapsed = %v, %v", first, err)
	}
	second, err := r.Elapsed(out)
	if err != nil || second["duration_ms"].(float64) < first["duration_ms"].(float64) {
		t.Fatalf("timer was reset by reading: %v, %v", second, err)
	}
	if _, err := New("other").Elapsed(out); err == nil {
		t.Fatal("accepted timer with no local start")
	}
	for i := 1; i < maxTimers; i++ {
		if _, err := r.StartTimer(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.StartTimer(); err == nil {
		t.Fatal("unbounded timers")
	}
}

func TestCollectionSnapshotsSurviveRepeatAndReset(t *testing.T) {
	r := New("test")
	handle, err := r.CreateCollection()
	if err != nil {
		t.Fatal(err)
	}
	sample := map[string]any{"items": []any{float64(1)}}
	in := map[string]any{"collection": handle["collection"], "value": sample}
	if _, err := r.Collect(in); err != nil {
		t.Fatal(err)
	}
	sample["items"].([]any)[0] = float64(2)
	r.Forget("create", "collect", "read")
	first, err := r.ReadCollection(handle)
	if err != nil {
		t.Fatal(err)
	}
	if got := first["values"].([]any)[0].(map[string]any)["items"].([]any)[0]; got != float64(1) {
		t.Fatal("input mutation changed collected sample:", got)
	}
	first["values"].([]any)[0].(map[string]any)["items"].([]any)[0] = float64(3)
	second, err := r.ReadCollection(handle)
	if err != nil || second["values"].([]any)[0].(map[string]any)["items"].([]any)[0] != float64(1) {
		t.Fatalf("read returned mutable state: %v %v", second, err)
	}
	if _, err := r.ResetCollection(handle); err != nil {
		t.Fatal(err)
	}
	empty, err := r.ReadCollection(handle)
	if err != nil || !reflect.DeepEqual(empty["values"], []any{}) || r.collectionBytes != 0 {
		t.Fatalf("reset: %v %v bytes=%d", empty, err, r.collectionBytes)
	}
	if _, err := r.Collect(in); err != nil {
		t.Fatal("collection handle unusable after reset:", err)
	}
}

func TestCollectionMemoryBoundsAreAtomic(t *testing.T) {
	r := New("test")
	handle, _ := r.CreateCollection()
	in := map[string]any{"collection": handle["collection"], "value": strings.Repeat("x", 16000)}
	for i := 0; i < 3; i++ {
		if _, err := r.Collect(in); err != nil {
			t.Fatal(err)
		}
	}
	before := r.collectionBytes
	if _, err := r.Collect(in); err == nil || r.collectionBytes != before {
		t.Fatalf("per-collection bound changed state: %v bytes=%d", err, r.collectionBytes)
	}
	full := false
	for i := 1; i < 8 && !full; i++ {
		handle, _ = r.CreateCollection()
		in["collection"] = handle["collection"]
		for j := 0; j < 3; j++ {
			before = r.collectionBytes
			if _, err := r.Collect(in); err != nil {
				if r.collectionBytes != before || before > maxCollectionStateBytes {
					t.Fatalf("global bound changed state: %v bytes=%d", err, r.collectionBytes)
				}
				full = true
				break
			}
		}
	}
	if !full {
		t.Fatal("global collection bound not enforced")
	}
	for len(r.collections) < maxCollections {
		if _, err := r.CreateCollection(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.CreateCollection(); err == nil {
		t.Fatal("unbounded collection handles")
	}
}

func TestCollectionSampleCountAndInvalidValues(t *testing.T) {
	r := New("test")
	handle, _ := r.CreateCollection()
	in := map[string]any{"collection": handle["collection"], "value": nil}
	for i := 0; i < 1024; i++ {
		if _, err := r.Collect(in); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Collect(in); err == nil {
		t.Fatal("unbounded sample count")
	}
	if _, err := New("other").ReadCollection(handle); err == nil {
		t.Fatal("accepted collection with no local creation")
	}
	_, _ = r.ResetCollection(handle)
	in["value"] = make(chan int)
	if _, err := r.Collect(in); err == nil || r.collectionBytes != 0 {
		t.Fatal("non-JSON sample altered collection")
	}
}
