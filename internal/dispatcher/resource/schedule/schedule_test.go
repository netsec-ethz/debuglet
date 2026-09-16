// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package schedule

import (
	"debuglet/internal/dispatcher/resource"
	"testing"
	"time"
)

func baseTime() time.Time {
	return time.Unix(1000, 0)
}

func makeReq(exec string, dests []string, from, to time.Time, use int64) Request {
	return Request{
		Executor:    exec,
		Destination: dests,
		From:        from,
		To:          to,
		Use:         resource.Bitrate(use),
	}
}

func TestSubmitAndRemove(t *testing.T) {
	s := New(time.Second)
	t0 := baseTime()
	from := t0
	to := t0.Add(10 * time.Second)

	req := makeReq("e1", []string{"d1"}, from, to, 100)
	s.Submit(req)

	if got := s.QueryMaxExec("e1", from, to); got != 100 {
		t.Fatalf("QueryMaxExec after submit = %d; want 100", got)
	}
	if got := s.QueryMaxDest("d1", from, to); got != 100 {
		t.Fatalf("QueryMaxDest after submit = %d; want 100", got)
	}

	s.Remove(req)

	if got := s.QueryMaxExec("e1", from, to); got != 0 {
		t.Fatalf("QueryMaxExec after remove = %d; want 0", got)
	}
	if got := s.QueryMaxDest("d1", from, to); got != 0 {
		t.Fatalf("QueryMaxDest after remove = %d; want 0", got)
	}
}

func TestOverlapping(t *testing.T) {
	s := New(time.Second)
	t0 := baseTime()

	req1 := makeReq("e1", []string{"d1"}, t0, t0.Add(10*time.Second), 60)
	req2 := makeReq("e2", []string{"d1"}, t0.Add(5*time.Second), t0.Add(15*time.Second), 60)

	s.Submit(req1)
	s.Submit(req2)

	overlapFrom := t0.Add(5 * time.Second)
	overlapTo := t0.Add(10 * time.Second)
	if got := s.QueryMaxDest("d1", overlapFrom, overlapTo); got != 120 {
		t.Fatalf("QueryMaxDest in overlap [%v, %v] = %d; want 120", overlapFrom, overlapTo, got)
	}

	s.Remove(req1)
	s.Remove(req2)

	if got := s.QueryMaxDest("d1", t0, t0.Add(20*time.Second)); got != 0 {
		t.Fatalf("QueryMaxDest after removes = %d; want 0", got)
	}
}

func TestNonOverlapping(t *testing.T) {
	s := New(time.Second)
	t0 := baseTime()

	req1 := makeReq("e1", []string{"d1"}, t0, t0.Add(10*time.Second), 60)
	req2 := makeReq("e2", []string{"d1"}, t0.Add(15*time.Second), t0.Add(25*time.Second), 60)

	s.Submit(req1)
	s.Submit(req2)

	gapFrom := t0.Add(11 * time.Second)
	gapTo := t0.Add(14 * time.Second)
	if got := s.QueryMaxDest("d1", gapFrom, gapTo); got != 0 {
		t.Fatalf("QueryMaxDest in gap = %d; want 0", got)
	}

	if got := s.QueryMaxDest("d1", t0, t0.Add(10*time.Second)); got != 60 {
		t.Fatalf("QueryMaxDest in first window = %d; want 60", got)
	}

	if got := s.QueryMaxDest("d1", t0.Add(15*time.Second), t0.Add(25*time.Second)); got != 60 {
		t.Fatalf("QueryMaxDest in second window = %d; want 60", got)
	}

	s.Remove(req1)
	s.Remove(req2)

	if got := s.QueryMaxDest("d1", t0, t0.Add(30*time.Second)); got != 0 {
		t.Fatalf("QueryMaxDest after removes = %d; want 0", got)
	}
}

func TestMultipleDestinations(t *testing.T) {
	s := New(time.Second)
	t0 := baseTime()
	from := t0
	to := t0.Add(10 * time.Second)

	req := makeReq("e1", []string{"d1", "d2"}, from, to, 100)
	s.Submit(req)

	if got := s.QueryMaxDest("d1", from, to); got != 100 {
		t.Fatalf("QueryMaxDest d1 = %d; want 100", got)
	}
	if got := s.QueryMaxDest("d2", from, to); got != 100 {
		t.Fatalf("QueryMaxDest d2 = %d; want 100", got)
	}
	if got := s.QueryMaxDest("d3", from, to); got != 0 {
		t.Fatalf("QueryMaxDest d3 = %d; want 0", got)
	}

	s.Remove(req)

	if got := s.QueryMaxDest("d1", from, to); got != 0 {
		t.Fatalf("QueryMaxDest d1 after remove = %d; want 0", got)
	}
	if got := s.QueryMaxDest("d2", from, to); got != 0 {
		t.Fatalf("QueryMaxDest d2 after remove = %d; want 0", got)
	}
}

func TestZeroDurationWindow(t *testing.T) {
	s := New(time.Second)
	t0 := baseTime()

	req := makeReq("e1", []string{"d1"}, t0, t0, 100)
	s.Submit(req)

	if got := s.QueryMaxDest("d1", t0, t0.Add(time.Second)); got != 100 {
		t.Fatalf("QueryMaxDest over narrow range = %d; want 100", got)
	}

	s.Remove(req)
	if got := s.QueryMaxDest("d1", t0, t0.Add(time.Second)); got != 0 {
		t.Fatalf("QueryMaxDest after remove = %d; want 0", got)
	}
}
