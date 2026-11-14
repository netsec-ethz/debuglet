// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
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

type barrierReadConn struct {
	net.Conn
	started  chan struct{}
	closed   bool
	deadline time.Time
}

func (c *barrierReadConn) Read(p []byte) (int, error) {
	if c.started != nil {
		close(c.started)
		c.started = nil
	}
	return c.Conn.Read(p)
}

func (c *barrierReadConn) Close() error {
	c.closed = true
	return c.Conn.Close()
}

func (c *barrierReadConn) SetReadDeadline(deadline time.Time) error {
	c.deadline = deadline
	return c.Conn.SetReadDeadline(deadline)
}

func TestBarrierRetainsArrivalAcrossReadDeadline(t *testing.T) {
	for _, split := range []int{0, 2, 4, 32} {
		t.Run(fmt.Sprint(split), func(t *testing.T) {
			e := experimentFixture(t, "a")
			previous := &experimentBarrierState{generation: 2, current: map[string]bool{"b": true}, next: map[string]bool{}}
			e.barriers["missing"] = previous
			packet, err := experimentEncode(barrierIncoming(e, "b", "recovery", 1, 1))
			if err != nil {
				t.Fatal(err)
			}
			reader, writer := net.Pipe()
			defer reader.Close()
			defer writer.Close()
			started := make(chan struct{})
			conn := &barrierReadConn{Conn: reader, started: started}
			expires := time.Now().Add(5 * time.Second)
			e.receiving = &experimentFrameReceiver{conn: conn, expires: expires}
			resume, done := make(chan struct{}), make(chan error, 1)
			go func() {
				<-started
				if err := writer.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
					done <- err
					return
				}
				if err := experimentWrite(writer, packet[:split]); err != nil {
					done <- err
					return
				}
				// The prefix was consumed. Expire the read deterministically,
				// without relying on the sender and receiver's scheduling.
				if err := reader.SetReadDeadline(time.Now()); err != nil {
					done <- err
					return
				}
				<-resume
				done <- experimentWrite(writer, packet[split:])
			}()
			err = e.receiveFrame(time.Now().Add(time.Second))
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				close(resume)
				t.Fatalf("partial read error = %v, want timeout", err)
			}
			if e.receiving == nil || conn.closed || e.barriers["recovery"] != nil {
				close(resume)
				t.Fatal("timeout discarded the frame or published an incomplete arrival")
			}
			if !e.receiving.expires.Equal(expires) {
				close(resume)
				t.Fatal("phase timeout renewed the accepted frame's lifetime")
			}
			if got := e.barrierMissing(previous); !reflect.DeepEqual(got, []any{"c"}) {
				close(resume)
				t.Fatalf("partial arrival changed the old phase: %v", got)
			}
			close(resume)
			if err := e.receiveFrame(time.Now().Add(time.Second)); err != nil {
				t.Fatal("resume arrival:", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if e.receiving != nil || !conn.closed {
				t.Fatal("complete frame retained its socket")
			}
			state := e.barriers["recovery"]
			if state == nil || len(state.next) != 1 || !state.next["b"] || len(e.inbox) != 0 {
				t.Fatalf("next-phase arrival not retained exactly once: %#v", state)
			}
		})
	}
}

func TestBarrierClosesUnrecoverableFrame(t *testing.T) {
	for name, packet := range map[string][]byte{
		"short header": {0, 0},
		"short body":   {0, 0, 0, 2, '{'},
		"oversized":    {0, 0, 32, 1},
		"invalid JSON": {0, 0, 0, 1, '{'},
	} {
		t.Run(name, func(t *testing.T) {
			e := experimentFixture(t, "a")
			reader, writer := net.Pipe()
			defer reader.Close()
			defer writer.Close()
			conn := &barrierReadConn{Conn: reader}
			e.receiving = &experimentFrameReceiver{conn: conn, expires: time.Now().Add(time.Second)}
			go func() {
				defer writer.Close()
				_ = experimentWrite(writer, packet)
			}()
			if err := e.receiveFrame(time.Now().Add(time.Second)); err == nil {
				t.Fatal("accepted invalid frame")
			}
			if e.receiving != nil || !conn.closed || len(e.barriers) != 0 {
				t.Fatal("invalid frame retained a socket or changed arrivals")
			}
		})
	}
}

func TestBarrierExpiresAbandonedFrameBeforeNextPeer(t *testing.T) {
	for _, split := range []int{2, 32} {
		t.Run(fmt.Sprint(split), func(t *testing.T) {
			e := experimentFixture(t, "a")
			packet, err := experimentEncode(barrierIncoming(e, "b", "recovery", 1, 1))
			if err != nil {
				t.Fatal(err)
			}
			reader, stalled := net.Pipe()
			defer reader.Close()
			defer stalled.Close()
			started, sent := make(chan struct{}), make(chan error, 1)
			conn := &barrierReadConn{Conn: reader, started: started}
			e.receiving = &experimentFrameReceiver{conn: conn, expires: time.Now().Add(time.Minute)}
			go func() {
				<-started
				if err := experimentWrite(stalled, packet[:split]); err != nil {
					sent <- err
					return
				}
				sent <- reader.SetReadDeadline(time.Now())
				// Keep this sender open without supplying the remaining bytes.
			}()
			var timeout net.Error
			if err := e.receiveFrame(time.Now().Add(time.Second)); !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("partial frame error = %v, want timeout", err)
			}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			if e.receiving == nil || conn.closed {
				t.Fatal("short phase did not retain the partial frame")
			}
			// Advance the stored absolute expiry, without sleeping or extending
			// this peer's lifetime to match the next operation's longer budget.
			expired := time.Now().Add(-time.Second)
			e.receiving.expires = expired
			if err := e.receiveFrame(time.Now().Add(time.Minute)); err != nil {
				t.Fatal("abandoned peer aborted the next phase:", err)
			}
			if e.receiving != nil || !conn.closed || !conn.deadline.Equal(expired) {
				t.Fatal("later phase renewed or retained the abandoned frame")
			}

			// Exercise the now-free receiver with the next accepted peer.
			packet, err = experimentEncode(barrierIncoming(e, "c", "recovery", 1, 1))
			if err != nil {
				t.Fatal(err)
			}
			reader, healthy := net.Pipe()
			defer reader.Close()
			defer healthy.Close()
			conn = &barrierReadConn{Conn: reader}
			e.receiving = &experimentFrameReceiver{conn: conn, expires: time.Now().Add(time.Second)}
			go func() { sent <- experimentWrite(healthy, packet) }()
			if err := e.receiveFrame(time.Now().Add(time.Second)); err != nil {
				t.Fatal("healthy peer after abandonment:", err)
			}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			if state := e.barriers["recovery"]; state == nil || !state.next["c"] || len(state.next) != 1 {
				t.Fatal("healthy next-phase arrival was not retained")
			}
			if e.receiving != nil || !conn.closed {
				t.Fatal("healthy completed frame retained its socket")
			}
		})
	}
}
