// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// serveAttribution answers the public attribution routes from a fakeSource.
func serveAttribution(t *testing.T, f *fakeServer, src *fakeSource) {
	f.handle("GET /attribution/candidates", func(w http.ResponseWriter, r *http.Request) {
		ip, err := netip.ParseAddr(r.URL.Query().Get("ip"))
		at, err2 := time.Parse(time.RFC3339Nano, r.URL.Query().Get("at"))
		if err != nil || err2 != nil {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		l, _ := src.candidates(r.Context(), ip, at)
		doc := AttributionCandidates{IP: ip.String(), At: at, RetainedFrom: l.RetainedFrom, Truncated: l.Truncated, Candidates: []AttributionCandidate{}}
		if doc.RetainedFrom.IsZero() {
			doc.RetainedFrom = time.Unix(0, 0)
		}
		for _, c := range l.Candidates {
			s := c.Schedule
			var at int64
			if c.DisclosedThrough > 0 {
				at = s.dueAt(c.DisclosedThrough).UnixNano()
			}
			doc.Candidates = append(doc.Candidates, AttributionCandidate{
				ExecutorID: c.ExecutorID, RunID: c.RunID, ActiveFrom: c.ActiveFrom, ActiveTo: c.ActiveTo, IPSource: "observed",
				Schedule: AttributionSchedule{ChainID: s.ChainID, K0: s.K0, T0UnixNs: s.T0UnixNs, EpochSeconds: s.EpochSeconds,
					DisclosureDelayEpochs: s.DisclosureDelayEpochs, ChainLength: s.ChainLength, TagSpec: s.TagSpec},
				DisclosedThrough: c.DisclosedThrough, DisclosedThroughAtNs: at, NextDisclosureAtNs: s.dueAt(c.DisclosedThrough + 1).UnixNano(),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	f.handle("GET /attribution/keys", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		from, _ := strconv.ParseInt(q.Get("from_epoch"), 10, 64)
		to, err := strconv.ParseInt(q.Get("to_epoch"), 10, 64)
		if err != nil {
			to = 1 << 40
		}
		to = min(to, from+1023)
		keys, next, err := src.keys(r.Context(), q.Get("executor_id"), q.Get("chain_id"), from, to)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		doc := AttributionKeys{ExecutorID: q.Get("executor_id"), ChainID: q.Get("chain_id"), Keys: []AttributionKey{}}
		for _, k := range keys {
			doc.Keys = append(doc.Keys, AttributionKey{Epoch: k.Epoch, Key: k.Key})
		}
		doc.NextEpoch = next
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
}

func TestVerifyOverTheAttributionRoutes(t *testing.T) {
	chain := newTestChain("exec-zrh-1", 1, 1000, 90)
	chain.sched.T0UnixNs = time.Now().Add(-time.Hour).UnixNano()
	src := &fakeSource{now: time.Now(), runs: []fakeRun{{ip: srcA, run: runA, chain: chain, from: chain.at(0, 0), to: time.Now().Add(time.Hour)}}}
	f := newFakeServer(t, "/api")
	serveAttribution(t, f, src)
	e := int64(200)
	pkts := append(packetsAt(chain.at(e, time.Second), chain.tag(e, runA, probe(srcA, 80, 1)), chain.tag(e, runA, probe(srcA, 90, 2))),
		CapturedPacket{Data: probe(srcB, 60, 3), CapturedAt: chain.at(e, 0)})
	rep, err := f.client(t, Options{}).Verify(t.Context(), pkts, VerifyOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts != (VerifyCounts{Verified: 1, Invalid: 1}) || rep.Groups[0].RunID != runA || rep.Dispatcher != f.endpoint() {
		t.Fatalf("report %+v", rep)
	}
	for _, r := range f.requests() {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || len(r.Body) != 0 {
			t.Fatalf("request %s %s sent a credential or a body", r.Method, r.Path)
		}
	}
	// Pending until disclosure: the key of a current epoch is not out yet.
	now := chain.sched.epochOf(time.Now())
	rep, err = f.client(t, Options{}).Verify(t.Context(), packetsAt(chain.at(now, 0), chain.tag(now, runA, probe(srcA, 80, 1))), VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if g := onlyGroup(t, rep); g.Verdict != VerdictPending || g.PendingUntil == nil || !g.PendingUntil.Equal(chain.sched.dueAt(now)) {
		t.Fatalf("group %+v", g)
	}
}

func TestVerifyRetriesRateLimitsAndNamesMissingRoutes(t *testing.T) {
	f := newFakeServer(t, "")
	var calls atomic.Int32
	f.handle("GET /attribution/candidates", func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			jsonHandler(http.StatusTooManyRequests, `{"code":"rate_limited","message":"slow down"}`)(w, r)
			return
		}
		jsonHandler(http.StatusOK, `{"ip":"192.0.2.7","at":"2026-09-29T10:00:00Z","retained_from":"2026-01-01T00:00:00Z","truncated":false,"candidates":[]}`)(w, r)
	})
	rep, err := f.client(t, Options{}).Verify(t.Context(), packetsAt(testT0, probe(srcA, 60, 0)), VerifyOptions{})
	if err != nil || calls.Load() != 2 || onlyGroup(t, rep).Reason != ReasonNoRun {
		t.Fatalf("after a 429: %+v, %v (%d calls)", rep, err, calls.Load())
	}
	g := newFakeServer(t, "")
	if _, err := g.client(t, Options{}).Verify(t.Context(), packetsAt(testT0, probe(srcA, 60, 0)), VerifyOptions{}); !errors.Is(err, ErrNoAttributionHistory) {
		t.Fatalf("dispatcher without the routes: %v", err)
	}
}

func TestVerifyHonoursRetryAfter(t *testing.T) {
	f := newFakeServer(t, "")
	var calls atomic.Int32
	var first, second atomic.Int64
	f.handle("GET /attribution/candidates", func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			first.Store(time.Now().UnixNano())
			w.Header().Set("Retry-After", "1")
			jsonHandler(http.StatusTooManyRequests, `{"code":"rate_limited","message":"slow down"}`)(w, r)
			return
		case 2:
			second.Store(time.Now().UnixNano())
		}
		jsonHandler(http.StatusOK, `{"ip":"192.0.2.7","at":"2026-09-29T10:00:00Z","retained_from":"2026-01-01T00:00:00Z","truncated":false,"candidates":[]}`)(w, r)
	})
	if _, err := f.client(t, Options{}).Verify(t.Context(), packetsAt(testT0, probe(srcA, 60, 0)), VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
	if gap := time.Duration(second.Load() - first.Load()); gap < 900*time.Millisecond {
		t.Fatalf("retried %v after a Retry-After of 1 s", gap)
	}
}

// A dispatcher that keeps answering 429 holds the verification until the
// context ends; the error says so and how much is left unchecked.
func TestVerifyRateLimitedUntilDeadline(t *testing.T) {
	f := newFakeServer(t, "")
	var calls atomic.Int32
	f.handle("GET /attribution/candidates", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "1")
		jsonHandler(http.StatusTooManyRequests, `{"code":"rate_limited","message":"slow down"}`)(w, r)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2500*time.Millisecond)
	defer cancel()
	pkts := append(packetsAt(testT0, probe(srcA, 60, 0), probe(srcA, 61, 0)), packetsAt(testT0, probe(srcB, 60, 0))...)
	start := time.Now()
	_, err := f.client(t, Options{}).Verify(ctx, pkts, VerifyOptions{})
	var rl *RateLimitedError
	if !errors.As(err, &rl) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error %v, want a RateLimitedError", err)
	}
	if elapsed := time.Since(start); elapsed < 2*time.Second {
		t.Fatalf("gave up after %v, before the deadline", elapsed)
	}
	if n := calls.Load(); n < 2 || n > 4 || rl.Throttled != int(n) {
		t.Fatalf("%d requests, %d throttled; want one per Retry-After", n, rl.Throttled)
	}
	if rl.UncheckedGroups != 2 || rl.UncheckedPackets != 3 || !rl.Partial ||
		!strings.Contains(err.Error(), "rate-limited the verification") || !strings.Contains(err.Error(), "at least 2 groups (3 packets) remain unchecked") {
		t.Fatalf("error %+v: %v", rl, err)
	}
}

func TestVerifyPacesRequests(t *testing.T) {
	f := newFakeServer(t, "")
	f.handle("GET /attribution/candidates", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"ip": r.URL.Query().Get("ip"), "at": r.URL.Query().Get("at"), "retained_from": "2026-01-01T00:00:00Z", "truncated": false, "candidates": []any{}})
	})
	var pkts []CapturedPacket
	for i := range 6 {
		pkts = append(pkts, CapturedPacket{Data: probe(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), 60, 0), CapturedAt: testT0})
	}
	start := time.Now()
	if _, err := f.client(t, Options{}).Verify(t.Context(), pkts, VerifyOptions{RequestRate: 20, RequestBurst: 2}); err != nil {
		t.Fatal(err)
	}
	// Two requests from the burst, four more at 20 per second.
	if elapsed := time.Since(start); elapsed < 190*time.Millisecond {
		t.Fatalf("6 requests in %v at 20 per second, burst 2", elapsed)
	}
	if _, err := f.client(t, Options{}).Verify(t.Context(), pkts, VerifyOptions{RequestRate: -1}); err != nil {
		t.Fatalf("unpaced: %v", err)
	}
	if _, err := f.client(t, Options{}).Verify(t.Context(), pkts, VerifyOptions{RequestBurst: -1}); err == nil {
		t.Fatal("negative burst accepted")
	}
}

func TestPacerTokenBucket(t *testing.T) {
	now := time.Unix(1000, 0)
	p := newPacer(10, 3, func() time.Time { return now })
	ctx := t.Context()
	for range 3 {
		if err := p.wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if p.tokens >= 1 {
		t.Fatalf("%v tokens after the burst", p.tokens)
	}
	now = now.Add(100 * time.Millisecond)
	if err := p.wait(ctx); err != nil {
		t.Fatal(err)
	}
	p.limited(5 * time.Second)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	var paced *errPaced
	if err := p.wait(cancelled); !errors.As(err, &paced) || paced.throttled != 1 {
		t.Fatalf("wait during a hold: %v", err)
	}
	now = now.Add(5 * time.Second)
	if err := p.wait(ctx); err != nil {
		t.Fatalf("after the hold: %v", err)
	}
}

func TestRetryAfterHeader(t *testing.T) {
	for _, tc := range []struct {
		status int
		header string
		want   time.Duration
	}{
		{429, "3", 3 * time.Second},
		{429, "", 0},
		{429, "-1", 0},
		{429, "soon", 0},
		{503, "86400", maxRetryAfter},
		{400, "3", 0},
	} {
		resp := &http.Response{StatusCode: tc.status, Header: http.Header{}}
		if tc.header != "" {
			resp.Header.Set("Retry-After", tc.header)
		}
		if got := retryAfter(resp); got != tc.want {
			t.Errorf("%d Retry-After %q: %v, want %v", tc.status, tc.header, got, tc.want)
		}
	}
	resp := &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": {time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)}}}
	if got := retryAfter(resp); got < 28*time.Second || got > 30*time.Second {
		t.Errorf("HTTP-date Retry-After: %v", got)
	}
}
