// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
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
