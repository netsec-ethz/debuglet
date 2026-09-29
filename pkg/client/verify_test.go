// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/tagspec"
)

var (
	testT0  = time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	testNow = testT0.Add(time.Hour)
)

const (
	runA = "6f1c2b1d-4c8e-4a6f-9d3b-2e1c4a57aaaa"
	runB = "6f1c2b1d-4c8e-4a6f-9d3b-2e1c4a57bbbb"
)

// testChain is a TESLA chain k_0 … k_L with its public schedule.
type testChain struct {
	executor string
	keys     [][]byte
	sched    EvidenceSchedule
}

func newTestChain(executor string, seed byte, length int64, delay int64) *testChain {
	keys := make([][]byte, length+1)
	tail := sha256.Sum256([]byte{seed})
	keys[length] = tail[:]
	for i := length - 1; i >= 0; i-- {
		sum := sha256.Sum256(keys[i+1])
		keys[i] = sum[:]
	}
	return &testChain{executor: executor, keys: keys, sched: EvidenceSchedule{
		ChainID: hex.EncodeToString(keys[0][:8]), K0: keys[0], T0UnixNs: testT0.UnixNano(), EpochSeconds: 10,
		DisclosureDelayEpochs: delay, ChainLength: length, TagSpec: tagspec.Version,
	}}
}

// at is a time inside epoch e, offset into it.
func (c *testChain) at(e int64, offset time.Duration) time.Time {
	return c.sched.epochStart(e).Add(offset)
}

// tag writes the tag of run under the key of epoch e into a copy of pkt.
func (c *testChain) tag(e int64, run string, pkt []byte) []byte {
	ak, err := tagspec.DeriveAK(c.keys[e], []byte(run))
	if err != nil {
		panic(err)
	}
	tag, err := tagspec.PacketTag(ak, pkt)
	if err != nil {
		panic(err)
	}
	out := bytes.Clone(pkt)
	binary.BigEndian.PutUint16(out[4:], tag)
	out[6] |= 0x40
	return out
}

type fakeRun struct {
	ip       netip.Addr
	run      string
	chain    *testChain
	from, to time.Time
}

// fakeSource is an in-memory attribution history.
type fakeSource struct {
	runs         []fakeRun
	retainedFrom time.Time
	now          time.Time
	truncated    bool
	// lost epochs are absent from the key store; bad ones are corrupted.
	lost, bad map[int64]bool
	// synthetic serves an arbitrary key at every requested epoch.
	synthetic        bool
	disclosedThrough int64 // overrides the computed value when non-zero
	pageSize         int64
	lookups, keyCall int
}

func (s *fakeSource) disclosed(c *testChain) int64 {
	if s.disclosedThrough != 0 {
		return s.disclosedThrough
	}
	d := c.sched.epochOf(s.now) - c.sched.DisclosureDelayEpochs
	return max(0, min(d, c.sched.ChainLength-1))
}

func (s *fakeSource) candidates(_ context.Context, ip netip.Addr, at time.Time) (EvidenceLookup, error) {
	s.lookups++
	out := EvidenceLookup{RetainedFrom: s.retainedFrom, Truncated: s.truncated, Candidates: []EvidenceCandidate{}}
	for _, r := range s.runs {
		i := r.chain.sched.interval()
		if r.ip == ip && !r.from.After(at.Add(i)) && !r.to.Before(at.Add(-i)) {
			out.Candidates = append(out.Candidates, EvidenceCandidate{
				ExecutorID: r.chain.executor, RunID: r.run, ActiveFrom: r.from, ActiveTo: r.to,
				Schedule: r.chain.sched, DisclosedThrough: s.disclosed(r.chain),
			})
		}
	}
	return out, nil
}

func (s *fakeSource) keys(_ context.Context, executor, chain string, from, to int64) ([]EvidenceKey, *int64, error) {
	s.keyCall++
	var c *testChain
	for _, r := range s.runs {
		if r.chain.executor == executor && r.chain.sched.ChainID == chain {
			c = r.chain
		}
	}
	if c == nil {
		return nil, nil, &HTTPError{StatusCode: 404}
	}
	page := s.pageSize
	if page == 0 {
		page = 1024
	}
	last := min(to, s.disclosed(c), from+page-1)
	out := []EvidenceKey{}
	for e := max(from, 1); e <= last; e++ {
		switch {
		case s.synthetic:
			out = append(out, EvidenceKey{Epoch: e, Key: bytes.Repeat([]byte{7}, 32)})
		case s.lost[e]:
		case s.bad[e]:
			out = append(out, EvidenceKey{Epoch: e, Key: bytes.Repeat([]byte{1}, 32)})
		default:
			out = append(out, EvidenceKey{Epoch: e, Key: c.keys[e]})
		}
	}
	if last < min(to, s.disclosed(c)) {
		next := last + 1
		return out, &next, nil
	}
	return out, nil, nil
}

func (s *fakeSource) describe() (string, string) { return "http://dispatcher.test", "1.10" }

var (
	srcA = netip.MustParseAddr("192.0.2.7")
	srcB = netip.MustParseAddr("192.0.2.8")
)

func packetsAt(at time.Time, data ...[]byte) []CapturedPacket {
	out := make([]CapturedPacket, len(data))
	for i, d := range data {
		out[i] = CapturedPacket{Data: d, CapturedAt: at.Add(time.Duration(i) * time.Millisecond)}
	}
	return out
}

func probe(src netip.Addr, n int, fill byte) []byte {
	return testUDP(src.As4(), n, fill)
}

func onlyGroup(t *testing.T, rep VerifyReport) VerifyGroup {
	t.Helper()
	if len(rep.Groups) != 1 {
		t.Fatalf("%d groups, want 1: %+v", len(rep.Groups), rep.Groups)
	}
	return rep.Groups[0]
}

func runOffline(t *testing.T, src *fakeSource, pkts []CapturedPacket, opts VerifyOptions) VerifyReport {
	t.Helper()
	if src.now.IsZero() {
		src.now = testNow
	}
	rep, err := verifyOffline(context.Background(), src, pkts, opts, src.now)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestVerifyVerdicts(t *testing.T) {
	chain := newTestChain("exec-zrh-1", 1, 1000, 2)
	legacy := newTestChain("exec-old", 2, 1000, 2)
	legacy.sched.TagSpec = 0
	short := newTestChain("exec-short", 3, 1000, 1)
	active := func(ip netip.Addr, run string, c *testChain) fakeRun {
		return fakeRun{ip: ip, run: run, chain: c, from: testT0, to: testNow.Add(time.Hour)}
	}
	const e = 100 // a disclosed epoch
	good := func(n int) [][]byte {
		var out [][]byte
		for i := range n {
			out = append(out, chain.tag(e, runA, probe(srcA, 60+i, byte(i))))
		}
		return out
	}
	// A packet whose tag both runA and runB reproduce.
	var collide []byte
	akA, _ := tagspec.DeriveAK(chain.keys[e], []byte(runA))
	akB, _ := tagspec.DeriveAK(chain.keys[e], []byte(runB))
	for i := 0; collide == nil; i++ {
		p := probe(srcA, 64, 0)
		binary.BigEndian.PutUint32(p[28:], uint32(i))
		a, _ := tagspec.PacketTag(akA, p)
		if b, _ := tagspec.PacketTag(akB, p); a == b {
			binary.BigEndian.PutUint16(p[4:], a)
			collide = p
		}
	}
	for _, tc := range []struct {
		name    string
		src     fakeSource
		pkts    []CapturedPacket
		opts    VerifyOptions
		verdict Verdict
		reason  string
		check   func(t *testing.T, g VerifyGroup)
	}{
		{name: "verified", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain)}},
			pkts: packetsAt(chain.at(e, time.Second), good(3)...), verdict: VerdictVerified,
			check: func(t *testing.T, g VerifyGroup) {
				if g.RunID != runA || g.ExecutorID != "exec-zrh-1" || g.Epoch != e || g.Method != VerifyMethodOffline ||
					g.Matched != 3 || g.Unmatched != 0 || g.Candidates != 1 {
					t.Errorf("group %+v", g)
				}
				if want := math.Pow(2.0/65536, 3); math.Abs(g.FalseMatchBound-want) > want*1e-9 {
					t.Errorf("false-match bound %g, want %g", g.FalseMatchBound, want)
				}
				if g.DisclosedAt == nil || !g.DisclosedAt.Equal(chain.at(e+2, -disclosureSkew)) {
					t.Errorf("disclosed at %v", g.DisclosedAt)
				}
			}},
		{name: "previous epoch", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain)}},
			pkts: packetsAt(chain.at(e+1, time.Second), good(2)...), verdict: VerdictVerified,
			check: func(t *testing.T, g VerifyGroup) {
				if g.Epoch != e+1 || len(g.keys) != 1 || g.keys[0] != e {
					t.Errorf("epoch %d keys %v", g.Epoch, g.keys)
				}
			}},
		{name: "two epochs back", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain)}},
			pkts: packetsAt(chain.at(e+2, time.Second), good(1)...), verdict: VerdictInvalid, reason: ReasonTagMismatch},
		{name: "next epoch", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain)}},
			pkts: packetsAt(chain.at(e-1, time.Second), good(1)...), verdict: VerdictInvalid, reason: ReasonTagMismatch},
		{name: "key public at capture", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain)}},
			// Late in e+1 the key of e is due within skew plus tolerance.
			pkts: packetsAt(chain.at(e+1, 7*time.Second), good(1)...), verdict: VerdictUnsupported, reason: ReasonKeyPublic},
		{name: "one bad packet", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain)}},
			pkts:    packetsAt(chain.at(e, time.Second), append(good(2), probe(srcA, 80, 9))...),
			verdict: VerdictInvalid, reason: ReasonTagMismatch,
			check: func(t *testing.T, g VerifyGroup) {
				if g.Matched != 2 || g.Unmatched != 1 {
					t.Errorf("matched %d unmatched %d", g.Matched, g.Unmatched)
				}
			}},
		{name: "no run", src: fakeSource{runs: []fakeRun{active(srcB, runA, chain)}},
			pkts: packetsAt(chain.at(e, time.Second), good(2)...), verdict: VerdictInvalid, reason: ReasonNoRun},
		{name: "before retained history", src: fakeSource{retainedFrom: chain.at(e+10, 0)},
			pkts: packetsAt(chain.at(e, time.Second), good(2)...), verdict: VerdictMissing, reason: ReasonNotRetained},
		{name: "mixed runs", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain), active(srcA, runB, chain)}},
			pkts:    packetsAt(chain.at(e, time.Second), chain.tag(e, runA, probe(srcA, 60, 1)), chain.tag(e, runB, probe(srcA, 61, 2))),
			verdict: VerdictInvalid, reason: ReasonMixedRuns},
		{name: "ambiguous", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain), active(srcA, runB, chain)}},
			pkts: packetsAt(chain.at(e, time.Second), collide), verdict: VerdictUnsupported, reason: ReasonAmbiguous,
			check: func(t *testing.T, g VerifyGroup) {
				if len(g.AmbiguousRuns) != 2 || g.Matched != 1 {
					t.Errorf("group %+v", g)
				}
			}},
		{name: "pending", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain)}},
			pkts:    packetsAt(testNow.Add(-5*time.Second), chain.tag(chain.sched.epochOf(testNow.Add(-5*time.Second)), runA, probe(srcA, 60, 1))),
			verdict: VerdictPending, reason: ReasonNotDisclosed,
			check: func(t *testing.T, g VerifyGroup) {
				want := chain.sched.dueAt(chain.sched.epochOf(testNow.Add(-5 * time.Second)))
				if g.PendingUntil == nil || !g.PendingUntil.Equal(want) {
					t.Errorf("pending until %v, want %v", g.PendingUntil, want)
				}
			}},
		{name: "lost key derived from a later one", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain)}, lost: map[int64]bool{e: true}},
			pkts: packetsAt(chain.at(e, time.Second), good(2)...), verdict: VerdictVerified},
		{name: "every key lost", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain)}, lost: lostFrom(e - 1)},
			pkts: packetsAt(chain.at(e, time.Second), good(2)...), verdict: VerdictMissing, reason: ReasonKeysMissing},
		{name: "bad key", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain)}, bad: map[int64]bool{e: true}, disclosedThrough: e},
			pkts: packetsAt(chain.at(e, time.Second), good(1)...), verdict: VerdictUnsupported, reason: ReasonBadKey},
		{name: "legacy tag spec", src: fakeSource{runs: []fakeRun{active(srcA, runA, legacy)}},
			pkts: packetsAt(chain.at(e, time.Second), good(1)...), verdict: VerdictUnsupported, reason: ReasonTagSpec},
		{name: "legacy candidate beside a failing one", src: fakeSource{runs: []fakeRun{active(srcA, runB, chain), active(srcA, runA, legacy)}},
			pkts: packetsAt(chain.at(e, time.Second), good(1)...), verdict: VerdictUnsupported, reason: ReasonTagSpec},
		{name: "legacy candidate beside a matching one", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain), active(srcA, runB, legacy)}},
			pkts: packetsAt(chain.at(e, time.Second), good(1)...), verdict: VerdictVerified},
		{name: "disclosure delay below two", src: fakeSource{runs: []fakeRun{active(srcA, runA, short)}},
			pkts: packetsAt(chain.at(e, time.Second), good(1)...), verdict: VerdictUnsupported, reason: ReasonDisclosureDelay},
		{name: "epoch zero", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain)}},
			pkts: packetsAt(chain.at(0, time.Second), probe(srcA, 60, 1)), verdict: VerdictUnsupported, reason: ReasonNoSigningKey},
		{name: "too many candidates", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain)}, truncated: true},
			pkts: packetsAt(chain.at(e, time.Second), good(1)...), verdict: VerdictUnsupported, reason: ReasonTooManyCandidates},
		{name: "capture time override", src: fakeSource{runs: []fakeRun{active(srcA, runA, chain)}},
			pkts: packetsAt(time.Unix(0, 0), good(2)...), opts: VerifyOptions{At: chain.at(e, time.Second)}, verdict: VerdictVerified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := onlyGroup(t, runOffline(t, &tc.src, tc.pkts, tc.opts))
			if g.Verdict != tc.verdict || g.Reason != tc.reason {
				t.Fatalf("verdict %s %q, want %s %q (%s)", g.Verdict, g.Reason, tc.verdict, tc.reason, g.Detail)
			}
			if g.Detail == "" {
				t.Error("no detail")
			}
			if tc.check != nil {
				tc.check(t, g)
			}
		})
	}
}

func lostFrom(e int64) map[int64]bool {
	out := map[int64]bool{}
	for i := e; i < 2000; i++ {
		out[i] = true
	}
	return out
}

func TestVerifyGroupsBySourceAndEpoch(t *testing.T) {
	chain := newTestChain("exec-zrh-1", 1, 1000, 2)
	src := &fakeSource{runs: []fakeRun{
		{ip: srcA, run: runA, chain: chain, from: testT0, to: testNow},
		{ip: srcB, run: runB, chain: chain, from: testT0, to: testNow},
	}}
	var pkts []CapturedPacket
	for e := int64(10); e < 60; e++ {
		pkts = append(pkts, CapturedPacket{Data: chain.tag(e, runA, probe(srcA, 60, byte(e))), CapturedAt: chain.at(e, 2*time.Second)})
		pkts = append(pkts, CapturedPacket{Data: chain.tag(e, runB, probe(srcB, 60, byte(e))), CapturedAt: chain.at(e, 3*time.Second)})
	}
	v6 := make([]byte, 40)
	v6[0] = 0x60
	pkts = append(pkts, CapturedPacket{Data: v6, CapturedAt: chain.at(10, 0)}, CapturedPacket{CapturedAt: chain.at(10, 0), LinkType: 147})
	rep := runOffline(t, src, pkts, VerifyOptions{})
	if rep.Counts.Verified != 100 || rep.Counts.Unsupported != 2 || len(rep.Groups) != 102 {
		t.Fatalf("counts %+v", rep.Counts)
	}
	if src.keyCall != 1 {
		t.Errorf("%d key requests, want one for the one chain", src.keyCall)
	}
	if src.lookups != 100 {
		t.Errorf("%d lookups, want one per group", src.lookups)
	}
	if g := rep.Groups[0]; g.RunID != runA || g.Epoch != 10 {
		t.Errorf("first group %s epoch %d; want groups by run, then time", g.RunID, g.Epoch)
	}
	last := rep.Groups[len(rep.Groups)-1]
	if last.Reason != ReasonIPv6 && last.Reason != ReasonLinkType {
		t.Errorf("last group %+v", last)
	}
}

func TestVerifyWorkCaps(t *testing.T) {
	chain := newTestChain("exec-zrh-1", 1, 1000, 2)
	t.Run("lookups", func(t *testing.T) {
		var pkts []CapturedPacket
		for i := range maxVerifyLookups + 1 {
			ip := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
			pkts = append(pkts, CapturedPacket{Data: probe(ip, 60, 0), CapturedAt: chain.at(100, 0)})
		}
		src := &fakeSource{}
		rep := runOffline(t, src, pkts, VerifyOptions{})
		if src.lookups != maxVerifyLookups || rep.Counts.Invalid != maxVerifyLookups || rep.Counts.Unsupported != 1 {
			t.Fatalf("%d lookups, counts %+v", src.lookups, rep.Counts)
		}
		if g := rep.Groups[len(rep.Groups)-1]; g.Reason != ReasonWorkCap {
			t.Fatalf("last group %+v", g)
		}
	})
	t.Run("tag computations", func(t *testing.T) {
		src := &fakeSource{}
		for i := range maxVerifyCandidates {
			src.runs = append(src.runs, fakeRun{ip: srcA, run: fmt.Sprintf("6f1c2b1d-4c8e-4a6f-9d3b-2e1c4a57%04x", i), chain: chain, from: testT0, to: testNow})
		}
		n := MaxVerifyTagComputations/(maxVerifyCandidates*2) + 1
		pkts := make([]CapturedPacket, n)
		for i := range pkts {
			pkts[i] = CapturedPacket{Data: probe(srcA, 60, 0), CapturedAt: chain.at(100, time.Second)}
		}
		g := onlyGroup(t, runOffline(t, src, pkts, VerifyOptions{}))
		if g.Verdict != VerdictUnsupported || g.Reason != ReasonWorkCap {
			t.Fatalf("group %s %s", g.Verdict, g.Reason)
		}
	})
	t.Run("hash walk", func(t *testing.T) {
		huge := newTestChain("exec-huge", 4, 8, 2)
		huge.sched.ChainLength = 0 // unknown: bounded by the walk budget
		huge.sched.T0UnixNs = testNow.Add(-time.Duration(maxVerifyHashWalk+10) * 10 * time.Second).UnixNano()
		src := &fakeSource{runs: []fakeRun{{ip: srcA, run: runA, chain: huge, from: testT0, to: testNow}}, synthetic: true,
			disclosedThrough: maxVerifyHashWalk + 5}
		pkts := packetsAt(huge.at(maxVerifyHashWalk+2, time.Second), probe(srcA, 60, 0))
		g := onlyGroup(t, runOffline(t, src, pkts, VerifyOptions{}))
		if g.Verdict != VerdictUnsupported || g.Reason != ReasonWorkCap {
			t.Fatalf("group %s %s", g.Verdict, g.Reason)
		}
	})
	t.Run("key pages", func(t *testing.T) {
		src := &fakeSource{runs: []fakeRun{{ip: srcA, run: runA, chain: chain, from: testT0, to: testNow}},
			lost: lostFrom(50), pageSize: 1}
		pkts := packetsAt(chain.at(50, time.Second), chain.tag(50, runA, probe(srcA, 60, 0)))
		g := onlyGroup(t, runOffline(t, src, pkts, VerifyOptions{}))
		if g.Verdict != VerdictUnsupported || g.Reason != ReasonWorkCap || src.keyCall != maxVerifyKeyRequests {
			t.Fatalf("group %s %s after %d key requests", g.Verdict, g.Reason, src.keyCall)
		}
	})
}

func TestVerifyEvidenceRoundTrip(t *testing.T) {
	chain := newTestChain("exec-zrh-1", 1, 1000, 2)
	src := &fakeSource{runs: []fakeRun{{ip: srcA, run: runA, chain: chain, from: testT0, to: testNow}}, retainedFrom: testT0}
	pkts := append(packetsAt(chain.at(100, time.Second),
		chain.tag(100, runA, probe(srcA, 200, 1)), chain.tag(100, runA, probe(srcA, 60, 2))),
		CapturedPacket{Data: probe(srcA, 60, 3), CapturedAt: chain.at(120, 0)},
		CapturedPacket{Data: probe(srcB, 60, 3), CapturedAt: chain.at(120, 0)},
		CapturedPacket{Data: chain.tag(359, runA, probe(srcA, 60, 4)), CapturedAt: testNow.Add(-5 * time.Second)})
	rep := runOffline(t, src, pkts, VerifyOptions{})
	if rep.Counts != (VerifyCounts{Verified: 1, Invalid: 2, Pending: 1}) {
		t.Fatalf("counts %+v", rep.Counts)
	}
	ev := rep.Evidence()
	if ev.Format != EvidenceFormat || ev.FormatVersion != 1 || ev.TagSpec != 1 || ev.Packets.Count != len(pkts) ||
		len(ev.Packets.Items[0].Data) != 64 || len(ev.Chains) != 1 {
		t.Fatalf("bundle %+v", ev)
	}
	if g := ev.Groups[0]; g.Verdict != VerdictVerified || g.Schedule == nil || len(g.Keys) != 1 || g.Keys[0].Epoch != 100 {
		t.Fatalf("verified group %+v", g)
	}
	var buf bytes.Buffer
	if err := WriteEvidence(&buf, ev); err != nil {
		t.Fatal(err)
	}
	encoded := buf.Bytes()
	read := func(t *testing.T, data []byte) Evidence {
		t.Helper()
		ev, err := ReadEvidence(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	again, err := VerifyEvidence(context.Background(), read(t, encoded))
	if err != nil {
		t.Fatalf("VerifyEvidence: %v", err)
	}
	a, _ := json.Marshal(rep.Groups)
	b, _ := json.Marshal(again.Groups)
	if !bytes.Equal(a, b) {
		t.Fatalf("recomputed groups differ:\n%s\n%s", a, b)
	}

	tamper := func(t *testing.T, change func(ev *Evidence)) error {
		t.Helper()
		ev := read(t, encoded)
		change(&ev)
		_, err := VerifyEvidence(context.Background(), ev)
		if err == nil {
			t.Fatal("tampered evidence checks out")
		}
		return err
	}
	t.Run("packet byte", func(t *testing.T) {
		if err := tamper(t, func(ev *Evidence) { ev.Packets.Items[0].Data[30] ^= 1 }); err != ErrEvidenceDigest {
			t.Fatalf("error %v, want the digest mismatch", err)
		}
	})
	t.Run("capture time", func(t *testing.T) {
		tamper(t, func(ev *Evidence) {
			ev.Packets.Items[1].CapturedAt = ev.Packets.Items[1].CapturedAt.Add(time.Nanosecond)
		})
	})
	t.Run("packet and digest", func(t *testing.T) {
		err := tamper(t, func(ev *Evidence) {
			ev.Packets.Items[0].Data[30] ^= 1
			ev.Packets.Digest = PacketDigest(ev.Packets.Items)
		})
		if _, ok := err.(*EvidenceMismatchError); !ok {
			t.Fatalf("error %v, want a verdict mismatch", err)
		}
	})
	t.Run("verdict", func(t *testing.T) {
		tamper(t, func(ev *Evidence) { ev.Groups[1].Verdict = VerdictVerified })
	})
	t.Run("key", func(t *testing.T) {
		tamper(t, func(ev *Evidence) { ev.Chains[0].Keys[0].Key[0] ^= 1 })
	})
	t.Run("lookup", func(t *testing.T) {
		tamper(t, func(ev *Evidence) { ev.Lookups[0].Candidates[0].RunID = runB })
	})
	t.Run("format version", func(t *testing.T) {
		if _, err := ReadEvidence(bytes.NewReader(bytes.Replace(encoded, []byte(`"format_version": 1`), []byte(`"format_version": 2`), 1))); err == nil {
			t.Fatal("format_version 2 accepted")
		}
	})
}
