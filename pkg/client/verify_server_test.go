// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// serveVerify answers POST /attribution/verify as a dispatcher whose
// executor confirms every group for run, signing receipts with key, and GET
// /attribution/receipt-keys with the key.
func serveVerify(t *testing.T, f *fakeServer, chain *testChain, run string, key ed25519.PrivateKey) {
	serveVerifyAnswer(t, f, chain, run, "verified", "", key)
}

// serveVerifyAnswer is serveVerify with the given verdict and reason.
func serveVerifyAnswer(t *testing.T, f *fakeServer, chain *testChain, run, verdict, reason string, key ed25519.PrivateKey) {
	t.Helper()
	public := key.Public().(ed25519.PublicKey)
	keyID := ReceiptKeyID(public)
	validFrom := time.Now().Add(-time.Hour).UTC()
	f.handle("GET /attribution/receipt-keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AttributionReceiptKeys{Keys: []AttributionReceiptKey{{KeyID: keyID, PublicKey: public, ValidFrom: validFrom}}})
	})
	f.handle("POST /attribution/verify", func(w http.ResponseWriter, r *http.Request) {
		var req wire.AttributionVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		packets := make([]int, len(req.Packets))
		for i := range packets {
			packets[i] = i
		}
		e := chain.sched.epochOf(req.Packets[0].CapturedAt)
		if verdict != "verified" {
			run = ""
		}
		group := wire.AttributionReceiptGroup{ChainID: chain.sched.ChainID, Epoch: e, ExecutorID: chain.executor, Method: "server",
			Packets: packets, Reason: reason, RunID: run, Source: srcA.String(), Verdict: verdict}
		payload, err := wire.CanonicalReceiptPayload(wire.AttributionReceiptPayload{
			APIVersion: "1.16", Dispatcher: "http://dispatcher.test", Groups: []wire.AttributionReceiptGroup{group},
			PacketsDigest: wire.PacketsDigest(req.Packets), QueryAt: time.Now().UTC().Format(time.RFC3339Nano),
		})
		if err != nil {
			t.Error(err)
		}
		resp := AttributionVerifyResponse{
			Groups: []AttributionVerifyGroup{{Source: group.Source, Epoch: e, ChainID: group.ChainID, ExecutorID: group.ExecutorID,
				RunID: run, Verdict: verdict, Reason: reason, Method: "server", Packets: packets,
				Budget: &wire.AttributionVerifyBudget{Limit: 16, Remaining: 15, ResetsAt: chain.sched.dueAt(e)}}},
			Receipt: AttributionReceipt{KeyID: keyID, Payload: payload, Signature: ed25519.Sign(key, payload)},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// TestVerifySendsPendingGroupsToTheServer checks a capture with one disclosed
// and one undisclosed epoch: only the pending group is sent, it is verified
// by the server with the receipt key named, and the evidence bundle keeps
// the receipt and checks again.
func TestVerifySendsPendingGroupsToTheServer(t *testing.T) {
	chain := newTestChain("exec-zrh-1", 1, 1000, 90)
	chain.sched.T0UnixNs = time.Now().Add(-time.Hour).UnixNano()
	src := &fakeSource{now: time.Now(), runs: []fakeRun{{ip: srcA, run: runA, chain: chain, from: chain.at(0, 0), to: time.Now().Add(time.Hour)}}}
	f := newFakeServer(t, "")
	serveAttribution(t, f, src)
	_, key, _ := ed25519.GenerateKey(nil)
	serveVerify(t, f, chain, runA, key)
	old, now := int64(200), chain.sched.epochOf(time.Now())
	pkts := append(packetsAt(chain.at(old, time.Second), chain.tag(old, runA, probe(srcA, 80, 1))),
		packetsAt(chain.at(now, 0), chain.tag(now, runA, probe(srcA, 80, 2)), chain.tag(now, runA, probe(srcA, 90, 3)))...)

	offline, err := f.client(t, Options{}).Verify(t.Context(), pkts, VerifyOptions{Offline: true})
	if err != nil || offline.Counts != (VerifyCounts{Verified: 1, Pending: 1}) || f.count(http.MethodPost, "/attribution/verify") != 0 {
		t.Fatalf("offline: %+v, %v; %d uploads", offline.Counts, err, f.count(http.MethodPost, "/attribution/verify"))
	}

	rep, err := f.client(t, Options{}).Verify(t.Context(), pkts, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts != (VerifyCounts{Verified: 2}) {
		t.Fatalf("counts %+v: %+v", rep.Counts, rep.Groups)
	}
	var server VerifyGroup
	for _, g := range rep.Groups {
		if g.Method == VerifyMethodServer {
			server = g
		}
	}
	keyID := ReceiptKeyID(key.Public().(ed25519.PublicKey))
	if server.RunID != runA || server.ExecutorID != chain.executor || server.Epoch != now || !slices.Equal(server.Packets, []int{1, 2}) ||
		server.ReceiptKeyID != keyID || server.Matched != 2 || server.DisclosedAt != nil {
		t.Fatalf("server group %+v", server)
	}
	if n := f.count(http.MethodPost, "/attribution/verify"); n != 1 {
		t.Fatalf("%d verification requests; want 1", n)
	}
	for _, r := range f.requests() {
		if r.Method != http.MethodPost {
			continue
		}
		var req wire.AttributionVerifyRequest
		if err := json.Unmarshal(r.Body, &req); err != nil || len(req.Packets) != 2 || !bytes.Equal(req.Packets[0].Data, pkts[1].Data[:64]) {
			t.Fatalf("the request sent %+v, %v; want only the pending group's packets", req.Packets, err)
		}
	}

	ev := rep.Evidence()
	if len(ev.Receipts) != 1 || !slices.Equal(ev.Receipts[0].Packets, []int{1, 2}) || len(ev.ReceiptKeys) != 1 || ev.ReceiptKeys[0].KeyID != keyID {
		t.Fatalf("bundle receipts %+v, keys %+v", ev.Receipts, ev.ReceiptKeys)
	}
	var buf bytes.Buffer
	if err := WriteEvidence(&buf, ev); err != nil {
		t.Fatal(err)
	}
	read, err := ReadEvidence(&buf)
	if err != nil {
		t.Fatal(err)
	}
	again, err := VerifyEvidence(t.Context(), read)
	if err != nil || again.Counts != rep.Counts {
		t.Fatalf("the bundle does not check out: %+v, %v", again.Counts, err)
	}

	clone := func() Evidence {
		var c Evidence
		data, _ := json.Marshal(read)
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	for name, change := range map[string]func(*Evidence){
		"tampered payload":   func(e *Evidence) { e.Receipts[0].Payload[10] ^= 1 },
		"tampered signature": func(e *Evidence) { e.Receipts[0].Signature[0] ^= 1 },
		"wrong key id":       func(e *Evidence) { e.Receipts[0].KeyID = "00000000000000000000000000000000" },
		"forged key":         func(e *Evidence) { e.ReceiptKeys[0].PublicKey[0] ^= 1 },
		"digest mismatch":    func(e *Evidence) { e.Receipts[0].Packets = []int{0, 1} },
		"key not yet valid":  func(e *Evidence) { e.ReceiptKeys[0].ValidFrom = time.Now().Add(time.Hour) },
	} {
		bad := clone()
		change(&bad)
		var receiptErr *EvidenceReceiptError
		if _, err := VerifyEvidence(t.Context(), bad); !errors.As(err, &receiptErr) {
			t.Errorf("%s: %v; want a receipt error", name, err)
		}
	}
	// A recorded server verdict without its receipt does not recompute.
	bad := clone()
	bad.Receipts, bad.ReceiptKeys = []EvidenceReceipt{}, nil
	var mismatch *EvidenceMismatchError
	if _, err := VerifyEvidence(t.Context(), bad); !errors.As(err, &mismatch) {
		t.Fatalf("a server verdict without its receipt: %v", err)
	}
}

// TestVerifyKeepsGroupsPendingWithoutTheServerMethod leaves the groups pending
// against a dispatcher that predates POST /attribution/verify.
func TestVerifyKeepsGroupsPendingWithoutTheServerMethod(t *testing.T) {
	chain := newTestChain("exec-zrh-1", 1, 1000, 90)
	chain.sched.T0UnixNs = time.Now().Add(-time.Hour).UnixNano()
	src := &fakeSource{now: time.Now(), runs: []fakeRun{{ip: srcA, run: runA, chain: chain, from: chain.at(0, 0), to: time.Now().Add(time.Hour)}}}
	f := newFakeServer(t, "")
	serveAttribution(t, f, src)
	now := chain.sched.epochOf(time.Now())
	rep, err := f.client(t, Options{}).Verify(t.Context(), packetsAt(chain.at(now, 0), chain.tag(now, runA, probe(srcA, 80, 1))), VerifyOptions{})
	if err != nil || onlyGroup(t, rep).Verdict != VerdictPending || f.count(http.MethodPost, "/attribution/verify") != 1 {
		t.Fatalf("%+v, %v", rep, err)
	}
	if ev := rep.Evidence(); len(ev.Receipts) != 0 || ev.ReceiptKeys != nil {
		t.Fatalf("a bundle without server answers carries receipts: %+v", ev.Receipts)
	}
}

// TestVerifyKeepsAnUnmatchedServerAnswerPending leaves a group pending when
// the executor finds no single candidate that reproduces every tag: two
// runs in one group answer so too, and the offline check after disclosure
// decides per run. The bundle keeps the receipt and checks out again.
func TestVerifyKeepsAnUnmatchedServerAnswerPending(t *testing.T) {
	chain := newTestChain("exec-zrh-1", 1, 1000, 90)
	chain.sched.T0UnixNs = time.Now().Add(-time.Hour).UnixNano()
	src := &fakeSource{now: time.Now(), runs: []fakeRun{
		{ip: srcA, run: runA, chain: chain, from: chain.at(0, 0), to: time.Now().Add(time.Hour)},
		{ip: srcA, run: runB, chain: chain, from: chain.at(0, 0), to: time.Now().Add(time.Hour)},
	}}
	f := newFakeServer(t, "")
	serveAttribution(t, f, src)
	_, key, _ := ed25519.GenerateKey(nil)
	serveVerifyAnswer(t, f, chain, "", "pending", "unmatched", key)
	now := chain.sched.epochOf(time.Now())
	pkts := packetsAt(chain.at(now, 0), chain.tag(now, runA, probe(srcA, 80, 1)), chain.tag(now, runB, probe(srcA, 90, 2)))
	rep, err := f.client(t, Options{}).Verify(t.Context(), pkts, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	g := onlyGroup(t, rep)
	if g.Verdict != VerdictPending || g.Reason != ReasonNotDisclosed || g.PendingUntil == nil || !g.PendingUntil.Equal(chain.sched.dueAt(now)) ||
		f.count(http.MethodPost, "/attribution/verify") != 1 {
		t.Fatalf("group %+v; want it pending until the disclosure", g)
	}
	ev := rep.Evidence()
	if len(ev.Receipts) != 1 {
		t.Fatalf("receipts %+v", ev.Receipts)
	}
	var buf bytes.Buffer
	if err := WriteEvidence(&buf, ev); err != nil {
		t.Fatal(err)
	}
	read, err := ReadEvidence(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := VerifyEvidence(t.Context(), read); err != nil || again.Counts != (VerifyCounts{Pending: 1}) {
		t.Fatalf("the bundle does not check out: %+v, %v", again.Counts, err)
	}
}
