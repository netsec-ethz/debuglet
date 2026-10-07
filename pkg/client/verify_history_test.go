// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/testtls"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestEvidenceAuthenticatesDatedHistory(t *testing.T) {
	chain := newTestChain("exec", 1, 1000, 2)
	ca, err := testtls.NewAuthority(t.TempDir(), "history")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ca.Issue("executor", testtls.Options{Client: true, NotBefore: testT0.Add(-time.Hour), NotAfter: testNow.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	chain.sched.OperatorProof, err = wire.SignAttributionSchedule("exec", historySchedule(chain.sched), identity.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeSource{runs: []fakeRun{{ip: srcA, run: runA, chain: chain, from: testT0, to: testNow}}}
	report := runOffline(t, source, packetsAt(chain.at(100, 0), chain.tag(100, runA, probe(srcA, 64, 1))), VerifyOptions{})
	ev := report.Evidence()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := EvidenceReceiptKey{KeyID: ReceiptKeyID(public), PublicKey: public, ValidFrom: ev.CreatedAt.Add(-time.Hour)}
	ev.ReceiptKeys = []EvidenceReceiptKey{key}
	for i := range ev.Lookups {
		p, err := wire.AttributionHistoryBytes(wire.AttributionHistoryPayload{Format: wire.AttributionHistoryFormat, Dispatcher: ev.Dispatcher.URL, SignedAt: ev.CreatedAt, Lookup: historyLookup(ev.Lookups[i])})
		if err != nil {
			t.Fatal(err)
		}
		ev.Lookups[i].Statement = &wire.AttributionReceipt{KeyID: key.KeyID, Payload: p, Signature: ed25519.Sign(private, p)}
	}
	trust := EvidenceTrust{Dispatcher: ev.Dispatcher.URL, Keys: ev.ReceiptKeys, ExecutorCertificates: map[string][]string{"exec": {wire.AttributionCertificateID(identity.Certificate.Certificate[0])}}}
	if got, err := VerifyEvidenceWithTrust(t.Context(), ev, trust); err != nil || !got.HistoryAuthenticated || !got.SchedulesAuthenticated || got.Counts.Verified != 1 {
		t.Fatalf("verified evidence: %+v, %v", got, err)
	}
	// A bundle from an older enrolled certificate remains verifiable after
	// rotation when the receiver kept both independent pins.
	rotated, err := ca.Issue("executor-renewed", testtls.Options{Client: true})
	if err != nil {
		t.Fatal(err)
	}
	oldPin := trust.ExecutorCertificates["exec"][0]
	newPin := wire.AttributionCertificateID(rotated.Certificate.Certificate[0])
	trust.ExecutorCertificates["exec"] = []string{newPin, oldPin}
	if _, err := VerifyEvidenceWithTrust(t.Context(), ev, trust); err != nil {
		t.Fatal(err)
	}
	trust.ExecutorCertificates["exec"] = []string{newPin}
	if _, err := VerifyEvidenceWithTrust(t.Context(), ev, trust); err == nil {
		t.Fatal("replacement certificate accepted for older signed schedule")
	}
	trust.ExecutorCertificates["exec"] = []string{newPin, oldPin}
	if got, err := VerifyEvidence(t.Context(), ev); err != nil || got.HistoryAuthenticated {
		t.Fatalf("embedded keys must not establish trust: %+v, %v", got, err)
	}
	for name, change := range map[string]func(*Evidence){
		"missing operator proof":   func(e *Evidence) { e.Lookups[0].Candidates[0].Schedule.OperatorProof = nil },
		"schedule delay":           func(e *Evidence) { e.Lookups[0].Candidates[0].Schedule.DisclosureDelayEpochs++ },
		"schedule anchor":          func(e *Evidence) { e.Lookups[0].Candidates[0].Schedule.K0[0] ^= 1 },
		"run identity":             func(e *Evidence) { e.Lookups[0].Candidates[0].RunID = runB },
		"active interval":          func(e *Evidence) { e.Lookups[0].Candidates[0].ActiveTo = e.CreatedAt.Add(time.Hour) },
		"retention":                func(e *Evidence) { e.Lookups[0].RetainedFrom = e.CreatedAt },
		"missing lookup signature": func(e *Evidence) { e.Lookups[0].Statement = nil },
		"signature":                func(e *Evidence) { e.Lookups[0].Statement.Signature[0] ^= 1 },
		"issuer":                   func(e *Evidence) { e.Dispatcher.URL = "https://another.example" },
		"embedded key replacement": func(e *Evidence) {
			pub, priv, _ := ed25519.GenerateKey(nil)
			e.ReceiptKeys[0].PublicKey, e.ReceiptKeys[0].KeyID = pub, ReceiptKeyID(pub)
			e.Lookups[0].Statement.KeyID = ReceiptKeyID(pub)
			e.Lookups[0].Statement.Signature = ed25519.Sign(priv, e.Lookups[0].Statement.Payload)
		},
	} {
		t.Run(name, func(t *testing.T) {
			data, _ := json.Marshal(ev)
			var changed Evidence
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			change(&changed)
			if _, err := VerifyEvidenceWithTrust(t.Context(), changed, trust); err == nil {
				t.Fatal("altered history accepted")
			}
		})
	}
}

func TestSignedHistoryRejectsReplayForAnotherQuery(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := EvidenceReceiptKey{KeyID: ReceiptKeyID(public), PublicKey: public, ValidFrom: testT0.Add(-time.Hour)}
	for _, kind := range []string{"address", "time"} {
		t.Run(kind, func(t *testing.T) {
			f := newFakeServer(t, "")
			c := f.client(t, Options{})
			at := testT0.Add(time.Minute)
			response := wire.AttributionCandidates{IP: srcA.String(), At: at, RetainedFrom: testT0, Candidates: []wire.AttributionCandidate{}}
			if kind == "address" {
				response.IP = "192.0.2.99"
			} else {
				response.At = at.Add(time.Second)
			}
			payload, _ := wire.AttributionHistoryBytes(wire.AttributionHistoryPayload{Format: wire.AttributionHistoryFormat, Dispatcher: c.origin, SignedAt: at, Lookup: response})
			response.Statement = &wire.AttributionReceipt{KeyID: key.KeyID, Payload: payload, Signature: ed25519.Sign(private, payload)}
			body, _ := json.Marshal(response)
			f.handle("GET /attribution/candidates", jsonHandler(http.StatusOK, string(body)))
			source := &clientSource{c: c, pace: newPacer(0, 1, time.Now), receiptKeys: []EvidenceReceiptKey{key}}
			if _, err := source.candidates(t.Context(), netip.MustParseAddr(srcA.String()), at); err == nil {
				t.Fatal("replayed signed lookup accepted")
			}
		})
	}
}
