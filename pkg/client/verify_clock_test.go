// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"crypto/ed25519"
	"encoding/json"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	"testing"
	"time"
)

func TestCaptureClockTrustForDelayedEvidence(t *testing.T) {
	chain := newTestChain("exec", 1, 1000, 2)
	at := chain.at(100, 3*time.Second)
	source := &fakeSource{runs: []fakeRun{{ip: srcA, run: runA, chain: chain, from: testT0, to: testNow}}}
	packets := packetsAt(at, chain.tag(100, runA, probe(srcA, 64, 1)))
	report := runOffline(t, source, packets, VerifyOptions{})
	ev := report.Evidence()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := EvidenceReceiptKey{KeyID: ReceiptKeyID(pub), PublicKey: pub, ValidFrom: testT0}
	ev.ReceiptKeys = []EvidenceReceiptKey{key}
	for i := range ev.Lookups {
		payload, _ := wire.AttributionHistoryBytes(wire.AttributionHistoryPayload{Format: wire.AttributionHistoryFormat, Dispatcher: ev.Dispatcher.URL, SignedAt: testNow, Lookup: historyLookup(ev.Lookups[i])})
		ev.Lookups[i].Statement = &wire.AttributionReceipt{KeyID: key.KeyID, Payload: payload, Signature: ed25519.Sign(priv, payload)}
	}
	clock := CaptureClockTrust{Source: "controlled receiver and executor reference observation", ObservedAt: at.Add(-time.Minute), ValidUntil: at.Add(time.Minute), MaxErrorNS: int64(time.Second), PacketsDigest: ev.Packets.Digest, Schedules: []CaptureClockSchedule{{ExecutorID: "exec", ChainID: chain.sched.ChainID, OriginUnixNS: chain.sched.T0UnixNs}}}
	trust := EvidenceTrust{Dispatcher: ev.Dispatcher.URL, Keys: ev.ReceiptKeys, CaptureClock: &clock}
	// A later export/recheck does not require the receiver observation to still
	// be fresh today: its measured interval covered the original arrival.
	ev.CreatedAt = testNow.Add(48 * time.Hour)
	got, err := VerifyEvidenceWithTrust(t.Context(), ev, trust)
	if err != nil || got.Counts.Verified != 1 || !got.CaptureTimeTrusted {
		t.Fatalf("delayed evidence: %+v, %v", got, err)
	}
	plain := trust
	plain.CaptureClock = nil
	got, err = VerifyEvidenceWithTrust(t.Context(), ev, plain)
	if err != nil || got.CaptureTimeTrusted {
		t.Fatalf("clock trust invented without a record: %+v, %v", got, err)
	}
	for name, change := range map[string]func(*CaptureClockTrust){
		"no measurement":                  func(c *CaptureClockTrust) { c.MaxErrorNS = 0 },
		"no source":                       func(c *CaptureClockTrust) { c.Source = "" },
		"expired at arrival":              func(c *CaptureClockTrust) { c.ValidUntil = at },
		"observed after arrival":          func(c *CaptureClockTrust) { c.ObservedAt = at.Add(time.Second) },
		"too large for applied tolerance": func(c *CaptureClockTrust) { c.MaxErrorNS = int64(2 * time.Second) },
		"other packets or timestamps":     func(c *CaptureClockTrust) { c.PacketsDigest = "sha256:other" },
		"other schedule origin": func(c *CaptureClockTrust) {
			c.Schedules = []CaptureClockSchedule{{ExecutorID: "exec", ChainID: chain.sched.ChainID, OriginUnixNS: chain.sched.T0UnixNs + 1}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := clock
			change(&copy)
			policy := trust
			policy.CaptureClock = &copy
			if _, err := VerifyEvidenceWithTrust(t.Context(), ev, policy); err == nil {
				t.Fatal("unbound clock record accepted")
			}
		})
	}
	override := ev
	override.At = &at
	if _, err := VerifyEvidenceWithTrust(t.Context(), override, trust); err == nil {
		t.Fatal("timestamp override accepted as a receiver observation")
	}
	data, _ := json.Marshal(clock)
	if _, err := ReadCaptureClockTrust(data); err != nil {
		t.Fatal(err)
	}
	// A fresh verification rounds the measured relative-clock bound upward.
	clock.MaxErrorNS = int64(2*time.Second) + 1
	got = runOffline(t, source, packets, VerifyOptions{CaptureClock: &clock})
	if !got.CaptureTimeTrusted || got.ClockToleranceMS != 2001 || got.Counts.Verified != 1 {
		t.Fatalf("measured bound not applied: %+v", got)
	}
	// With a bound reaching key disclosure, authentic tags cannot regain
	// authority merely by calling the receiver synchronized.
	clock.MaxErrorNS = int64(20 * time.Second)
	got = runOffline(t, source, packets, VerifyOptions{CaptureClock: &clock})
	if got.Counts.Verified != 0 || got.Groups[0].Reason != ReasonKeyPublic {
		t.Fatalf("public key regained authority: %+v", got)
	}
}
