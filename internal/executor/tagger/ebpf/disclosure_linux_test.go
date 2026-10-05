// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// disclosureEpoch is the epoch length of the disclosure fixtures, and
// disclosureDelay their disclosure delay d in epochs, the shortest allowed.
const (
	disclosureEpoch = time.Second
	disclosureDelay = tesla.MinDisclosureDelay
)

// disclosureInstallBound is how long after a boundary the slot may still hold
// the previous epoch's key. The refresh timer fires at the boundary and the
// update is one map write; the rest is scheduling latency on a loaded host.
const disclosureInstallBound = 300 * time.Millisecond

// disclosureSchedule starts a chain whose epoch 1 ends lead from now.
func disclosureSchedule(t *testing.T, length int64, lead time.Duration) *tesla.KeySchedule {
	t.Helper()
	ks, err := tesla.NewKeySchedule(tesla.Config{
		Seed:            make([]byte, 32),
		ChainLength:     length,
		EpochLength:     disclosureEpoch,
		DisclosureDelay: disclosureDelay,
		Epoch:           time.Now().Add(lead - 2*disclosureEpoch),
	})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}
	return ks
}

func disclosureTagger(t *testing.T, ks *tesla.KeySchedule, measurementID string) *BPFTagger {
	t.Helper()
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("InterfaceByName: %v", err)
	}
	bt, err := NewBPFTagger(zap.NewNop(), iface, ks, []byte(measurementID))
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping test: insufficient privileges for eBPF: %v", err)
		}
		t.Fatalf("NewBPFTagger: %v", err)
	}
	t.Cleanup(func() { _ = bt.Close() })
	return bt
}

// disclosureSlotEpoch returns the epoch whose key bt's map slot holds, and
// false for an empty slot.
func disclosureSlotEpoch(t *testing.T, bt *BPFTagger) (int64, bool) {
	t.Helper()
	key := bt.MapKey()
	var entry akEntry
	if err := bt.objs.AkMap.Lookup(&key, &entry); errors.Is(err, ebpf.ErrKeyNotExist) {
		return 0, false
	} else if err != nil {
		t.Fatalf("lookup slot: %v", err)
	}
	cfg := bt.schedule.Config()
	for e := int64(1); e < cfg.ChainLength; e++ {
		if epochEntry(t, bt.schedule, bt.measureID, e) == entry {
			return e, true
		}
	}
	t.Fatalf("slot holds an entry of no epoch: %+v", entry)
	return 0, false
}

// disclosureWatch samples the heartbeat's disclosure and every tagger's slot
// until the given instant. The disclosure is read first: keys only move
// forward, so a slot read afterwards that holds the disclosed epoch's key held
// it when the disclosure was computed. It returns, per sample, the time, the
// disclosed epoch and each slot's epoch (-1 for empty).
func disclosureWatch(t *testing.T, ks *tesla.KeySchedule, until time.Time, taggers ...*BPFTagger) []disclosureSample {
	t.Helper()
	var samples []disclosureSample
	for now := time.Now(); now.Before(until); now = time.Now() {
		idx, _, _ := ks.DisclosedKey(now)
		s := disclosureSample{at: now, disclosed: idx}
		for i, bt := range taggers {
			epoch, ok := disclosureSlotEpoch(t, bt)
			if !ok {
				epoch = -1
			}
			if ok && epoch == idx {
				t.Fatalf("at %v: disclosed epoch %d while tagger %d still holds its key", now.Sub(ks.Config().Epoch), idx, i)
			}
			s.slots = append(s.slots, epoch)
		}
		samples = append(samples, s)
		time.Sleep(2 * time.Millisecond)
	}
	return samples
}

type disclosureSample struct {
	at        time.Time
	disclosed int64
	slots     []int64
}

// disclosureCheckBoundary requires that within disclosureInstallBound after
// the start of epoch e every slot holds k_e (or is empty from L on) and
// k_{e-d} is disclosed, k_{L-1} at most.
func disclosureCheckBoundary(t *testing.T, ks *tesla.KeySchedule, samples []disclosureSample, e int64) {
	t.Helper()
	cfg := ks.Config()
	boundary := cfg.Epoch.Add(time.Duration(e) * cfg.EpochLength)
	want := e
	if e >= cfg.ChainLength {
		want = -1
	}
	disclosed := min(e-disclosureDelay, cfg.ChainLength-1)
	for _, s := range samples {
		if s.at.Before(boundary) {
			continue
		}
		moved := s.disclosed == disclosed
		for _, slot := range s.slots {
			moved = moved && slot == want
		}
		if moved {
			return
		}
		if s.at.Sub(boundary) > disclosureInstallBound {
			t.Fatalf("%v after the start of epoch %d: slots %v, disclosed %d; want slots at %d and k_%d disclosed",
				s.at.Sub(boundary), e, s.slots, s.disclosed, want, disclosed)
		}
	}
	t.Fatalf("no sample after the start of epoch %d", e)
}

// TestDisclosureFollowsKernelSlot runs a real tagger across two boundaries
// and the end of the chain: the disclosed epoch is never the one whose key is
// in the map and trails the current one by d, the slot holds the new key
// shortly after each boundary, after Expiry the slot is empty, and k_{L-1} is
// disclosed from the start of epoch L-1+d.
func TestDisclosureFollowsKernelSlot(t *testing.T) {
	const length = 4
	ks := disclosureSchedule(t, length, 400*time.Millisecond)
	before := ks.EpochOf(time.Now())
	bt := disclosureTagger(t, ks, "disclosure-single")
	// A slow construction may pass the first boundary: the slot then holds the
	// key of the epoch the tagger was built or refreshed in.
	if epoch, ok := disclosureSlotEpoch(t, bt); !ok || epoch < before || epoch > ks.EpochOf(time.Now()) {
		t.Fatalf("initial slot epoch=%d,%v, want %d to %d", epoch, ok, before, ks.EpochOf(time.Now()))
	}
	lastDue := ks.Config().Epoch.Add((length - 1 + disclosureDelay) * disclosureEpoch)
	samples := disclosureWatch(t, ks, lastDue.Add(disclosureEpoch/2), bt)
	for e := int64(2); e <= length-1+disclosureDelay; e++ {
		disclosureCheckBoundary(t, ks, samples, e)
	}
	if epoch, ok := bt.InstalledEpoch(); ok {
		t.Fatalf("hold on epoch %d after Expiry", epoch)
	}
	if idx, _, _ := ks.DisclosedKey(time.Now()); idx != length-1 {
		t.Fatalf("after Expiry disclosed %d, want %d", idx, length-1)
	}
}

// TestDisclosureWaitsForEveryTagger runs two taggers, two runs, on one
// schedule: disclosure never names a key either slot holds, moves only once
// both slots moved, and a closed tagger stops capping it while the other one
// still does.
func TestDisclosureWaitsForEveryTagger(t *testing.T) {
	ks := disclosureSchedule(t, 64, 400*time.Millisecond)
	first := disclosureTagger(t, ks, "disclosure-first")
	second := disclosureTagger(t, ks, "disclosure-second")
	start := ks.Config().Epoch
	samples := disclosureWatch(t, ks, start.Add(3*disclosureEpoch+disclosureEpoch/2), first, second)
	for e := int64(2); e <= 3; e++ {
		disclosureCheckBoundary(t, ks, samples, e)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, ok := first.InstalledEpoch(); ok {
		t.Fatal("closed tagger still holds a key")
	}
	now := time.Now()
	held, ok := second.InstalledEpoch()
	if !ok {
		t.Fatal("running tagger holds no key")
	}
	if idx, _, _ := ks.DisclosedKey(now); idx >= held {
		t.Fatalf("disclosed %d while the running tagger holds epoch %d", idx, held)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	now = time.Now()
	if idx, _, _ := ks.DisclosedKey(now); idx != ks.EpochOf(now)-disclosureDelay {
		t.Fatalf("disclosed %d with no tagger running, want %d", idx, ks.EpochOf(now)-disclosureDelay)
	}
}
