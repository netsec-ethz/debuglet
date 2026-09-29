// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// attributionHolder is a kernel tagger stand-in whose installed epoch and
// refresh outcome the test sets by hand.
type attributionHolder struct {
	mu        sync.Mutex
	epoch     int64
	installed bool
	last      time.Time
	err       error
}

func (h *attributionHolder) InstalledEpoch() (int64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.epoch, h.installed
}

func (h *attributionHolder) LastRefresh() (time.Time, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last, h.err
}

func (h *attributionHolder) set(epoch int64, last time.Time, err error) {
	h.mu.Lock()
	h.epoch, h.installed, h.last, h.err = epoch, true, last, err
	h.mu.Unlock()
}

// Epoch 0 is reported unavailable, and the first heartbeat after epoch 1 has
// begun reports it available although the 30 s interval has not elapsed.
func TestCapabilityReportsAttributionFromEpochOne(t *testing.T) {
	e := newFixtureExecutor(t, fixtureConfig(), nil, newFixtureMemoryStorage(t))
	const delay = 200 * time.Millisecond
	schedule, err := tesla.NewKeySchedule(tesla.Config{Seed: []byte("attribution epoch"), ChainLength: 64, EpochLength: delay, Epoch: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	e.teslaSchedule = schedule
	report, _ := e.capabilityReport(t.Context(), true)
	a := report.GetAttribution()
	if a.GetState() != "unavailable" || a.GetReason() != tesla.UnattributableEpochZero || a.GetEpoch() != 0 ||
		a.InstalledEpoch != nil || a.LastRefreshAgeMs != nil || a.DisclosureHeldMs != nil || a.GetRefreshError() != "" {
		t.Fatalf("epoch 0: %v", a)
	}
	if caps, vantage := e.capabilityReport(t.Context(), false); caps != nil || vantage != nil {
		t.Fatal("unchanged attribution bypassed the report interval")
	}
	time.Sleep(time.Until(schedule.Config().Epoch.Add(delay + delay/4)))
	report, vantage := e.capabilityReport(t.Context(), false)
	if vantage == nil {
		t.Fatal("early attribution report dropped the vantage report")
	}
	if a := report.GetAttribution(); a.GetState() != "available" || a.GetReason() != "" || a.GetEpoch() != 1 {
		t.Fatalf("epoch 1: %v", a)
	}
	if report.GetEnforcementMode() != "fallback" {
		t.Fatal("early attribution report dropped the other capabilities")
	}
}

// A failing kernel refresh is unavailable with a bounded, valid UTF-8 error,
// and a key that has held disclosure back beyond one epoch is reported with
// its age once the failure is gone.
func TestCapabilityReportsRefreshFailureAndHeldDisclosure(t *testing.T) {
	e := newFixtureExecutor(t, fixtureConfig(), nil, newFixtureMemoryStorage(t))
	const delay = time.Second
	schedule, err := tesla.NewKeySchedule(tesla.Config{Seed: []byte("attribution refresh"), ChainLength: 1 << 16, EpochLength: delay, Epoch: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	e.teslaSchedule = schedule
	holder := &attributionHolder{}
	schedule.RegisterInstalled(holder)
	defer schedule.UnregisterInstalled(holder)
	now := time.Now()
	current := schedule.EpochOf(now)
	long := errors.New("map update: " + strings.Repeat("é", 200))
	holder.set(current-5, now.Add(-5*delay), long)

	report, _ := e.capabilityReport(t.Context(), true)
	a := report.GetAttribution()
	if a.GetState() != "unavailable" || a.GetReason() != tesla.UnattributableRefreshFailing || a.GetInstalledEpoch() != current-5 {
		t.Fatalf("refresh failure: %v", a)
	}
	if text := a.GetRefreshError(); len(text) > maxRefreshError || !utf8.ValidString(text) || !strings.HasPrefix(text, "map update: ") {
		t.Fatalf("refresh error %q not bounded", text)
	}
	if age := a.GetLastRefreshAgeMs(); age < (5 * delay).Milliseconds() {
		t.Fatalf("last refresh age %d ms", age)
	}
	if held := a.GetDisclosureHeldMs(); held < (4 * delay).Milliseconds() {
		t.Fatalf("held %d ms", held)
	}

	holder.set(current-5, now.Add(-5*delay), nil)
	report, _ = e.capabilityReport(t.Context(), false)
	a = report.GetAttribution()
	if a.GetReason() != tesla.UnattributableDisclosureHeld || a.GetRefreshError() != "" || a.DisclosureHeldMs == nil {
		t.Fatalf("held disclosure: %v", a)
	}
}
