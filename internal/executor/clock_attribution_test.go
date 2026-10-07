// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// aheadClock puts the wall clock a fixed offset ahead of the monotonic clock,
// as after a suspend the monotonic clock did not count.
type aheadClock time.Duration

func (c aheadClock) Elapsed(origin, t time.Time) (time.Duration, time.Duration) {
	monotonic := t.Sub(origin)
	return monotonic, monotonic + time.Duration(c)
}

func clockSchedule(t *testing.T, unready bool, clock tesla.Clock) *tesla.KeySchedule {
	t.Helper()
	ks, err := tesla.NewKeySchedule(tesla.Config{Seed: []byte("clock fixture"), ChainLength: 1 << 10, EpochLength: time.Second,
		Epoch: time.Now().Add(-time.Minute), ClockUnready: unready, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// A tagging node refuses new runs while its clock makes attribution
// unavailable, naming the reason, and admits them on a trusted clock.
func TestUploadRefusedWhileClockUntrusted(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the kernel tagger is predicted on Linux only")
	}
	for _, tc := range []struct {
		name   string
		ks     *tesla.KeySchedule
		reason string
	}{
		{"trusted", clockSchedule(t, false, nil), ""},
		{"unready", clockSchedule(t, true, nil), tesla.UnattributableClockUnready},
		{"drift", clockSchedule(t, false, aheadClock(30*time.Second)), tesla.UnattributableClockDrift},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storage := &uploadBindingScheduler{abortTestScheduler: &abortTestScheduler{}}
			e, _ := newExecutorRPCFixture(t, newOperationPeer(), storage)
			e.iface, e.packetCount = &net.Interface{Index: 1, Name: "lo"}, ebpfCounter{}
			e.teslaSchedule = tc.ks
			ctx, cancel := context.WithTimeout(context.Background(), operationTestBound)
			defer cancel()
			_, err := e.OnUpload(ctx, operationBinding(), boundsUploadRequest())
			if tc.reason == "" {
				if err != nil || len(storage.inserted) != 1 {
					t.Fatalf("upload on a trusted clock: %v, %d inserted", err, len(storage.inserted))
				}
				return
			}
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), tc.reason) {
				t.Fatalf("upload: %v; want FailedPrecondition naming %s", err, tc.reason)
			}
			if len(storage.inserted) != 0 {
				t.Fatalf("refused upload reached persistence %d times", len(storage.inserted))
			}
		})
	}
}

// Only the clock reasons refuse, and only on a node that tags packets.
func TestClockRefusalNeedsTagging(t *testing.T) {
	userspace := tagger.Untagged
	userspace.IPv4 = tagger.ModeUserspace
	for _, tc := range []struct {
		reason string
		mode   tagger.Mode
		want   string
	}{
		{tesla.UnattributableClockUnready, userspace, tesla.UnattributableClockUnready},
		{tesla.UnattributableClockDrift, userspace, tesla.UnattributableClockDrift},
		{tesla.UnattributableClockUnready, tagger.Untagged, ""},
		{tesla.UnattributableClockDrift, tagger.Untagged, ""},
		{tesla.UnattributableEpochZero, userspace, ""},
		{tesla.UnattributableRefreshFailing, userspace, ""},
		{"", userspace, ""},
	} {
		if got := clockRefusal(tc.reason, func() tagger.Mode { return tc.mode }); got != tc.want {
			t.Errorf("reason %q mode %+v: refusal %q, want %q", tc.reason, tc.mode, got, tc.want)
		}
	}
}

// The capability report carries the clock reasons as unavailable attribution.
func TestCapabilityReportsClockReasons(t *testing.T) {
	for _, tc := range []struct {
		ks     *tesla.KeySchedule
		reason string
	}{
		{clockSchedule(t, true, nil), tesla.UnattributableClockUnready},
		{clockSchedule(t, false, aheadClock(-time.Hour)), tesla.UnattributableClockDrift},
	} {
		e := newFixtureExecutor(t, fixtureConfig(), nil, newFixtureMemoryStorage(t))
		e.teslaSchedule = tc.ks
		report, _ := e.capabilityReport(t.Context(), true)
		if a := report.GetAttribution(); a.GetState() != "unavailable" || a.GetReason() != tc.reason || a.GetEpoch() < 59 {
			t.Errorf("attribution %v, want unavailable with %s", a, tc.reason)
		}
	}
}
