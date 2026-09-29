// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"slices"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"github.com/scionproto/scion/pkg/addr"
)

// The dispatcher's canonical form is the one the SCION libraries print, so an
// executor's ia.String() survives validation unchanged.
func TestCanonicalISDASMatchesSCION(t *testing.T) {
	for _, text := range []string{"1-ff00:0:110", "1-FF00:0:0110", "64-559", "65535-4294967295", "1-1:0:0", "2-0:1:0", "71-2:0:4a", "1-0:0:1"} {
		want, err := addr.ParseIA(text)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := wire.CanonicalISDAS(text); !ok || got != want.String() {
			t.Errorf("%q: %q %v, want %q", text, got, ok, want)
		}
	}
	for _, text := range []string{"", "1", "0-1", "1-0", "1-0:0:0", "65536-1", "1-4294967296", "1-ff00:0", "1-ff00:0:110:1", "1-10000:0:0", "+1-1", "1--1", "1-0x1:0:0", "1-1_0", " 1-1", "1-ff00::110"} {
		if got, ok := wire.CanonicalISDAS(text); ok {
			t.Errorf("%q accepted as %q", text, got)
		}
	}
}

func TestVantageReportValidation(t *testing.T) {
	good := vantageFromReport(&pb.VantagePointReport{SchemaVersion: 1, ScionIsdAs: "1-ff00:0:0110", Listeners: []string{"tcp", "scion"}})
	if good == nil || good.isdAS != "1-ff00:0:110" || !slices.Equal(good.listeners, []string{"tcp", "scion"}) {
		t.Fatalf("valid report: %+v", good)
	}
	if empty := vantageFromReport(&pb.VantagePointReport{SchemaVersion: 1}); empty == nil || empty.isdAS != "" || empty.listeners == nil {
		t.Fatalf("empty report must be known-empty listeners and unknown ISD-AS: %+v", empty)
	}
	for _, report := range []*pb.VantagePointReport{
		nil,
		{SchemaVersion: 2, ScionIsdAs: "1-ff00:0:110"},
		{SchemaVersion: 1, ScionIsdAs: "1-0"},
		{SchemaVersion: 1, ScionIsdAs: "not an ia"},
		{SchemaVersion: 1, Listeners: []string{"tcp", "tcp"}},
		{SchemaVersion: 1, Listeners: []string{"icmp"}},
		{SchemaVersion: 1, Listeners: []string{"tcp", "udp", "scion", "tls"}},
	} {
		if vantageFromReport(report) != nil {
			t.Errorf("malformed report accepted: %v", report)
		}
	}
}

// Live observations expire with the capability lifetime; the admission
// snapshot keeps the last one and marks it stale. Operator metadata is copied
// at registration and labelled operator.
func TestVantageObservationsExpireAndLabel(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	now := time.Unix(1700000000, 0)
	d.now = func() time.Time { return now }
	if err := d.ConfigureExecutorDisplay(map[string]config.ExecutorDisplay{"vantage": {DisplayName: "Lab", Country: "CH", Network: "AS559"}}); err != nil {
		t.Fatal(err)
	}
	owner := registryOwner(t, "vantage")
	hello := registryHello("vantage")
	hello.VantagePoint = &pb.VantagePointReport{SchemaVersion: 1, ScionIsdAs: "1-ff00:0:110", Listeners: []string{"udp"}}
	if err := registryRegisterWithSetup(t.Context(), d, owner, hello, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	owner.MarkRegistered()
	if err := d.ConfigureExecutorDisplay(nil); err == nil {
		t.Fatal("display metadata changed after registration")
	}
	get := func() *RegisteredExecutor {
		t.Helper()
		snapshot, ok := d.GetExecutor("vantage")
		if !ok {
			t.Fatal("registration missing")
		}
		return snapshot
	}
	ia, listeners := get().Vantage()
	if ia.Value == nil || *ia.Value != "1-ff00:0:110" || *ia.Source != wire.SourceExecutorReported || *ia.ObservedAt != now.Unix() {
		t.Fatalf("isd-as: %+v", ia)
	}
	if !slices.Equal(listeners.Value, []string{"udp"}) || *listeners.Source != wire.SourceExecutorReported {
		t.Fatalf("listeners: %+v", listeners)
	}
	display := get().Display()
	if *display.DisplayName.Value != "Lab" || *display.Country.Source != wire.SourceOperator || *display.Network.Value != "AS559" || display.City != (wire.LabelledString{}) {
		t.Fatalf("display: %+v", display)
	}

	now = now.Add(capabilityLifetime)
	if ia, listeners := get().Vantage(); ia != (wire.ObservedString{}) || listeners.Value != nil {
		t.Fatalf("expired observation stayed live: %+v %+v", ia, listeners)
	}
	d.mu.Lock()
	v := admissionVantagePoint(d.executors["vantage"], d.now())
	d.mu.Unlock()
	if v.SCIONISDAS.Value == nil || !*v.SCIONISDAS.Stale || *v.Display.DisplayName.Value != "Lab" {
		t.Fatalf("admission snapshot: %+v", v)
	}

	mutation := effectTestMutation(t, d, "vantage")
	_, err := d.OnHeartbeat(t.Context(), mutation, &pb.HeartbeatRequest{ExecutorId: "vantage",
		VantagePoint: &pb.VantagePointReport{SchemaVersion: 1, Listeners: []string{}}})
	mutation.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if ia, listeners := get().Vantage(); ia != (wire.ObservedString{}) || listeners.Value == nil || len(listeners.Value) != 0 {
		t.Fatalf("heartbeat report: %+v %+v", ia, listeners)
	}
	unconfigured := (&RegisteredExecutor{}).Display()
	if unconfigured != (wire.ExecutorDisplay{}) {
		t.Fatalf("invented display: %+v", unconfigured)
	}
}

func TestAdmissionState(t *testing.T) {
	for _, tc := range []struct {
		ready, paused bool
		want          string
	}{
		{false, false, wire.AdmissionOffline}, {false, true, wire.AdmissionOffline},
		{true, true, wire.AdmissionMaintenance}, {true, false, wire.AdmissionReady},
	} {
		if got := (&RegisteredExecutor{Ready: tc.ready}).Admission(tc.paused); got != tc.want {
			t.Errorf("ready=%t paused=%t: %q, want %q", tc.ready, tc.paused, got, tc.want)
		}
	}
}
