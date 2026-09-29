// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"net"
	"runtime"
	"slices"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// A node without the eBPF counter reports the pure-Go tagger, and IPv6 and
// SCION are never tagged. The report is the node's capability: creating a run
// does not change it, so an unchanged mode is not resent before the interval.
func TestCapabilityReportsTaggingMode(t *testing.T) {
	e := newFixtureExecutor(t, fixtureConfig(), nil, newFixtureMemoryStorage(t))
	hello, err := e.OnHello(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := &pb.TaggingMode{Ipv4: debuglet.UserspaceTagging(), Ipv6: tagger.ModeNone, Scion: tagger.ModeNone}
	if got := hello.GetCapabilities().GetTagging(); got.GetIpv4() != want.Ipv4 || got.GetIpv6() != want.Ipv6 || got.GetScion() != want.Scion {
		t.Fatalf("tagging %v, want %v", got, want)
	}
	if got := hello.GetCapabilities().GetTagging().GetTagSpec(); got != tesla.TagSpec {
		t.Fatalf("tag spec %q, want %q", got, tesla.TagSpec)
	}
	if report, _ := e.capabilityReport(t.Context(), false); report != nil {
		t.Fatal("unchanged tagging renewed a cached observation")
	}

	// A changed node mode (here simulated through the cached last report) is
	// sent on the next heartbeat rather than after the interval.
	e.capabilityMu.Lock()
	e.capabilityTagging = tagger.Mode{IPv4: tagger.ModeEBPF, IPv6: tagger.ModeNone, SCION: tagger.ModeNone}
	e.capabilityMu.Unlock()
	report, _ := e.capabilityReport(t.Context(), false)
	if report == nil {
		t.Fatal("changed tagging waited for the report interval")
	}
	if got := report.GetTagging(); got.GetIpv4() != want.Ipv4 || got.GetIpv6() != want.Ipv6 || got.GetScion() != want.Scion {
		t.Fatalf("tagging %v, want %v", got, want)
	}
	if report, _ := e.capabilityReport(t.Context(), false); report != nil {
		t.Fatal("reported tagging renewed a cached observation")
	}
}

// A node whose runs get the kernel tagger refuses IPv6, so under an IPv6
// public host its runs refuse TCP and UDP listeners; the vantage report does
// not advertise them. An IPv4 public host, or a node without the kernel
// tagger, keeps them.
func TestCapabilityListenersUnderIPv6PublicHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the kernel tagger is predicted on Linux only")
	}
	for _, tc := range []struct {
		host    string
		counter ratelimit.PacketCount
		want    []string
	}{
		{"2001:db8::1", ebpfCounter{}, nil},
		{"::ffff:192.0.2.1", ebpfCounter{}, []string{"tcp", "udp"}},
		{"192.0.2.1", ebpfCounter{}, []string{"tcp", "udp"}},
		{"2001:db8::1", nil, []string{"tcp", "udp"}},
	} {
		cfg := fixtureConfig()
		cfg.Network.PublicHost, cfg.Network.PublicPorts = tc.host, "40000-40010"
		e := newFixtureExecutor(t, cfg, tc.counter, newFixtureMemoryStorage(t))
		e.iface = &net.Interface{Index: 1, Name: "lo"}
		_, vantage := e.capabilityReport(t.Context(), true)
		if got := vantage.GetListeners(); !slices.Equal(got, tc.want) {
			t.Errorf("public host %s, counter %v: listeners %v, want %v", tc.host, tc.counter, got, tc.want)
		}
	}
}
