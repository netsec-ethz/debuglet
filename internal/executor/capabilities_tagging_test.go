// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"testing"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// A node without the eBPF counter predicts the pure-Go tagger, and IPv6 and
// SCION are never tagged. Once a run was created its actual mode is reported,
// and a change is sent on the next heartbeat rather than after the interval.
func TestCapabilityReportsTaggingMode(t *testing.T) {
	e := newFixtureExecutor(t, fixtureConfig(), nil, newFixtureMemoryStorage(t))
	hello, err := e.OnHello(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := &pb.TaggingMode{Ipv4: debuglet.UserspaceTagging(), Ipv6: tagger.ModeNone, Scion: tagger.ModeNone}
	if got := hello.GetCapabilities().GetTagging(); got.GetIpv4() != want.Ipv4 || got.GetIpv6() != want.Ipv6 || got.GetScion() != want.Scion {
		t.Fatalf("predicted tagging %v, want %v", got, want)
	}
	if e.capabilityReport(t.Context(), false) != nil {
		t.Fatal("unchanged tagging renewed a cached observation")
	}

	e.lastTagging.Store(&tagger.Mode{IPv4: tagger.ModeEBPF, IPv6: tagger.ModeNone, SCION: tagger.ModeNone})
	report := e.capabilityReport(t.Context(), false)
	if report == nil {
		t.Fatal("changed tagging waited for the report interval")
	}
	if got := report.GetTagging(); got.GetIpv4() != tagger.ModeEBPF || got.GetIpv6() != tagger.ModeNone || got.GetScion() != tagger.ModeNone {
		t.Fatalf("run tagging %v", got)
	}
	if e.capabilityReport(t.Context(), false) != nil {
		t.Fatal("reported tagging renewed a cached observation")
	}
}
