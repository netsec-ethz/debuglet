// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"net/netip"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/config"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func TestAddressTargetsSkipConfiguredReflectorsAndOtherLiteralFamily(t *testing.T) {
	for _, tc := range []struct {
		name, addr, v4, v6 string
		want               []string
	}{
		{"name observes both families", "dispatcher.example:9090", "", "", []string{"ip4", "ip6"}},
		{"configured reflector already observes its family", "dispatcher.example:9090", "192.0.2.1:9090", "", []string{"ip6"}},
		{"both reflectors configured", "dispatcher.example:9090", "192.0.2.1:9090", "[2001:db8::1]:9090", []string{}},
		{"IPv4 literal has no IPv6 address", "192.0.2.1:9090", "", "", []string{"ip4"}},
		{"IPv6 literal has no IPv4 address", "[2001:db8::1]:9090", "", "", []string{"ip6"}},
		{"malformed address", "dispatcher.example", "", "", []string{}},
		{"zero port", "dispatcher.example:0", "", "", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &Executor{cfg: config.ExecutorConfig{Dispatcher: config.DispatcherConfig{Addr: tc.addr},
				Connectivity: config.ConnectivityConfig{IPv4Reflector: tc.v4, IPv6Reflector: tc.v6, ObserveAddresses: true}}}
			got := []string{}
			for _, target := range e.addressTargets() {
				got = append(got, target.network)
				if target.port != 9090 {
					t.Fatalf("port = %d", target.port)
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("families = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("families = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestObserveAddressesIsOptional(t *testing.T) {
	e := &Executor{cfg: config.ExecutorConfig{Dispatcher: config.DispatcherConfig{Addr: "dispatcher.example:9090"}}}
	e.observeAddresses(t.Context(), controlsession.Binding{})
	if !e.addressNext.IsZero() {
		t.Fatal("disabled observation was scheduled")
	}
	e.cfg.Connectivity.ObserveAddresses = true
	// Without a control transport nothing is sent or scheduled.
	e.observeAddresses(t.Context(), controlsession.Binding{})
	if !e.addressNext.IsZero() {
		t.Fatal("observation without a transport was scheduled")
	}
}

func TestAddressSelfCheckReportsOnlyBooleans(t *testing.T) {
	if _, ok := localIPv4Private(netip.AddrPort{}); ok {
		t.Fatal("no dispatcher address produced a result")
	}
	if _, ok := localIPv4Private(netip.MustParseAddrPort("[::1]:9090")); ok {
		t.Fatal("an IPv6 dispatcher produced an IPv4 result")
	}
	// Loopback is not RFC 1918; choosing the source sends nothing.
	if private, ok := localIPv4Private(netip.MustParseAddrPort("127.0.0.1:9")); !ok || private {
		t.Fatalf("loopback source: private=%t ok=%t", private, ok)
	}
	e := &Executor{}
	if e.addressSelfCheck() != nil {
		t.Fatal("self-check before the first round")
	}
	private := true
	e.addressCheck = &pb.AddressSelfCheck{Ipv4LocalPrivate: &private, ResolvesA: true}
	got := e.addressSelfCheck()
	if got == e.addressCheck || got.Ipv4LocalPrivate == e.addressCheck.Ipv4LocalPrivate || !got.GetIpv4LocalPrivate() || !got.ResolvesA || got.ResolvesAaaa {
		t.Fatalf("self-check copy: %+v", got)
	}
}
