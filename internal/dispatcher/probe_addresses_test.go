// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func TestAddressingPrefersControlAndHidesOnlyAddressesWhenPrivate(t *testing.T) {
	seen := time.Unix(1_790_000_000, 0)
	source := "database:Test-ASN@1"
	reflectedV4 := addressSighting{address: "198.51.100.9", via: wire.AddressViaReflection, at: seen.Add(time.Second),
		asn: wire.IPLookup[wire.ASInfo]{Value: &wire.ASInfo{Number: 64999, Name: "Other", Prefix: "198.51.100.0/24"}, Source: &source}}
	reflectedV6 := addressSighting{address: "2001:db8::7", via: wire.AddressViaReflection, at: seen.Add(-time.Minute),
		asn: wire.IPLookup[wire.ASInfo]{Value: &wire.ASInfo{Number: 64501, Name: "Six", Prefix: "2001:db8::/32"}, Source: &source}}
	e := &RegisteredExecutor{sourceIp: "192.0.2.1", sourceIPObserved: true, LastSeen: seen,
		ipMetadata: &wire.IPMetadata{Observed: wire.AddressMetadata{AddressSource: wire.SourceDispatcherObserved,
			ASN: wire.IPLookup[wire.ASInfo]{Value: &wire.ASInfo{Number: 64500, Name: "Four", Prefix: "192.0.2.0/24"}, Source: &source}}},
		probe: probeAddresses{reflected: [2]addressSighting{reflectedV4, reflectedV6}}}

	got := e.Addressing(false)
	if got.IsPublic == nil || !*got.IsPublic {
		t.Fatalf("executor not public by default: %+v", got)
	}
	// The control connection wins its family even against a newer reflection.
	if got.AddressV4 == nil || *got.AddressV4 != "192.0.2.1" || *got.ASNV4 != 64500 || *got.PrefixV4 != "192.0.2.0/24" {
		t.Fatalf("IPv4 is not the control address: %+v", got)
	}
	if v4 := got.AddressObservations.V4; v4 == nil || v4.Via != wire.AddressViaControl || v4.ObservedAt != seen.Unix() || v4.Source != wire.SourceDispatcherObserved || v4.LookupSource == nil || *v4.LookupSource != source {
		t.Fatalf("IPv4 observation: %+v", v4)
	}
	if got.AddressV6 == nil || *got.AddressV6 != "2001:db8::7" || *got.ASNV6 != 64501 || *got.PrefixV6 != "2001:db8::/32" {
		t.Fatalf("IPv6 is not the reflected address: %+v", got)
	}
	if v6 := got.AddressObservations.V6; v6 == nil || v6.Via != wire.AddressViaReflection || v6.ObservedAt != seen.Add(-time.Minute).Unix() {
		t.Fatalf("IPv6 observation: %+v", v6)
	}

	e.probe.optOut = true
	private := e.Addressing(false)
	if private.IsPublic == nil || *private.IsPublic || private.AddressV4 != nil || private.AddressV6 != nil {
		t.Fatalf("private executor published an address: %+v", private)
	}
	if private.ASNV4 == nil || private.PrefixV4 == nil || private.ASNV6 == nil || private.PrefixV6 == nil || private.AddressObservations.V4 == nil || private.AddressObservations.V6 == nil {
		t.Fatalf("private executor lost its public network facts: %+v", private)
	}
	encoded, _ := json.Marshal(private)
	if bytes.Contains(encoded, []byte("192.0.2.1")) || bytes.Contains(encoded, []byte("2001:db8::7")) {
		t.Fatalf("private addresses leaked: %s", encoded)
	}
	if operator := e.Addressing(true); operator.AddressV4 == nil || operator.AddressV6 == nil {
		t.Fatalf("operator view lost the addresses: %+v", operator)
	}

	// A hello claim is not an observation: only reflections are published.
	e.sourceIPObserved = false
	if claimed := e.Addressing(true); claimed.AddressV4 == nil || *claimed.AddressV4 != "198.51.100.9" || claimed.AddressObservations.V4.Via != wire.AddressViaReflection {
		t.Fatalf("claimed source address was published as observed: %+v", claimed)
	}
	if none := (&RegisteredExecutor{sourceIp: "192.0.2.1"}).Addressing(false); none.AddressV4 != nil || none.AddressV6 != nil || none.AddressObservations.V4 != nil || none.AddressObservations.V6 != nil || none.ASNV4 != nil {
		t.Fatalf("unobserved executor has addresses: %+v", none)
	}
}

func TestAddressingRecordsReflectionPeerOfOtherFamily(t *testing.T) {
	plan := siNewPlan()
	f := siNewHarness(t, map[string]*siPlan{"addresses": plan})
	peer := f.connect("network", "addresses")
	owner := siEntered(t, plan)
	siAvailable(t, plan, owner)
	_ = f.boundClient("addresses")
	binding, _ := peer.client.Binding()
	v6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	f.serves.Add(1)
	go func() { defer f.serves.Done(); _ = f.d.Bidi.ServeGRPCListener(f.ctx, v6) }()
	before, ok := f.d.GetExecutor("network")
	if !ok {
		t.Fatal("executor not registered")
	}
	if got := before.Addressing(false); got.AddressV6 != nil || got.AddressObservations.V6 != nil {
		t.Fatalf("IPv6 known before any reflection: %+v", got)
	}
	// The address the executor resolved for the dispatcher name is dialled;
	// the dispatcher records the call's peer, not anything in the request.
	endpoint := netip.MustParseAddrPort(v6.Addr().String()).String()
	if _, err := peer.client.ReflectAddressAs(f.ctx, binding, endpoint, "localhost", &pb.ReflectAddressRequest{ExecutorId: "network", Nonce: bytes.Repeat([]byte{9}, 32)}); err != nil {
		t.Fatal(err)
	}
	after, ok := f.d.GetExecutor("network")
	if !ok {
		t.Fatal("executor disappeared")
	}
	got := after.Addressing(false)
	if got.AddressV6 == nil || *got.AddressV6 != "::1" || got.AddressObservations.V6 == nil || got.AddressObservations.V6.Via != wire.AddressViaReflection {
		t.Fatalf("reflected IPv6 address not recorded: %+v", got)
	}
	// Loopback is never looked up, and the reason says so.
	if got.ASNV6 != nil || got.AddressObservations.V6.LookupReason != "non_global" {
		t.Fatalf("loopback address was looked up: %+v", got.AddressObservations.V6)
	}
	if got.AddressV4 == nil || *got.AddressV4 != "127.0.0.1" || got.AddressObservations.V4.Via != wire.AddressViaControl {
		t.Fatalf("control address missing: %+v", got)
	}
	// A replacement session starts without the old session's reflections.
	replacement := registryOwner(t, "network")
	defer replacement.Retire()
	if err := registryRegisterWithSetup(t.Context(), f.d, replacement, registryHello("network"), "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	replacement.MarkRegistered()
	f.d.mu.RLock()
	fresh := snapshotLocked(f.d.executors["network"], time.Now())
	f.d.mu.RUnlock()
	if got := fresh.Addressing(false); got.AddressV6 != nil {
		t.Fatalf("reflection crossed a control binding: %+v", got)
	}
}
