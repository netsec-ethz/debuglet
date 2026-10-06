// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"net/netip"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// addressSighting is one address the dispatcher saw on an authenticated
// connection of the executor, with the ASN lookup made when it was seen. It is
// replaced, never mutated, so snapshots may share its pointers.
type addressSighting struct {
	address string // Canonical; empty when nothing was seen.
	via     string
	at      time.Time
	asn     wire.IPLookup[wire.ASInfo]
}

// probeAddresses is the RIPE Atlas-style addressing state of one control
// session. The control connection's own address is not copied here: it is
// sourceIp, confirmed by every heartbeat of the session that carries it.
type probeAddresses struct {
	// optOut is the executor's address_opt_out, read at registration.
	optOut bool
	// hostTags are the executor's canonical host tags, read at registration.
	hostTags []string
	// registeredAt is when this control session registered.
	registeredAt time.Time
	// reflected holds the last ReflectAddress peer of each family, IPv4
	// first. A replacement session starts empty, like its reflections.
	reflected [2]addressSighting
}

func familyIndex(ip netip.Addr) int {
	if ip.Unmap().Is4() {
		return 0
	}
	return 1
}

// addressSightingLocked looks the address up in the offline ASN database. The
// caller holds the registry lock; the readers are fixed before startup.
func (d *Dispatcher) addressSightingLocked(ip netip.Addr, at time.Time) addressSighting {
	lookup := d.ipMetadata.Lookup(ip.String(), wire.SourceDispatcherObserved, at.Unix(), true)
	return addressSighting{address: ip.String(), via: wire.AddressViaReflection, at: at, asn: lookup.ASN}
}

// sightings returns the observed address of each family. The control
// connection's address is preferred for its own family: the session that
// carries it is alive, so it is current at the last heartbeat, and choosing it
// keeps a multi-homed executor's address from alternating between paths. A
// reflection supplies the other family, or both when the control address is
// only the executor's hello claim.
func (e *RegisteredExecutor) sightings() [2]addressSighting {
	out := e.probe.reflected
	ip, err := netip.ParseAddr(e.sourceIp)
	if !e.sourceIPObserved || err != nil {
		return out
	}
	asn := wire.IPLookup[wire.ASInfo]{ObservedAt: e.LastSeen.Unix(), Reason: "no_database"}
	if e.ipMetadata != nil && e.ipMetadata.Observed.AddressSource == wire.SourceDispatcherObserved {
		asn = e.ipMetadata.Observed.ASN
	}
	ip = ip.Unmap()
	out[familyIndex(ip)] = addressSighting{address: ip.String(), via: wire.AddressViaControl, at: e.LastSeen, asn: asn}
	return out
}

// Addressing is the executor's RIPE Atlas-style addressing for the listing.
// The addresses are withheld unless the executor is public or the caller may
// see private detail (an established operator); prefix and ASN are not.
func (e *RegisteredExecutor) Addressing(private bool) wire.ProbeAddressing {
	return addressing(e.sightings(), !e.probe.optOut, private)
}

func addressing(sightings [2]addressSighting, public, private bool) wire.ProbeAddressing {
	out := wire.ProbeAddressing{IsPublic: &public, AddressObservations: &wire.AddressObservations{}}
	addresses := [2]**string{&out.AddressV4, &out.AddressV6}
	prefixes := [2]**string{&out.PrefixV4, &out.PrefixV6}
	asns := [2]**uint32{&out.ASNV4, &out.ASNV6}
	observations := [2]**wire.AddressObservation{&out.AddressObservations.V4, &out.AddressObservations.V6}
	for i, sighting := range sightings {
		if sighting.address == "" {
			continue
		}
		if public || private {
			address := sighting.address
			*addresses[i] = &address
		}
		observation := &wire.AddressObservation{Source: wire.SourceDispatcherObserved, Via: sighting.via, ObservedAt: sighting.at.Unix(), LookupReason: sighting.asn.Reason}
		if sighting.asn.Source != nil {
			source := *sighting.asn.Source
			observation.LookupSource = &source
		}
		if value := sighting.asn.Value; value != nil {
			number, prefix := value.Number, value.Prefix
			*asns[i], *prefixes[i] = &number, &prefix
		}
		*observations[i] = observation
	}
	return out
}
