// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"net/netip"
	"slices"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func validIPMetadata(m *wire.IPMetadata) bool {
	if m == nil {
		return true
	} // Earlier result 1.1 files omit the field.
	addresses := []wire.AddressMetadata{m.Observed, m.Advertised}
	if m.Reported != nil {
		addresses = append(addresses, *m.Reported)
	}
	for _, a := range addresses {
		if a.AddressSource != wire.SourceDispatcherObserved && a.AddressSource != wire.SourceExecutorReported {
			return false
		}
		if !validLookup(a.ASN, func(v wire.ASInfo) bool { _, err := netip.ParsePrefix(v.Prefix); return v.Number > 0 && err == nil }) {
			return false
		}
		if !validLookup(a.Location, func(v wire.GeoLocation) bool {
			return len(v.Country) == 2 && (v.Precision == "country" && v.City == "" || v.Precision == "city" && v.City != "")
		}) {
			return false
		}
		if m.LocationOptOut && (a.Location.Value != nil || a.Location.Source != nil || a.Location.Reason != "opted_out") {
			return false
		}
	}
	for _, disagreement := range m.Disagreements {
		if !slices.Contains([]string{"observed_advertised_asn", "observed_advertised_location", "operator_location"}, disagreement) {
			return false
		}
	}
	return true
}

func validLookup[T any](r wire.IPLookup[T], valid func(T) bool) bool {
	if r.ObservedAt <= 0 {
		return false
	}
	if r.Source != nil && !wire.DatabaseSource(*r.Source) {
		return false
	}
	if r.Value != nil {
		return r.Reason == "" && r.Source != nil && valid(*r.Value)
	}
	switch r.Reason {
	case "not_found", "lookup_error", "invalid_record":
		return r.Source != nil
	case "no_database", "no_address", "not_ip", "non_global", "opted_out":
		return r.Source == nil
	default:
		return false
	}
}
