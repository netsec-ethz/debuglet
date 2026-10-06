// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

// Ways the dispatcher observed an executor's address. Both are the peer
// address of a connection the executor authenticated with its own identity;
// neither is the executor's claim.
const (
	// AddressViaControl is the executor's control connection.
	AddressViaControl = "control"
	// AddressViaReflection is a ReflectAddress call over the other address
	// family (docs/operations/executor-discovery.md).
	AddressViaReflection = "reflection"
)

// AddressObservation describes how and when the dispatcher last observed the
// address of one family. The address itself is in Executor.AddressV4 or
// AddressV6, where is_public may hide it; this record never carries it.
type AddressObservation struct {
	Source string `json:"source"` // Always dispatcher-observed.
	Via    string `json:"via"`    // control or reflection.
	// ObservedAt is the Unix second of the last observation: the last
	// heartbeat of the control session that carries the address, or the
	// receipt of the last reflection call.
	ObservedAt int64 `json:"observed_at"`
	// LookupSource names the offline ASN database the prefix and ASN come
	// from, as in ip_metadata; null when no database is configured.
	LookupSource *string `json:"lookup_source"`
	// LookupReason is empty when the database knew the address; otherwise
	// it explains a null prefix and ASN, with the ip_metadata vocabulary.
	LookupReason string `json:"lookup_reason"`
}

// AddressObservations has one record per address family, null when the
// dispatcher has observed no address of that family in the current control
// session.
type AddressObservations struct {
	V4 *AddressObservation `json:"v4"`
	V6 *AddressObservation `json:"v6"`
}

// ProbeAddressing is the RIPE Atlas-style addressing of an executor in the
// public listing, embedded in Executor. A dispatcher of API 1.16 or later
// always sends every field, null when unknown; all are absent from
// dispatchers older than API 1.16, which a client reads as unknown.
//
// AddressV4 and AddressV6 are the last addresses the dispatcher itself
// observed for each family. They are null when none was observed, and in the
// public listing also when IsPublic is false; an operator always sees them.
// Prefixes and ASNs are looked up from those addresses in the offline ASN
// database and stay public for a private executor, as RIPE Atlas does.
type ProbeAddressing struct {
	IsPublic            *bool                `json:"is_public"`
	AddressV4           *string              `json:"address_v4"`
	AddressV6           *string              `json:"address_v6"`
	PrefixV4            *string              `json:"prefix_v4"`
	PrefixV6            *string              `json:"prefix_v6"`
	ASNV4               *uint32              `json:"asn_v4"`
	ASNV6               *uint32              `json:"asn_v6"`
	AddressObservations *AddressObservations `json:"address_observations"`
}
