// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

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
// dispatcher has observed no address of that family: for a connected
// executor in its current control session, for another within the retained
// history.
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

// Probe status names, after RIPE Atlas's Connected, Disconnected, Abandoned
// and Never Connected.
const (
	ProbeConnected      = "connected"
	ProbeDisconnected   = "disconnected"
	ProbeAbandoned      = "abandoned"
	ProbeNeverConnected = "never_connected"
)

// ProbeStatuses lists the status names in their documented order.
var ProbeStatuses = []string{ProbeConnected, ProbeDisconnected, ProbeAbandoned, ProbeNeverConnected}

// AbandonedAfter is how long an executor stays disconnected before it is
// abandoned: 30 days after it was last known connected.
const AbandonedAfter = 30 * 24 * time.Hour

// HostTags is the fixed vocabulary of tags an executor's host may set in its
// configuration ([metadata] host_tags): where the host is, how it is
// connected, and whether it sits behind a NAT the host knows of.
var HostTags = []string{
	"home", "office", "datacentre", "academic", "cloud",
	"dsl", "cable", "fibre", "wifi", "mobile", "satellite",
	"nat",
}

// MaxHostTags bounds the host tags of one executor.
const MaxHostTags = 8

// System tags, derived by the dispatcher from its own observations and the
// executor's reports; see docs/operations/executor-discovery.md.
const (
	TagIPv4Works     = "system-ipv4-works"
	TagIPv6Works     = "system-ipv6-works"
	TagIPv4Capable   = "system-ipv4-capable"
	TagIPv6Capable   = "system-ipv6-capable"
	TagIPv4RFC1918   = "system-ipv4-rfc1918"
	TagResolvesA     = "system-resolves-a-correctly"
	TagResolvesAAAA  = "system-resolves-aaaa-correctly"
	TagIPv4Stable1d  = "system-ipv4-stable-1d"
	TagIPv4Stable30d = "system-ipv4-stable-30d"
	TagIPv4Stable90d = "system-ipv4-stable-90d"
	TagIPv6Stable1d  = "system-ipv6-stable-1d"
	TagIPv6Stable30d = "system-ipv6-stable-30d"
	TagIPv6Stable90d = "system-ipv6-stable-90d"
)

// CanonicalHostTags validates host tags against HostTags and returns them in
// vocabulary order. Unknown, repeated or too many tags are an error.
func CanonicalHostTags(tags []string) ([]string, error) {
	if len(tags) > MaxHostTags {
		return nil, fmt.Errorf("at most %d host tags", MaxHostTags)
	}
	seen := map[string]bool{}
	for _, tag := range tags {
		if !slices.Contains(HostTags, tag) {
			return nil, fmt.Errorf("unknown host tag %q; use one of %s", tag, strings.Join(HostTags, ", "))
		}
		if seen[tag] {
			return nil, fmt.Errorf("repeated host tag %q", tag)
		}
		seen[tag] = true
	}
	out := []string{}
	for _, tag := range HostTags {
		if seen[tag] {
			out = append(out, tag)
		}
	}
	return out, nil
}

// ProbeStatusName is a status with the Unix second it began.
type ProbeStatusName struct {
	Name  string `json:"name"`
	Since *int64 `json:"since"`
}

// ProbeStatus is the RIPE Atlas-style status history and tags of an
// executor, embedded in Executor. A dispatcher of API 1.17 or later always
// sends every field; all are absent from older dispatchers.
//
// Times are Unix seconds. FirstConnected and LastConnected are null for an
// executor that never connected; LastConnected of a connected executor is its
// last heartbeat. TotalUptime counts connected seconds since the dispatcher
// began recording them (schema 24). Tags lists the host tags, then the system
// tags, which start with "system-".
type ProbeStatus struct {
	Status         *ProbeStatusName `json:"status"`
	StatusSince    *int64           `json:"status_since"`
	FirstConnected *int64           `json:"first_connected"`
	LastConnected  *int64           `json:"last_connected"`
	TotalUptime    *int64           `json:"total_uptime"`
	Tags           []string         `json:"tags"`
}
