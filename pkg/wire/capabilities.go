// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

// ExecutorCapabilities is a current executor-reported observation, not a
// destination reachability, admission or packet-attribution guarantee. An absent
// object means unknown, including older peers, stale reports and unknown versions.
type ExecutorCapabilities struct {
	SchemaVersion         uint32            `json:"schema_version"`
	ObservedAt            int64             `json:"observed_at"`             // Dispatcher receipt time, Unix seconds.
	Protocols             []string          `json:"protocols"`               // Positive tcp, tls, udp, icmp (IPv4), scion support.
	EnforcementMode       string            `json:"enforcement_mode"`        // Actual ebpf/fallback packet counter; empty unknown.
	AdvertisedCapacityBPS *int64            `json:"advertised_capacity_bps"` // Total reported bandwidth, not free capacity; null unknown.
	Attribution           *AttributionState `json:"attribution"`             // Null unknown, including executors that predate it.
	Tagging               *TaggingMode      `json:"tagging"`                 // Null unknown, including executors that predate it.
}

// Tagging modes of one address family or transport.
const (
	TaggingEBPF      = "ebpf"      // Kernel tagger: every packet of a marked socket.
	TaggingUserspace = "userspace" // Pure-Go tagger: IPv4 UDP and ICMP datagrams only; TCP and TLS untagged.
	TaggingNone      = "none"      // Untagged.
)

// TaggingMode is the executor's report of how a run's packets are tagged, per
// address family and for SCION. It is the mode of the executor's latest run,
// or before any run the mode a run is set up to get; an executor claim, not a
// verification. Readers must tolerate values they do not know.
type TaggingMode struct {
	IPv4  string `json:"ipv4"`
	IPv6  string `json:"ipv6"`
	SCION string `json:"scion"`
}

// AttributionState is the executor's report of whether packets it tags now can
// be attributed once their TESLA key is disclosed. Its times are the dispatcher
// receipt time minus an executor-reported age, in Unix seconds, so they share
// ObservedAt's clock. Available is an executor claim, not a verification.
type AttributionState struct {
	State               string `json:"state"`                 // available or unavailable.
	Reason              string `json:"reason"`                // Empty when available; epoch_zero, chain_exhausted, refresh_failing, disclosure_held.
	Epoch               int64  `json:"epoch"`                 // Current key-schedule epoch.
	InstalledEpoch      *int64 `json:"installed_epoch"`       // Oldest epoch a kernel tagger may still sign with; null when none holds a key.
	LastRefreshAt       *int64 `json:"last_refresh_at"`       // Oldest last successful kernel key install; null without one.
	RefreshError        string `json:"refresh_error"`         // Short error of a failing kernel key refresh; empty when none fails.
	DisclosureHeldSince *int64 `json:"disclosure_held_since"` // When an installed key started holding disclosure back; null when not held.
}
