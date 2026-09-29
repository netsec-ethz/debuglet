// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

// ExecutorCapabilities is a current executor-reported observation, not a
// destination reachability, admission or packet-attribution guarantee. An absent
// object means unknown, including older peers, stale reports and unknown versions.
type ExecutorCapabilities struct {
	SchemaVersion         uint32   `json:"schema_version"`
	ObservedAt            int64    `json:"observed_at"`             // Dispatcher receipt time, Unix seconds.
	Protocols             []string `json:"protocols"`               // Positive tcp, tls, udp, icmp (IPv4), scion support.
	EnforcementMode       string   `json:"enforcement_mode"`        // Actual ebpf/fallback packet counter; empty unknown.
	AdvertisedCapacityBPS *int64   `json:"advertised_capacity_bps"` // Total reported bandwidth, not free capacity; null unknown.
}
