// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import "time"

// CapabilityObservation distinguishes an expired report from absent or
// malformed metadata while legacy Capabilities continues to expire to null.
type CapabilityObservation struct {
	State      string `json:"state"`
	ObservedAt *int64 `json:"observed_at"`
	ExpiresAt  *int64 `json:"expires_at"`
}

// ExecutorAdmissionLimits describes the dispatcher policy's numeric domain,
// not free resources. A complete scheduled reservation must also fit the
// scheduler's time range and the executor's remaining advertised capacity.
type ExecutorAdmissionLimits struct {
	Scheduling      bool   `json:"scheduling"`
	MinTimeoutMS    int64  `json:"min_timeout_ms"`
	MaxTimeoutMS    int64  `json:"max_timeout_ms"`
	MaxBandwidthBPS int64  `json:"max_bandwidth_bps"`
	PriceUnit       string `json:"price_unit"`
}

// Connectivity records bounded observations against operator-controlled peers.
// A successful test describes that peer and transport at that time; it does
// not establish reachability to every destination or port. Addresses and
// endpoints are returned only to operators and in owner-visible results.
type Connectivity struct {
	SchemaVersion int            `json:"schema_version"`
	IPv4          Reachability   `json:"ipv4"`
	IPv6          Reachability   `json:"ipv6"`
	TCPListener   Reachability   `json:"tcp_listener"`
	UDPListener   Reachability   `json:"udp_listener"`
	SCIONListener Reachability   `json:"scion_listener"`
	SCIONHost     ObservedString `json:"scion_host"`
	SCIONPaths    Reachability   `json:"scion_paths"`
	Disagreements []string       `json:"disagreements"`
}

// Reachability distinguishes an unsuccessful test from an unperformed one.
// Missing times mean no test was performed. Stale retains the last outcome
// without renewing its authority. Endpoint identifies the one tested peer or
// listener; Address is the reflector-observed egress address, when available.
type Reachability struct {
	State      string `json:"state"` // reachable, unreachable or untested.
	Reason     string `json:"reason"`
	Source     string `json:"source"`
	ObservedAt *int64 `json:"observed_at"`
	ExpiresAt  *int64 `json:"expires_at"`
	Stale      bool   `json:"stale"`
	Address    string `json:"address,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
}

// FreshReachable never treats an expired or untested observation as positive.
func (r Reachability) FreshReachable(now time.Time) bool {
	return r.State == "reachable" && !r.Stale && r.ObservedAt != nil && r.ExpiresAt != nil &&
		now.Unix() >= *r.ObservedAt && now.Unix() < *r.ExpiresAt
}

// CloneConnectivity detaches pointer fields for registry and result snapshots.
func CloneConnectivity(in *Connectivity, now time.Time, private bool) *Connectivity {
	if in == nil {
		return nil
	}
	out := *in
	out.Disagreements = append([]string{}, in.Disagreements...)
	for _, r := range []*Reachability{&out.IPv4, &out.IPv6, &out.TCPListener, &out.UDPListener, &out.SCIONListener, &out.SCIONPaths} {
		if r.ObservedAt != nil {
			at := *r.ObservedAt
			r.ObservedAt = &at
		}
		if r.ExpiresAt != nil {
			at := *r.ExpiresAt
			r.ExpiresAt = &at
			if !now.IsZero() {
				r.Stale = now.Unix() >= at || r.ObservedAt != nil && now.Unix() < *r.ObservedAt
			}
		}
		if !private {
			r.Address, r.Endpoint = "", ""
		}
	}
	if in.SCIONHost.Value != nil {
		value := *in.SCIONHost.Value
		out.SCIONHost.Value = &value
	}
	if in.SCIONHost.Source != nil {
		value := *in.SCIONHost.Source
		out.SCIONHost.Source = &value
	}
	if in.SCIONHost.ObservedAt != nil {
		value := *in.SCIONHost.ObservedAt
		out.SCIONHost.ObservedAt = &value
	}
	if !private {
		out.SCIONHost = ObservedString{}
	}
	return &out
}
