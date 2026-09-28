// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package observability collects on-demand operational observations without
// changing the subsystems being observed.
package observability

import "time"

// HostValue is either an observation or a fixed reason it could not be read.
// An unavailable value is null, never an inferred zero. Reasons do not include
// paths or operating-system error text.
type HostValue struct {
	Value       *uint64 `json:"value"`
	Unavailable string  `json:"unavailable,omitempty"`
}

// HostSnapshot describes this process and the filesystem containing its state.
// Fields are observed sequentially, not as an atomic system-wide snapshot.
type HostSnapshot struct {
	ObservedAt          time.Time `json:"observed_at"`
	ProcessRSSBytes     HostValue `json:"process_rss_bytes"`
	OpenFDs             HostValue `json:"open_fds"`
	StateAvailableBytes HostValue `json:"state_available_bytes"`
	StateCapacityBytes  HostValue `json:"state_capacity_bytes"`
}

func hostValue(value uint64) HostValue {
	return HostValue{Value: &value}
}
