// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !linux

package observability

import "time"

// CollectHost reports unavailable observations on unsupported platforms.
func CollectHost(stateDir string) HostSnapshot {
	value := HostValue{Unavailable: "unsupported"}
	return HostSnapshot{
		ObservedAt: time.Now().UTC(), ProcessRSSBytes: value, OpenFDs: value,
		StateAvailableBytes: value, StateCapacityBytes: value,
	}
}
