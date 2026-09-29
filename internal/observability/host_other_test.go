// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !linux

package observability

import "testing"

func TestUnsupportedHost(t *testing.T) {
	got := CollectHost(".")
	for _, value := range []HostValue{got.ProcessRSSBytes, got.OpenFDs, got.StateAvailableBytes, got.StateCapacityBytes} {
		if value.Value != nil || value.Unavailable != "unsupported" {
			t.Fatalf("unsupported host reported an observation: %+v", value)
		}
	}
}
