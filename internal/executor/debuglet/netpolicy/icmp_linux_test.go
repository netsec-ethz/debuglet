// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package netpolicy

import (
	"os"
	"testing"
)

// The probe runs on every capability report, so each one, permitted or not,
// must release every descriptor it opens, the ping socket included.
func TestRefreshICMPReleasesDescriptors(t *testing.T) {
	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skipf("no /proc/self/fd: %v", err)
		}
		return len(entries)
	}
	RefreshICMP()
	_ = probePingSocket()
	before := count()
	for range 64 {
		RefreshICMP()
		_ = probePingSocket()
	}
	if after := count(); after > before {
		t.Fatalf("open descriptors grew from %d to %d", before, after)
	}
}
