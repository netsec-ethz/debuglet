// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"testing"

	"golang.org/x/sys/unix"
)

// Load with the deployment capability profile, without CAP_SYS_ADMIN.
// CAP_PERFMON relaxes some verifier checks; this checks that profile, not
// stricter stack verification or compatibility with every kernel version.
// The kernel CI requires this test to pass, with no skipped tests.
func TestCounterVerifierWithoutSysAdmin(t *testing.T) {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		t.Fatal(err)
	}
	effective := uint64(data[1].Effective)<<32 | uint64(data[0].Effective)
	if effective&(1<<unix.CAP_SYS_ADMIN) != 0 {
		t.Skip("this verifier regression requires CAP_SYS_ADMIN to be absent")
	}
	if missing := missingFrom(effective); len(missing) != 0 {
		t.Skipf("counter verifier requires %v", missing)
	}
	var objects countObjects
	if err := loadCountObjects(&objects, nil); err != nil {
		t.Fatalf("counter object rejected without CAP_SYS_ADMIN: %v", err)
	}
	if err := objects.Close(); err != nil {
		t.Fatal(err)
	}
}
