// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

// egressFilters lists the tc bpf filters on iface's egress hook by handle.
func egressFilters(t *testing.T, iface *net.Interface) map[uint32]tc.Object {
	t.Helper()
	conn, err := tc.Open(&tc.Config{})
	if err != nil {
		t.Fatalf("open rtnetlink: %v", err)
	}
	defer conn.Close()
	filters, err := conn.Filter().Get(&tc.Msg{
		Family:  unix.AF_UNSPEC,
		Ifindex: uint32(iface.Index),
		Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress),
	})
	if err != nil {
		t.Fatalf("list egress filters: %v", err)
	}
	byHandle := make(map[uint32]tc.Object)
	for _, filter := range filters {
		if filter.Kind == "bpf" {
			byHandle[filter.Handle] = filter
		}
	}
	return byHandle
}

// TestLegacyTCAttachesAndRemovesOnlyItsFilter covers the attachment used where
// the kernel has no TCX: the program is installed as a direct-action filter
// under the run's handle, and Close removes that filter and nothing else.
func TestLegacyTCAttachesAndRemovesOnlyItsFilter(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("InterfaceByName: %v", err)
	}
	var objs taggerObjects
	if err := loadTaggerObjects(&objs, nil); err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("skipping test: insufficient privileges for eBPF: %v", err)
		}
		t.Fatalf("load tagger objects: %v", err)
	}
	defer objs.Close()

	const first, second = 0x0DEB0001, 0x0DEB0002
	a, err := attachLegacyTC(iface, objs.DebugletTag, first)
	if err != nil {
		t.Fatalf("attach first filter: %v", err)
	}
	defer a.Close()
	b, err := attachLegacyTC(iface, objs.DebugletTag, second)
	if err != nil {
		t.Fatalf("attach second filter on the shared clsact: %v", err)
	}
	defer b.Close()

	filters := egressFilters(t, iface)
	for _, handle := range []uint32{first, second} {
		filter, ok := filters[handle]
		if !ok {
			t.Fatalf("filter %#x is not installed: %v", handle, filters)
		}
		if priority := filter.Info >> 16; priority != legacyFilterPriority {
			t.Errorf("filter %#x has priority %#x, want %#x", handle, priority, legacyFilterPriority)
		}
		if filter.BPF == nil || filter.BPF.Flags == nil || *filter.BPF.Flags&tc.BpfActDirect == 0 {
			t.Errorf("filter %#x is not direct-action", handle)
		}
	}

	if err := a.Close(); err != nil {
		t.Fatalf("close first filter: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second close of the first filter: %v", err)
	}
	filters = egressFilters(t, iface)
	if _, ok := filters[first]; ok {
		t.Error("the first filter survived its Close")
	}
	if _, ok := filters[second]; !ok {
		t.Error("closing one filter removed another run's filter")
	}
}
