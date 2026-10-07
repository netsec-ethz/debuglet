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
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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

// TestRetireStaleFiltersRemovesAnEarlierProcessFilter attaches a legacy
// filter as a process that then ended without removing it: the filter, with
// its program, outlives the process's descriptors. The sweep of the next
// process's start removes it and only tagger filters.
func TestRetireStaleFiltersRemovesAnEarlierProcessFilter(t *testing.T) {
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
	const handle = 0x0DEB0071
	stale, err := attachLegacyTC(iface, objs.DebugletTag, handle)
	if err != nil {
		objs.Close()
		t.Fatalf("attach filter: %v", err)
	}
	t.Cleanup(func() { _ = stale.Close() })
	// The earlier process ends: its descriptors close, the filter stays.
	if err := objs.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := egressFilters(t, iface)[handle]; !ok {
		t.Fatal("the filter did not outlive its program descriptor")
	}

	core, logs := observer.New(zapcore.WarnLevel)
	if err := RetireStaleFilters(iface, zap.New(core)); err != nil {
		t.Fatalf("retire stale filters: %v", err)
	}
	if _, ok := egressFilters(t, iface)[handle]; ok {
		t.Fatal("the stale filter is still attached")
	}
	if logs.FilterMessage("Removed a tagger filter an earlier executor process left attached").FilterField(zap.Uint32("handle", handle)).Len() != 1 {
		t.Fatalf("removal logged %v", logs.All())
	}
	if err := RetireStaleFilters(iface, zap.NewNop()); err != nil {
		t.Fatalf("a second sweep: %v", err)
	}
}

// The sweep deletes only filters that carry the tagger's identity, and
// reports a failed listing or deletion, and a foreign filter at the tagger's
// priority, as an error so the caller does not treat the signers as retired.
func TestRetireStaleFiltersReportsWhatItCannotRetire(t *testing.T) {
	name, other := legacyFilterName, "someone_else"
	filter := func(handle uint32, kind string, filterName *string, priority uint16) tc.Object {
		return tc.Object{Msg: tc.Msg{Handle: handle, Info: core.FilterInfo(priority, unix.ETH_P_ALL)},
			Attribute: tc.Attribute{Kind: kind, BPF: &tc.Bpf{Name: filterName}}}
	}
	ours, unrelated := filter(1, "bpf", &name, legacyFilterPriority), filter(2, "bpf", &other, 1)
	type tcObject = tc.Object
	for _, c := range []struct {
		name    string
		filters []tcObject
		listErr error
		delErr  error
		deleted []uint32
		fails   bool
	}{
		{"none", nil, nil, nil, nil, false},
		{"stale and unrelated", []tcObject{ours, unrelated}, nil, nil, []uint32{1}, false},
		{"priority entry", []tcObject{filter(0, "bpf", nil, legacyFilterPriority), ours}, nil, nil, []uint32{1}, false},
		{"already gone", []tcObject{ours}, nil, unix.ENOENT, []uint32{1}, false},
		{"listing fails", nil, unix.EPERM, nil, nil, true},
		{"deletion fails", []tcObject{ours}, nil, unix.EPERM, []uint32{1}, true},
		{"foreign filter at the tagger's priority", []tcObject{filter(3, "bpf", &other, legacyFilterPriority), ours}, nil, nil, []uint32{1}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var deleted []uint32
			err := retireStaleFilters(func() ([]tcObject, error) { return c.filters, c.listErr }, func(f *tcObject) error {
				deleted = append(deleted, f.Handle)
				return c.delErr
			}, zap.NewNop())
			if (err != nil) != c.fails || len(deleted) != len(c.deleted) || (len(deleted) == 1 && deleted[0] != c.deleted[0]) {
				t.Fatalf("err %v, deleted %v; want failure %v, deleted %v", err, deleted, c.fails, c.deleted)
			}
		})
	}
}
