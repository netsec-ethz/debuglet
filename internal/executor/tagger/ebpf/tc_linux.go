// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// legacyFilterName is the name every tagger gives its legacy tc filter.
const legacyFilterName = "debuglet_tag"

// legacyFilterPriority orders the tagger's filters among an interface's tc
// egress filters. Every tagger uses it; the handle tells them apart.
const legacyFilterPriority = 0xC0DE

// legacyFilter is the tagger program attached as a direct-action tc bpf
// filter on a clsact qdisc, the attachment kernels without TCX (before 6.6)
// offer. Close removes this filter only: the clsact qdisc is shared by every
// tagger on the interface and by whatever else uses it, so it stays. No
// rtnetlink socket is held between the attach and Close.
type legacyFilter struct {
	filter    tc.Object
	closeOnce sync.Once
	closeErr  error
}

// attachLegacyTC attaches program to iface's tc egress hook under handle,
// which identifies this run's filter for removal.
func attachLegacyTC(iface *net.Interface, program *ebpf.Program, handle uint32) (*legacyFilter, error) {
	conn, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, fmt.Errorf("open rtnetlink: %w", err)
	}
	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{Kind: "clsact"},
	}
	if err := conn.Qdisc().Add(&qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, errors.Join(fmt.Errorf("add clsact qdisc: %w", err), conn.Close())
	}
	fd := uint32(program.FD())
	name := legacyFilterName
	flags := uint32(tc.BpfActDirect)
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  handle,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress),
			Info:    core.FilterInfo(legacyFilterPriority, unix.ETH_P_ALL),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF:  &tc.Bpf{FD: &fd, Name: &name, Flags: &flags},
		},
	}
	if err := conn.Filter().Add(&filter); err != nil {
		return nil, errors.Join(fmt.Errorf("add bpf egress filter: %w", err), conn.Close())
	}
	attached := &legacyFilter{filter: filter}
	if err := conn.Close(); err != nil {
		return nil, errors.Join(fmt.Errorf("close rtnetlink: %w", err), attached.Close())
	}
	return attached, nil
}

// Close removes the filter once. A filter that is already gone, for example
// with its interface, is not an error.
func (f *legacyFilter) Close() error {
	f.closeOnce.Do(func() {
		conn, err := tc.Open(&tc.Config{})
		if err != nil {
			f.closeErr = fmt.Errorf("open rtnetlink: %w", err)
			return
		}
		deleteErr := conn.Filter().Delete(&f.filter)
		if errors.Is(deleteErr, unix.ENOENT) || errors.Is(deleteErr, unix.ENODEV) {
			deleteErr = nil
		}
		if deleteErr != nil {
			deleteErr = fmt.Errorf("delete bpf egress filter: %w", deleteErr)
		}
		f.closeErr = errors.Join(deleteErr, conn.Close())
	})
	return f.closeErr
}

// RetireStaleFilters removes from iface's egress hook every legacy tc filter
// a tagger of an earlier process left. A TCX attachment is owned by its link
// descriptor and ends with its process, but a legacy filter keeps its program
// and key map, and so keeps signing with the last key installed, until it is
// deleted. It is called before this process attaches any tagger, so every
// tagger filter found on iface is stale. Other interfaces are inspected but
// never changed: any remaining filter at the tagger's priority, or a failed
// listing or deletion, means the earlier signers are not known to be retired.
// A nil iface performs only this read-only check, including after a restart
// with fallback packet counting or no configured interface.
func RetireStaleFilters(iface *net.Interface, logger *zap.Logger) error {
	conn, err := tc.Open(&tc.Config{})
	if err != nil {
		return fmt.Errorf("open rtnetlink: %w", err)
	}
	defer conn.Close()
	list := func(ifindex uint32) ([]tc.Object, error) {
		qdiscs, err := conn.Qdisc().Get()
		if err != nil {
			return nil, fmt.Errorf("list qdiscs: %w", err)
		}
		var all []tc.Object
		for _, qdisc := range qdiscs {
			if (ifindex == 0 || qdisc.Ifindex == ifindex) && qdisc.Kind == "clsact" {
				egress := tc.Msg{Family: unix.AF_UNSPEC, Ifindex: qdisc.Ifindex, Parent: core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress)}
				filters, err := conn.Filter().Get(&egress)
				if err != nil {
					return nil, fmt.Errorf("list egress filters: %w", err)
				}
				all = append(all, filters...)
			}
		}
		// Without a clsact qdisc no legacy filter is attached.
		return all, nil
	}
	if iface != nil {
		if err := retireStaleFilters(func() ([]tc.Object, error) { return list(uint32(iface.Index)) }, func(filter *tc.Object) error { return conn.Filter().Delete(filter) }, logger); err != nil {
			return err
		}
	}
	filters, err := list(0)
	if err != nil {
		return err
	}
	for _, filter := range filters {
		if filter.Info>>16 == legacyFilterPriority && filter.Handle != 0 {
			return fmt.Errorf("egress filter %#x on interface %d may still sign with the previous chain; retire it before recovering that chain", filter.Handle, filter.Ifindex)
		}
	}
	return nil
}

// retireStaleFilters deletes the tagger filters list returns through remove.
func retireStaleFilters(list func() ([]tc.Object, error), remove func(*tc.Object) error, logger *zap.Logger) error {
	filters, err := list()
	if err != nil {
		return err
	}
	var errs []error
	for _, filter := range filters {
		// Handle 0 is the dump's entry for the priority itself, not a filter.
		if filter.Info>>16 != legacyFilterPriority || filter.Handle == 0 {
			continue
		}
		if filter.Kind != "bpf" || filter.BPF == nil || filter.BPF.Name == nil || *filter.BPF.Name != legacyFilterName {
			errs = append(errs, fmt.Errorf("egress filter %#x at the tagger's priority is not a tagger filter", filter.Handle))
			continue
		}
		stale := tc.Object{Msg: tc.Msg{Family: unix.AF_UNSPEC, Ifindex: filter.Ifindex, Handle: filter.Handle, Parent: filter.Parent,
			Info: core.FilterInfo(legacyFilterPriority, unix.ETH_P_ALL)}, Attribute: tc.Attribute{Kind: "bpf"}}
		if err := remove(&stale); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("delete stale egress filter %#x: %w", filter.Handle, err))
			continue
		}
		logger.Warn("Removed a tagger filter an earlier executor process left attached", zap.Uint32("ifindex", filter.Ifindex), zap.Uint32("handle", filter.Handle))
	}
	return errors.Join(errs...)
}
