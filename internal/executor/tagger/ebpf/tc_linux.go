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
	"golang.org/x/sys/unix"
)

// legacyFilterPriority orders the tagger's filters among an interface's tc
// egress filters. Every tagger uses it; the handle tells them apart.
const legacyFilterPriority = 0xC0DE

// legacyFilter is the tagger program attached as a direct-action tc bpf
// filter on a clsact qdisc, the attachment kernels without TCX (before 6.6)
// offer. Close removes this filter only: the clsact qdisc is shared by every
// tagger on the interface and by whatever else uses it, so it stays.
type legacyFilter struct {
	conn      *tc.Tc
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
	name := "debuglet_tag"
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
	return &legacyFilter{conn: conn, filter: filter}, nil
}

// Close removes the filter once. A filter that is already gone, for example
// with its interface, is not an error.
func (f *legacyFilter) Close() error {
	f.closeOnce.Do(func() {
		deleteErr := f.conn.Filter().Delete(&f.filter)
		if errors.Is(deleteErr, unix.ENOENT) || errors.Is(deleteErr, unix.ENODEV) {
			deleteErr = nil
		}
		if deleteErr != nil {
			deleteErr = fmt.Errorf("delete bpf egress filter: %w", deleteErr)
		}
		f.closeErr = errors.Join(deleteErr, f.conn.Close())
	})
	return f.closeErr
}
