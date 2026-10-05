// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// AttachmentState reads the two owned TCX links, without sending packets or
// changing their configuration. Link.Info can succeed after detach: the kernel
// then reports ifindex zero. Presence requires the expected hook and program on
// the configured interface. It proves attachment at observation time, not that
// traffic is policed. Sessions finish before the node closes these handles.
func (bc *BpfCount) AttachmentState() string {
	unknown := false
	for i, expected := range []struct {
		program *ebpf.Program
		hook    ebpf.AttachType
	}{
		{bc.objs.HandleEgress, ebpf.AttachTCXEgress}, {bc.objs.HandleIngress, ebpf.AttachTCXIngress},
	} {
		attached, ok := bc.attachmentLinks[i].(interface{ Info() (*link.Info, error) })
		if !ok || expected.program == nil || bc.interfaceIndex == 0 {
			unknown = true
			continue
		}
		info, err := attached.Info()
		if err != nil || info == nil || info.TCX() == nil {
			unknown = true
			continue
		}
		if info.TCX().Ifindex != bc.interfaceIndex || uint32(info.TCX().AttachType) != uint32(expected.hook) {
			return "missing"
		}
		program, err := expected.program.Info()
		if err != nil {
			unknown = true
			continue
		}
		id, ok := program.ID()
		if !ok {
			unknown = true
			continue
		}
		if info.Program != id {
			return "missing"
		}
	}
	if unknown {
		return "unknown"
	}
	return "present"
}
