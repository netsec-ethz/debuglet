// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"errors"
	"math"

	"github.com/cilium/ebpf"
)

// DropTotals reads cumulative observations for this counter instance, ordered
// ingress then egress. Verdicts count TCX_DROP returns; bytes sum skb->len at
// those returns. Neither is an on-wire packet/byte count or proof that every
// traffic path passed through this program. A new counter starts at zero.
// Sessions finish before the node closes the counter and its owned maps.
func (bc *BpfCount) DropTotals() (verdicts, skbBytes [2]uint64, err error) {
	if bc.AttachmentState() != "present" || bc.objs.DropStats == nil {
		return verdicts, skbBytes, errors.New("counter drop observations unavailable")
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return verdicts, skbBytes, err
	}
	verdicts, skbBytes, err = readDropTotals(bc.objs.DropStats, cpus)
	if err == nil && bc.AttachmentState() != "present" {
		err = errors.New("counter attachment changed while reading drop observations")
	}
	if err != nil {
		return [2]uint64{}, [2]uint64{}, err
	}
	return verdicts, skbBytes, nil
}

func readDropTotals(reader interface{ Lookup(any, any) error }, cpus int) (verdicts, skbBytes [2]uint64, err error) {
	if cpus < 1 || cpus > 65536 {
		return verdicts, skbBytes, errors.New("unsupported CPU count for drop observations")
	}
	values := make([]countDropTotals, cpus)
	for direction := uint32(0); direction < 2; direction++ {
		if err := reader.Lookup(&direction, &values); err != nil {
			return [2]uint64{}, [2]uint64{}, err
		}
		for _, value := range values {
			if value.Verdicts > math.MaxUint64-verdicts[direction] || value.Bytes > math.MaxUint64-skbBytes[direction] {
				return [2]uint64{}, [2]uint64{}, errors.New("counter drop observations overflow")
			}
			verdicts[direction] += value.Verdicts
			skbBytes[direction] += value.Bytes
		}
	}
	return verdicts, skbBytes, nil
}
