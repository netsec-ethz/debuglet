// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"flag"
	"strconv"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

func capabilityFlags(fs *flag.FlagSet, filter *client.ExecutorFilter) {
	fs.Func("protocol", "required protocol; repeatable", func(value string) error {
		filter.Protocols = append(filter.Protocols, value)
		return nil
	})
	fs.StringVar(&filter.EnforcementMode, "enforcement", "", "actual packet counter: ebpf or fallback")
	fs.StringVar(&filter.ISDAS, "isd-as", "", "executor-reported SCION ISD-AS, e.g. 1-ff00:0:110")
	fs.StringVar(&filter.Country, "country", "", "display country code, e.g. CH")
	fs.Func("asn", "offline database origin ASN, e.g. 559", func(value string) error {
		n, err := strconv.ParseUint(value, 10, 32)
		if err == nil && n == 0 {
			return strconv.ErrRange
		}
		if err == nil {
			filter.ASN = uint32(n)
		}
		return err
	})
	fs.Func("min-capacity-bps", "minimum advertised total bandwidth", func(value string) error {
		minimum, err := strconv.ParseInt(value, 10, 64)
		if err == nil {
			filter.MinCapacityBPS = &minimum
		}
		return err
	})
}
