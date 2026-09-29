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
	fs.Func("min-capacity-bps", "minimum advertised total bandwidth", func(value string) error {
		minimum, err := strconv.ParseInt(value, 10, 64)
		if err == nil {
			filter.MinCapacityBPS = &minimum
		}
		return err
	})
}
