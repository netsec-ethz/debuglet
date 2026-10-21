// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package netaddr

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParsePortRanges expands "2022,2025-3005,56000-62000" into a deduped,
// ordered []int. Each port must satisfy 1 <= p <= 65535 and range start <= end.
// Empty string yields an empty list with no error.
func ParsePortRanges(spec string) ([]int, error) {
	if strings.TrimSpace(spec) == "" {
		return []int{}, nil
	}

	seen := make(map[int]struct{})
	var ports []int
	for part := range strings.SplitSeq(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, err := parseRange(part)
		if err != nil {
			return nil, err
		}
		for p := lo; p <= hi; p++ {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	return ports, nil
}

func parseRange(part string) (int, int, error) {
	fields := strings.SplitN(part, "-", 2)
	lo, err := parsePort(fields[0])
	if err != nil {
		return 0, 0, err
	}
	hi := lo
	if len(fields) == 2 {
		hi, err = parsePort(fields[1])
		if err != nil {
			return 0, 0, err
		}
	}
	if lo > hi {
		return 0, 0, fmt.Errorf("invalid port range %q: start %d greater than end %d", part, lo, hi)
	}
	return lo, hi, nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", s, err)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %d: must be between 1 and 65535", p)
	}
	return p, nil
}
