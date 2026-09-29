// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ExecutorCapabilities is a current executor-reported observation, not a
// destination reachability, admission or packet-attribution guarantee. An absent
// object means unknown, including older peers, stale reports and unknown versions.
type ExecutorCapabilities struct {
	SchemaVersion         uint32   `json:"schema_version"`
	ObservedAt            int64    `json:"observed_at"`             // Dispatcher receipt time, Unix seconds.
	Protocols             []string `json:"protocols"`               // Positive tcp, tls, udp, icmp (IPv4), scion support.
	EnforcementMode       string   `json:"enforcement_mode"`        // Actual ebpf/fallback packet counter; empty unknown.
	AdvertisedCapacityBPS *int64   `json:"advertised_capacity_bps"` // Total reported bandwidth, not free capacity; null unknown.
}

// Admission states of a listed executor. An executor whose control session
// ended is not listed at all.
const (
	// AdmissionReady executors accept submissions, subject to normal admission.
	AdmissionReady = "ready"
	// AdmissionMaintenance means the dispatcher's operator stopped admission.
	AdmissionMaintenance = "maintenance"
	// AdmissionOffline executors have sent no heartbeat on their current
	// control session yet; selection skips them.
	AdmissionOffline = "offline"
)

// ExecutorDisplay is operator presentation metadata from the dispatcher
// configuration. Location is at most city and country and is never inferred.
type ExecutorDisplay struct {
	DisplayName LabelledString `json:"display_name"`
	City        LabelledString `json:"city"`
	Country     LabelledString `json:"country"` // ISO 3166-1 alpha-2.
	Network     LabelledString `json:"network"`
}

// ObservedString is an expiring observation in the live executor view. All
// three fields are null when it is unknown or has expired.
type ObservedString struct {
	Value      *string `json:"value"`
	Source     *string `json:"source"`
	ObservedAt *int64  `json:"observed_at"` // Dispatcher receipt time, Unix seconds.
}

// ObservedList is an expiring list observation. A null Value is unknown; an
// empty one was observed as empty.
type ObservedList struct {
	Value      []string `json:"value"`
	Source     *string  `json:"source"`
	ObservedAt *int64   `json:"observed_at"` // Dispatcher receipt time, Unix seconds.
}

// CanonicalISDAS returns the canonical text of a concrete SCION ISD-AS, as the
// SCION libraries print it: a decimal ISD, then a decimal AS up to 2^32-1 or
// three colon-separated hexadecimal groups above it. Wildcards (ISD or AS 0)
// and malformed values are rejected.
func CanonicalISDAS(text string) (string, bool) {
	isdText, asText, ok := strings.Cut(text, "-")
	if !ok {
		return "", false
	}
	isd, err := strconv.ParseUint(isdText, 10, 16)
	if err != nil || isd == 0 {
		return "", false
	}
	var as uint64
	if groups := strings.Split(asText, ":"); len(groups) == 1 {
		if as, err = strconv.ParseUint(asText, 10, 32); err != nil {
			return "", false
		}
	} else if len(groups) == 3 {
		for _, group := range groups {
			part, err := strconv.ParseUint(group, 16, 16)
			if err != nil {
				return "", false
			}
			as = as<<16 | part
		}
	} else {
		return "", false
	}
	if as == 0 {
		return "", false
	}
	if as <= math.MaxUint32 {
		return fmt.Sprintf("%d-%d", isd, as), true
	}
	return fmt.Sprintf("%d-%x:%x:%x", isd, as>>32, as>>16&0xffff, as&0xffff), true
}
