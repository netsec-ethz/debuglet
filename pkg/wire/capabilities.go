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
	SchemaVersion         uint32            `json:"schema_version"`
	ObservedAt            int64             `json:"observed_at"`             // Dispatcher receipt time, Unix seconds.
	Protocols             []string          `json:"protocols"`               // Positive tcp, tls, udp, icmp (IPv4), scion support.
	EnforcementMode       string            `json:"enforcement_mode"`        // Actual ebpf/fallback packet counter; empty unknown.
	AdvertisedCapacityBPS *int64            `json:"advertised_capacity_bps"` // Total reported bandwidth, not free capacity; null unknown.
	Attribution           *AttributionState `json:"attribution"`             // Null unknown, including executors that predate it.
	// EnforcementReason says why the counter is fallback: configured,
	// no_interface, not_permitted, unsupported or attach_failed. Empty when
	// unknown or ebpf.
	EnforcementReason string `json:"enforcement_reason"`
	// ICMP is the executor's raw ICMPv4 socket probe; null unknown.
	ICMP *ProbeState `json:"icmp"`
}

// ProbeState is an executor-reported local probe outcome.
type ProbeState struct {
	State  string `json:"state"`  // available or unavailable.
	Reason string `json:"reason"` // Empty when available; disabled, not_permitted, ping_socket_only or unsupported.
}

// ClockReport is the executor's reading of its kernel clock discipline
// (adjtimex). The errors are the kernel's own estimates, maintained by a time
// daemon, not measured bounds.
type ClockReport struct {
	State            string `json:"state"`              // synced, unsynced or unknown.
	EstimatedErrorNS *int64 `json:"estimated_error_ns"` // Kernel esterror; null unknown.
	MaxErrorNS       *int64 `json:"max_error_ns"`       // Kernel maxerror; null unknown.
	ErrorBoundNS     int64  `json:"error_bound_ns"`     // Operator-configured bound on the estimated error.
	Readiness        string `json:"readiness"`          // ready, degraded or unknown.
	Reason           string `json:"reason"`             // Empty unless degraded: unsynced or error_exceeds_bound.
}

// HostPlatform is operator-only host detail. Null values are unknown.
type HostPlatform struct {
	OS            *string `json:"os"`   // Go GOOS.
	Arch          *string `json:"arch"` // Go GOARCH.
	KernelRelease *string `json:"kernel_release"`
	CPUs          *int64  `json:"cpus"`
	MemoryBytes   *uint64 `json:"memory_bytes"`
	BuildVersion  *string `json:"build_version"`
}

// ObservedClock is the live clock observation; all fields are null together
// when unknown or expired.
type ObservedClock struct {
	Value      *ClockReport `json:"value"`
	Source     *string      `json:"source"`
	ObservedAt *int64       `json:"observed_at"` // Dispatcher receipt time, Unix seconds.
}

// AttributionState is the executor's report of whether packets it tags now can
// be attributed once their TESLA key is disclosed. Its times are the dispatcher
// receipt time minus an executor-reported age, in Unix seconds, so they share
// ObservedAt's clock. Available is an executor claim, not a verification.
type AttributionState struct {
	State               string `json:"state"`                 // available or unavailable.
	Reason              string `json:"reason"`                // Empty when available; epoch_zero, chain_exhausted, refresh_failing, disclosure_held.
	Epoch               int64  `json:"epoch"`                 // Current key-schedule epoch.
	InstalledEpoch      *int64 `json:"installed_epoch"`       // Oldest epoch a kernel tagger may still sign with; null when none holds a key.
	LastRefreshAt       *int64 `json:"last_refresh_at"`       // Oldest last successful kernel key install; null without one.
	RefreshError        string `json:"refresh_error"`         // Short error of a failing kernel key refresh; empty when none fails.
	DisclosureHeldSince *int64 `json:"disclosure_held_since"` // When an installed key started holding disclosure back; null when not held.
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
