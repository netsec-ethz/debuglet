// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"slices"
	"time"

	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

const capabilityLifetime = 90 * time.Second

// Unknown or malformed reports clear the observation. The schema has five
// protocol names; accepting arbitrary strings would make filters misleading.
func capabilitiesFromReport(report *pb.ExecutorCapabilities, observed time.Time) *wire.ExecutorCapabilities {
	if report.GetSchemaVersion() != 1 || len(report.GetProtocols()) > 5 {
		return nil
	}
	if mode := report.GetEnforcementMode(); mode != "" && mode != "ebpf" && mode != "fallback" {
		return nil
	}
	protocols := make([]string, 0, len(report.GetProtocols()))
	for _, protocol := range report.GetProtocols() {
		switch protocol {
		case "tcp", "tls", "udp", "icmp", "scion":
		default:
			return nil
		}
		if slices.Contains(protocols, protocol) {
			return nil
		}
		protocols = append(protocols, protocol)
	}
	return &wire.ExecutorCapabilities{SchemaVersion: 1, ObservedAt: observed.Unix(),
		Protocols: protocols, EnforcementMode: report.GetEnforcementMode()}
}

// Caller holds the registry lock. Unlike capabilitySnapshot this keeps a report
// past its lifetime and says it was stale, because a result records what the
// dispatcher knew at admission rather than filtering on it.
func admissionCapabilities(entry *executorEntry, now time.Time) wire.VantageCapabilities {
	if entry.Capabilities == nil {
		return wire.VantageCapabilities{}
	}
	source, observed := wire.SourceExecutorReported, entry.capabilityObserved.UTC()
	stale := now.Before(entry.capabilityObserved) || now.Sub(entry.capabilityObserved) >= capabilityLifetime
	return wire.VantageCapabilities{
		Value: &wire.CapabilityReport{SchemaVersion: int(entry.Capabilities.SchemaVersion),
			Protocols: append([]string{}, entry.Capabilities.Protocols...), EnforcementMode: entry.Capabilities.EnforcementMode},
		Source: &source, ObservedAt: &observed, Stale: &stale,
	}
}

// Caller holds the registry lock. Capacity belongs to the current registration
// and remains a total advertisement before reservations and destination limits.
func capabilitySnapshot(entry *executorEntry, now time.Time) *wire.ExecutorCapabilities {
	if entry.Capabilities == nil || now.Before(entry.capabilityObserved) || now.Sub(entry.capabilityObserved) >= capabilityLifetime {
		return nil
	}
	out := *entry.Capabilities
	out.Protocols = slices.Clone(out.Protocols)
	if len(out.Protocols) == 0 {
		out.Protocols = []string{}
	}
	if capacity := int64(entry.capacity); capacity > 0 && bitrate.InPolicyRange(capacity) {
		out.AdvertisedCapacityBPS = &capacity
	}
	return &out
}
