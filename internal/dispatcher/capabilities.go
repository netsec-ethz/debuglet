// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
	out := &wire.ExecutorCapabilities{SchemaVersion: 1, ObservedAt: observed.Unix(),
		Protocols: protocols, EnforcementMode: report.GetEnforcementMode()}
	if report.Attribution != nil {
		out.Attribution = attributionFromReport(report.Attribution, observed)
	}
	return out
}

// Attribution report bounds. An age beyond maxReportedAge cannot come from a
// schedule this build creates and would overflow the derived times.
const (
	maxRefreshError = 128
	maxReportedAge  = 10 * 365 * 24 * time.Hour
)

// attributionFromReport validates the attribution state and converts its ages
// to times on the dispatcher's clock. Nil means malformed, which leaves
// attribution unknown, as for an executor that predates it, while the rest of
// the report stands: null never claims availability, and a bad attribution
// field must not hide the node's protocols from discovery. The reason must
// agree with the facts it names, so an unavailable report always says why.
func attributionFromReport(report *pb.AttributionState, observed time.Time) *wire.AttributionState {
	switch report.GetState() {
	case "available":
		if report.GetReason() != "" {
			return nil
		}
	case "unavailable":
		switch report.GetReason() {
		case "epoch_zero", "chain_exhausted", "refresh_failing", "disclosure_held":
		default:
			return nil
		}
	default:
		return nil
	}
	epoch := report.GetEpoch()
	if epoch < 0 || (report.InstalledEpoch != nil && (*report.InstalledEpoch < 0 || *report.InstalledEpoch > epoch)) {
		return nil
	}
	refreshError := report.GetRefreshError()
	if len(refreshError) > maxRefreshError || !utf8.ValidString(refreshError) ||
		strings.ContainsFunc(refreshError, unicode.IsControl) {
		return nil
	}
	if (report.GetReason() == "refresh_failing" && refreshError == "") ||
		(report.GetReason() == "disclosure_held" && report.DisclosureHeldMs == nil) {
		return nil
	}
	at := func(age *int64) (*int64, bool) {
		if age == nil {
			return nil, true
		}
		if *age < 0 || *age > maxReportedAge.Milliseconds() {
			return nil, false
		}
		unix := observed.Add(-time.Duration(*age) * time.Millisecond).Unix()
		return &unix, true
	}
	lastRefresh, ok := at(report.LastRefreshAgeMs)
	if !ok {
		return nil
	}
	heldSince, ok := at(report.DisclosureHeldMs)
	if !ok {
		return nil
	}
	out := &wire.AttributionState{State: report.GetState(), Reason: report.GetReason(), Epoch: epoch,
		LastRefreshAt: lastRefresh, RefreshError: refreshError, DisclosureHeldSince: heldSince}
	if report.InstalledEpoch != nil {
		installed := *report.InstalledEpoch
		out.InstalledEpoch = &installed
	}
	return out
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
	if out.Attribution != nil {
		attribution := *out.Attribution
		out.Attribution = &attribution
	}
	if len(out.Protocols) == 0 {
		out.Protocols = []string{}
	}
	if capacity := int64(entry.capacity); capacity > 0 && bitrate.InPolicyRange(capacity) {
		out.AdvertisedCapacityBPS = &capacity
	}
	return &out
}
