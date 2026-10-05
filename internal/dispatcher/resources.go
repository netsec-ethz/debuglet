// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"github.com/netsec-ethz/debuglet/internal/observability"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"math"
)

// Resource observations are optional and operator-only. Invalid fields become
// unknown independently, without publishing arbitrary peer-supplied reasons.
func resourcesFromReport(report *pb.HostResources) *observability.HostSnapshot {
	if report == nil {
		return nil
	}
	value := func(v *pb.HostResourceValue, limit uint64) observability.HostValue {
		unknown := observability.HostValue{Unavailable: "invalid"}
		if v == nil {
			return observability.HostValue{Unavailable: "missing"}
		}
		if v.Value != nil {
			if v.Unavailable != "" || *v.Value > limit {
				return unknown
			}
			n := *v.Value
			return observability.HostValue{Value: &n}
		}
		switch v.Unavailable {
		case "missing", "permission", "read", "limit", "invalid", "unsupported":
			return observability.HostValue{Unavailable: v.Unavailable}
		}
		return unknown
	}
	out := &observability.HostSnapshot{ProcessRSSBytes: value(report.ProcessRssBytes, math.MaxInt64),
		OpenFDs: value(report.OpenFds, 65536), StateAvailableBytes: value(report.StateAvailableBytes, math.MaxInt64),
		StateCapacityBytes: value(report.StateCapacityBytes, math.MaxInt64)}
	if out.StateAvailableBytes.Value != nil && out.StateCapacityBytes.Value != nil &&
		(*out.StateCapacityBytes.Value == 0 || *out.StateAvailableBytes.Value > *out.StateCapacityBytes.Value) {
		out.StateAvailableBytes, out.StateCapacityBytes = observability.HostValue{Unavailable: "invalid"}, observability.HostValue{Unavailable: "invalid"}
	}
	return out
}
