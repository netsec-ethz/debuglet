// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package socket

import (
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

// DescribeSCIONPath copies public path metadata into the bounded guest result.
// MTU and interfaces are control-plane observations, not measurement results.
func DescribeSCIONPath(path *pan.Path) guestio.SCIONPath {
	if path == nil {
		return guestio.SCIONPath{ID: "local", Interfaces: []guestio.SCIONInterface{}}
	}
	result := guestio.SCIONPath{
		ID: SCIONPathID(path), Source: path.Source.String(), Destination: path.Destination.String(),
		Interfaces: []guestio.SCIONInterface{},
	}
	if !path.Expiry.IsZero() {
		result.ExpiresMS = path.Expiry.UnixMilli()
	}
	if path.Metadata != nil {
		result.MTU = path.Metadata.MTU
		result.HopCount = len(path.Metadata.Interfaces) / 2
		for _, iface := range path.Metadata.Interfaces {
			result.Interfaces = append(result.Interfaces, guestio.SCIONInterface{IA: iface.IA.String(), ID: uint64(iface.IfID)})
		}
	}
	return result
}
