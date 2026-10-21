// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"time"
)

type TLSInfo = guestio.TLSInfo
type TLSCertificate = guestio.TLSCertificate
type HopReply = guestio.HopReply

// InspectTLS opens and verifies one TLS connection, reports public certificate
// and negotiation metadata, and closes it. Timeout includes resolution and TCP
// establishment. Zero uses the run's remaining lifetime. Requires tls_inspect.
func InspectTLS(address string, timeout time.Duration) (TLSInfo, error) {
	if address == "" {
		return TLSInfo{}, fmt.Errorf("empty TLS address")
	}
	return inspectTLS(address, timeout)
}

// ProbeHop sends one IPv4 ICMP echo with the requested TTL. It reports only a
// matching echo response or ICMP error quoting that probe. Requires hop_probe,
// ICMP permission and raw-socket support. Zero timeout uses the run lifetime.
func ProbeHop(address string, ttl int, timeout time.Duration) (HopReply, error) {
	if address == "" || ttl < 1 || ttl > 255 {
		return HopReply{}, fmt.Errorf("hop probe needs a target and TTL from 1 to 255")
	}
	return probeHop(address, uint32(ttl), timeout)
}
