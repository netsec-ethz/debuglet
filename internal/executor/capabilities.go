// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet/addrutil"
)

// A heartbeat may run much faster than this interval for TESLA disclosure. Send
// only newly collected observations; resending a cached positive would renew its
// dispatcher expiry without probing whether it is still available.
func (e *Executor) capabilityReport(ctx context.Context, initial bool) *pb.ExecutorCapabilities {
	now := time.Now()
	e.capabilityMu.Lock()
	if !initial && now.Before(e.capabilityNext) {
		e.capabilityMu.Unlock()
		return nil
	}
	e.capabilityNext = now.Add(30 * time.Second)
	e.capabilityMu.Unlock()

	report := &pb.ExecutorCapabilities{SchemaVersion: 1}
	policy := e.cfg.Network.Policy.Spec()
	for _, transport := range []struct {
		name    string
		enabled bool
	}{
		{"tcp", policy.TCP}, {"tls", policy.TLS}, {"udp", policy.UDP},
		{"icmp", policy.ICMP && netpolicy.ICMPPermitted() == nil},
	} {
		if transport.enabled {
			report.Protocols = append(report.Protocols, transport.name)
		}
	}
	if e.packetCount != nil {
		switch mode := e.packetCount.Type(); mode {
		case "ebpf", "fallback":
			report.EnforcementMode = mode
		}
	}
	if policy.SCION {
		budget := 100 * time.Millisecond
		if initial {
			budget = 500 * time.Millisecond
		}
		probeCtx, cancel := context.WithTimeout(ctx, budget)
		if scionAvailable(probeCtx) {
			report.Protocols = append(report.Protocols, "scion")
		}
		cancel()
	}
	return report
}

// Probe the configured daemon and local route only. The execution helper also
// accepts hostnames, but its DNS resolution is not context bounded. Such names
// therefore remain unknown to discovery; this probe never resolves or sends a
// packet to a destination. No runtime lock is held while probing.
func scionAvailable(ctx context.Context) bool {
	target := os.Getenv("SCION_DAEMON_ADDRESS")
	endpoint, err := netip.ParseAddrPort(target)
	if err != nil || endpoint.Port() == 0 {
		return false
	}
	connector, err := daemon.NewService(target).Connect(ctx)
	if err != nil {
		return false
	}
	defer connector.Close()
	info, err := connector.ASInfo(ctx, 0)
	if err != nil || info.IA == 0 {
		return false
	}
	services, err := connector.SVCInfo(ctx, []addr.SVC{addr.SvcCS})
	if err != nil {
		return false
	}
	for _, service := range services[addr.SvcCS] {
		if ctx.Err() != nil {
			return false
		}
		endpoint, err := netip.ParseAddrPort(service)
		if err == nil && endpoint.Port() != 0 {
			if _, err := addrutil.ResolveLocal(net.IP(endpoint.Addr().AsSlice())); err == nil {
				return true
			}
		}
	}
	return false
}
