// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet/addrutil"
)

// A heartbeat may run much faster than this interval for TESLA disclosure. Send
// only newly collected observations; resending a cached positive would renew its
// dispatcher expiry without probing whether it is still available. A changed
// attribution reason is sent on the next heartbeat regardless, so a failing key
// refresh is not advertised as available until the interval ends. Both reports
// come from the same probe and are sent, or omitted, together.
func (e *Executor) capabilityReport(ctx context.Context, initial bool) (*pb.ExecutorCapabilities, *pb.VantagePointReport) {
	now := time.Now()
	attribution := attributionReport(e.teslaSchedule, now)
	e.capabilityMu.Lock()
	if !initial && now.Before(e.capabilityNext) && attribution.GetReason() == e.capabilityReason {
		e.capabilityMu.Unlock()
		return nil, nil
	}
	e.capabilityNext = now.Add(30 * time.Second)
	e.capabilityReason = attribution.GetReason()
	e.capabilityMu.Unlock()

	report := &pb.ExecutorCapabilities{SchemaVersion: 1, Attribution: attribution}
	vantage := &pb.VantagePointReport{SchemaVersion: 1}
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
	// TCP and UDP listeners need the inbound switch, the transport and both
	// public_host and public_ports; the address itself is not reported here.
	inbound := policy.Inbound && e.portManager.Enabled()
	if inbound && policy.TCP {
		vantage.Listeners = append(vantage.Listeners, "tcp")
	}
	if inbound && policy.UDP {
		vantage.Listeners = append(vantage.Listeners, "udp")
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
		ia, available := scionProbe(probeCtx)
		cancel()
		if !ia.IsWildcard() {
			vantage.ScionIsdAs = ia.String()
		}
		if available {
			report.Protocols = append(report.Protocols, "scion")
			if policy.Inbound {
				vantage.Listeners = append(vantage.Listeners, "scion")
			}
		}
	}
	return report, vantage
}

// maxRefreshError bounds the refresh error text a report carries; the
// dispatcher refuses a longer one.
const maxRefreshError = 128

// attributionReport converts the schedule's state into the report. A refresh
// error is cut to maxRefreshError bytes on a rune boundary; the executor log
// keeps the full text. Nil without a schedule, which leaves attribution unknown.
func attributionReport(schedule *tesla.KeySchedule, now time.Time) *pb.AttributionState {
	if schedule == nil {
		return nil
	}
	a := schedule.Attribution(now)
	out := &pb.AttributionState{State: "available", Reason: a.Reason, Epoch: a.Epoch}
	if a.Reason != "" {
		out.State = "unavailable"
	}
	if a.Installed {
		out.InstalledEpoch = &a.InstalledEpoch
	}
	if !a.LastInstall.IsZero() {
		age := max(now.Sub(a.LastInstall), 0).Milliseconds()
		out.LastRefreshAgeMs = &age
	}
	if a.RefreshErr != nil {
		text := strings.ToValidUTF8(a.RefreshErr.Error(), "?")
		for len(text) > maxRefreshError {
			_, size := utf8.DecodeLastRuneInString(text)
			text = text[:len(text)-size]
		}
		if text == "" {
			text = "unknown error"
		}
		out.RefreshError = text
	}
	if !a.HeldSince.IsZero() {
		held := max(now.Sub(a.HeldSince), 0).Milliseconds()
		out.DisclosureHeldMs = &held
	}
	return out
}

// Probe the configured daemon and local route only. The execution helper also
// accepts hostnames, but its DNS resolution is not context bounded. Such names
// therefore remain unknown to discovery; this probe never resolves or sends a
// packet to a destination. No runtime lock is held while probing. The local
// ISD-AS is returned whenever the daemon names one, even if no local route to
// its control service is found.
func scionProbe(ctx context.Context) (addr.IA, bool) {
	target := os.Getenv("SCION_DAEMON_ADDRESS")
	endpoint, err := netip.ParseAddrPort(target)
	if err != nil || endpoint.Port() == 0 {
		return 0, false
	}
	connector, err := daemon.NewService(target).Connect(ctx)
	if err != nil {
		return 0, false
	}
	defer connector.Close()
	info, err := connector.ASInfo(ctx, 0)
	if err != nil || info.IA == 0 {
		return 0, false
	}
	services, err := connector.SVCInfo(ctx, []addr.SVC{addr.SvcCS})
	if err != nil {
		return info.IA, false
	}
	for _, service := range services[addr.SvcCS] {
		if ctx.Err() != nil {
			return info.IA, false
		}
		endpoint, err := netip.ParseAddrPort(service)
		if err == nil && endpoint.Port() != 0 {
			if _, err := addrutil.ResolveLocal(net.IP(endpoint.Addr().AsSlice())); err == nil {
				return info.IA, true
			}
		}
	}
	return info.IA, false
}
