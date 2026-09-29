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

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
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
// refresh is not advertised as available until the interval ends. A changed
// tagging mode is likewise sent on the next heartbeat.
func (e *Executor) capabilityReport(ctx context.Context, initial bool) *pb.ExecutorCapabilities {
	now := time.Now()
	attribution := attributionReport(e.teslaSchedule, now)
	tagging := e.tagging()
	e.capabilityMu.Lock()
	if !initial && now.Before(e.capabilityNext) && attribution.GetReason() == e.capabilityReason && tagging == e.capabilityTagging {
		e.capabilityMu.Unlock()
		return nil
	}
	e.capabilityNext = now.Add(30 * time.Second)
	e.capabilityReason = attribution.GetReason()
	e.capabilityTagging = tagging
	e.capabilityMu.Unlock()

	report := &pb.ExecutorCapabilities{SchemaVersion: 1, Attribution: attribution,
		Tagging: &pb.TaggingMode{Ipv4: tagging.IPv4, Ipv6: tagging.IPv6, Scion: tagging.SCION}}
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

// tagging is the mode of this session's latest run, or before any run the
// mode a run on this node is set up to get.
func (e *Executor) tagging() tagger.Mode {
	if mode := e.lastTagging.Load(); mode != nil {
		return *mode
	}
	counter := ""
	if e.packetCount != nil {
		counter = e.packetCount.Type()
	}
	return debuglet.ExpectedTagging(e.iface, counter)
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
