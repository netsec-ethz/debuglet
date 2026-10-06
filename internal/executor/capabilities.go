// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"github.com/netsec-ethz/debuglet/internal/hostprobe"
	"github.com/netsec-ethz/debuglet/internal/observability"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	"go.uber.org/zap"
)

// A heartbeat may run much faster than this interval for TESLA disclosure. Send
// only newly collected observations; resending a cached positive would renew its
// dispatcher expiry without probing whether it is still available. A changed
// attribution reason is sent on the next heartbeat regardless, so a failing key
// refresh is not advertised as available until the interval ends. A changed
// tagging mode is likewise sent on the next heartbeat. Both reports come from
// the same probe and are sent, or omitted, together.
func (e *Executor) capabilityReport(ctx context.Context, initial bool) (*pb.ExecutorCapabilities, *pb.VantagePointReport) {
	now := time.Now()
	attribution := attributionReport(e.teslaSchedule, now)
	tagging := e.tagging()
	e.capabilityMu.Lock()
	if !initial && now.Before(e.capabilityNext) && attribution.GetReason() == e.capabilityReason && tagging == e.capabilityTagging {
		e.capabilityMu.Unlock()
		return nil, nil
	}
	e.capabilityNext = now.Add(30 * time.Second)
	e.capabilityReason = attribution.GetReason()
	e.capabilityMu.Unlock()

	policy := e.cfg.Network.Policy.Spec()
	icmp := icmpReport(policy.ICMP, netpolicy.RefreshICMP)
	// The userspace tagger needs the same raw sockets, so the tagging mode is
	// read again after the probe refreshed that answer; otherwise one report
	// could carry a fresh ICMP state beside a tagging mode from the last one.
	tagging = e.tagging()
	e.capabilityMu.Lock()
	e.capabilityTagging = tagging
	e.capabilityMu.Unlock()

	report := &pb.ExecutorCapabilities{SchemaVersion: 1, Attribution: attribution, Icmp: icmp,
		Tagging: &pb.TaggingMode{Ipv4: tagging.IPv4, Ipv6: tagging.IPv6, Scion: tagging.SCION, TagSpec: tesla.TagSpec}}
	vantage := &pb.VantagePointReport{SchemaVersion: 1, LocationOptOut: e.cfg.Metadata.LocationOptOut, AddressOptOut: e.cfg.Metadata.AddressOptOut, Clock: e.clockReport(), Platform: platformReport(hostprobe.ReadPlatform())}
	stateDir := ""
	if e.cfg.Database.Path != "" {
		stateDir = filepath.Dir(e.cfg.Database.Path)
	}
	vantage.Resources = hostResources(observability.CollectHost(stateDir))
	vantage.CounterAttachment = "unknown"
	if counter, ok := e.packetCount.(interface{ AttachmentState() string }); ok {
		vantage.CounterAttachment = counter.AttachmentState()
	}
	if initial {
		vantage.Connectivity = e.initialConnectivityReport()
	}
	for _, transport := range []struct {
		name    string
		enabled bool
	}{
		{"tcp", policy.TCP}, {"tls", policy.TLS}, {"udp", policy.UDP},
		{"icmp", report.Icmp.GetState() == "available"},
	} {
		if transport.enabled {
			report.Protocols = append(report.Protocols, transport.name)
		}
	}
	// TCP and UDP listeners need the inbound switch, the transport and both
	// public_host and public_ports; the address itself is not reported here.
	// A node whose runs refuse IPv6 cannot offer them under an IPv6 public
	// host: the run refuses such a listener.
	inbound := policy.Inbound && e.portManager.Enabled() &&
		!(tagging.RefusesIPv6() && debuglet.IPv6PublicHost(e.portManager.PublicHost()))
	if inbound && policy.TCP {
		vantage.Listeners = append(vantage.Listeners, "tcp")
	}
	if inbound && policy.UDP {
		vantage.Listeners = append(vantage.Listeners, "udp")
	}
	if e.packetCount != nil {
		switch mode := e.packetCount.Type(); mode {
		case "ebpf":
			report.EnforcementMode = mode
		case "fallback":
			report.EnforcementMode = mode
			report.EnforcementReason = ratelimit.FallbackReason(e.packetCount)
			if e.cfg.Network.PacketCounter == "fallback" {
				report.EnforcementReason = ratelimit.FallbackConfigured
			}
		}
	}
	if policy.SCION {
		budget := 100 * time.Millisecond
		if initial {
			budget = 500 * time.Millisecond
		}
		probeCtx, cancel := context.WithTimeout(ctx, budget)
		ia, host, paths := scionDetails(probeCtx, e.cfg.Connectivity.SCIONPathTarget)
		available := host != ""
		vantage.ScionHost, vantage.ScionPaths = host, paths
		vantage.ScionPathTarget = e.cfg.Connectivity.SCIONPathTarget
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

func hostResources(host observability.HostSnapshot) *pb.HostResources {
	value := func(v observability.HostValue) *pb.HostResourceValue {
		return &pb.HostResourceValue{Value: v.Value, Unavailable: v.Unavailable}
	}
	return &pb.HostResources{ProcessRssBytes: value(host.ProcessRSSBytes), OpenFds: value(host.OpenFDs),
		StateAvailableBytes: value(host.StateAvailableBytes), StateCapacityBytes: value(host.StateCapacityBytes)}
}

// icmpReport probes raw ICMPv4 sockets unless the operator switched ICMP off,
// in which case no socket is opened. The probe also refreshes the answer guest
// admission uses.
func icmpReport(enabled bool, probe func() (string, error)) *pb.ProbeState {
	if !enabled {
		return &pb.ProbeState{State: "unavailable", Reason: netpolicy.ICMPDisabled}
	}
	if reason, err := probe(); err != nil {
		if reason == "" {
			reason = netpolicy.ICMPUnsupported
		}
		return &pb.ProbeState{State: "unavailable", Reason: reason}
	}
	return &pb.ProbeState{State: "available"}
}

// clockReport reads the kernel clock against the configured bound and logs a
// change of its degraded reason once.
func (e *Executor) clockReport() *pb.ClockState {
	c := hostprobe.ReadClock(e.cfg.Clock.MaxErrorBound())
	e.capabilityMu.Lock()
	changed := c.Reason != e.clockReason
	e.clockReason = c.Reason
	e.capabilityMu.Unlock()
	if changed && e.logger != nil {
		if c.Reason != "" {
			e.logger.Warn("Clock readiness degraded", zap.String("reason", c.Reason), zap.String("state", c.State), zap.Duration("bound", c.Bound))
		} else {
			e.logger.Info("Clock readiness restored", zap.String("state", c.State))
		}
	}
	return clockState(c)
}

func clockState(c hostprobe.Clock) *pb.ClockState {
	out := &pb.ClockState{State: c.State, ErrorBoundNs: c.Bound.Nanoseconds(), Readiness: c.Readiness, Reason: c.Reason}
	if c.EstimatedError != nil {
		ns := c.EstimatedError.Nanoseconds()
		out.EstimatedErrorNs = &ns
	}
	if c.MaxError != nil {
		ns := c.MaxError.Nanoseconds()
		out.MaxErrorNs = &ns
	}
	return out
}

func platformReport(p hostprobe.Platform) *pb.HostPlatform {
	out := &pb.HostPlatform{Os: p.OS, Arch: p.Arch, KernelRelease: p.KernelRelease, BuildVersion: p.BuildVersion}
	if p.CPUs > 0 && p.CPUs <= math.MaxUint32 {
		out.Cpus = uint32(p.CPUs)
	}
	if p.MemoryBytes > 0 {
		memory := p.MemoryBytes
		out.MemoryBytes = &memory
	}
	return out
}

// tagging is this node's tagging capability: the mode a run on it is set up
// to get, which depends on the node (interface, eBPF counter, raw-socket
// permission) and not on any one run. It does not follow individual runs, so
// the capability snapshot a result keeps from admission describes the node,
// never a previous run. A run whose kernel tagger then fails to load falls
// back to the pure-Go tagger and logs so; that per-run fallback is not
// reported.
func (e *Executor) tagging() tagger.Mode {
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
// packet to a destination. No runtime lock is held while probing. The local
// ISD-AS is returned whenever the daemon names one, even if no local route to
// its control service is found.
func scionProbe(ctx context.Context) (addr.IA, bool) {
	ia, host, _ := scionDetails(ctx, "")
	return ia, host != ""
}

func scionDetails(ctx context.Context, remote string) (addr.IA, string, *pb.ProbeState) {
	var failed *pb.ProbeState
	if remote != "" {
		failed = &pb.ProbeState{State: "unavailable", Reason: "daemon_failed"}
	}
	target := os.Getenv("SCION_DAEMON_ADDRESS")
	endpoint, err := netip.ParseAddrPort(target)
	if err != nil || endpoint.Port() == 0 {
		return 0, "", failed
	}
	connector, err := daemon.NewService(target).Connect(ctx)
	if err != nil {
		return 0, "", failed
	}
	defer connector.Close()
	info, err := connector.ASInfo(ctx, 0)
	if err != nil || info.IA.IsWildcard() {
		return 0, "", failed
	}
	var host string
	services, err := connector.SVCInfo(ctx, []addr.SVC{addr.SvcCS})
	if err == nil {
		for _, service := range services[addr.SvcCS] {
			if ctx.Err() != nil {
				break
			}
			endpoint, err := netip.ParseAddrPort(service)
			if err != nil || endpoint.Port() == 0 {
				continue
			}
			if local, err := addrutil.ResolveLocal(net.IP(endpoint.Addr().AsSlice())); err == nil {
				host = local.String()
				break
			}
		}
	}
	if remote == "" {
		return info.IA, host, nil
	}
	destination, err := addr.ParseIA(remote)
	if err != nil || destination.IsWildcard() || destination == info.IA {
		return info.IA, host, &pb.ProbeState{State: "unavailable", Reason: "invalid_target"}
	}
	paths, err := connector.Paths(ctx, destination, info.IA, daemon.PathReqFlags{})
	if err != nil {
		return info.IA, host, &pb.ProbeState{State: "unavailable", Reason: "daemon_failed"}
	}
	for _, path := range paths {
		if path.Source() == info.IA && path.Destination() == destination && path.Metadata() != nil && len(path.Metadata().Interfaces) > 0 && path.Metadata().Expiry.After(time.Now()) {
			return info.IA, host, &pb.ProbeState{State: "available"}
		}
	}
	return info.IA, host, &pb.ProbeState{State: "unavailable", Reason: "no_path"}
}
