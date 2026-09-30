// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connectivity"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type reflectionReceipt struct {
	nonce    []byte
	address  string
	observed time.Time
}

func emptyConnectivity() *wire.Connectivity {
	return &wire.Connectivity{SchemaVersion: 1, IPv4: untested("not_configured"), IPv6: untested("not_configured"), TCPListener: untested("not_configured"), UDPListener: untested("not_configured"), SCIONListener: untested("no_controlled_peer"), SCIONPaths: untested("not_configured"), Disagreements: []string{}}
}

func initialConnectivity(report *pb.ConnectivityReport) *wire.Connectivity {
	if report == nil {
		return nil
	}
	out := emptyConnectivity()
	if report.GetIpv4().GetReason() != "not_configured" {
		out.IPv4 = untested("pending")
	}
	if report.GetIpv6().GetReason() != "not_configured" {
		out.IPv6 = untested("pending")
	}
	if report.ListenersEnabled {
		out.TCPListener, out.UDPListener = untested("pending"), untested("pending")
	}
	return out
}

func connectivitySCION(previous *wire.Connectivity, report *vantageReport, at time.Time) *wire.Connectivity {
	if previous == nil && (report == nil || report.scionHost == "" && report.scionPaths == nil) {
		return nil
	}
	out := wire.CloneConnectivity(previous, time.Time{}, true)
	if out == nil {
		out = emptyConnectivity()
	}
	out.SCIONHost, out.SCIONPaths = wire.ObservedString{}, untested("not_configured")
	if report == nil {
		return out
	}
	if report.scionHost != "" {
		host, source, observed := report.scionHost, wire.SourceExecutorReported, at.Unix()
		out.SCIONHost = wire.ObservedString{Value: &host, Source: &source, ObservedAt: &observed}
	}
	if report.scionPaths != nil {
		state := "unreachable"
		if report.scionPaths.State == "available" {
			state = "reachable"
		}
		out.SCIONPaths = observedReachability(state, report.scionPaths.Reason, wire.SourceExecutorReported, at)
		out.SCIONPaths.Endpoint = report.scionPathTarget
	}
	return out
}

// OnReflectAddress records only the authenticated transport's actual peer IP.
// Two slots, one per family, bound storage and tie proof to the current owner.
func (d *Dispatcher) OnReflectAddress(ctx context.Context, mutation *rpc.Mutation, req *pb.ReflectAddressRequest, address string) (*pb.ReflectAddressResponse, error) {
	owner, err := requireMutation(mutation, req.GetExecutorId())
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || len(req.GetNonce()) != connectivity.TokenSize {
		return nil, status.Error(codes.InvalidArgument, "invalid reflection request")
	}
	index := 1
	if ip.Is4() {
		index = 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	entry := d.executors[owner.ExecutorID()]
	if d.closed || entry == nil || entry.owner != owner || ctx.Err() != nil {
		return nil, status.Error(codes.FailedPrecondition, "executor session unavailable")
	}
	entry.reflections[index] = reflectionReceipt{nonce: bytes.Clone(req.Nonce), address: ip.String(), observed: d.now()}
	return &pb.ReflectAddressResponse{Address: ip.String()}, nil
}

func untested(reason string) wire.Reachability {
	return wire.Reachability{State: "untested", Reason: reason}
}
func observedReachability(state, reason, source string, at time.Time) wire.Reachability {
	observed, expiry := at.Unix(), at.Add(capabilityLifetime).Unix()
	return wire.Reachability{State: state, Reason: reason, Source: source, ObservedAt: &observed, ExpiresAt: &expiry}
}

func egressObservation(test *pb.EgressTest, receipt reflectionReceipt, now time.Time) wire.Reachability {
	if test == nil {
		return untested("unknown")
	}
	if test.State == "untested" && test.Reason == "not_configured" {
		return untested("not_configured")
	}
	if test.State == "untested" && test.Reason == "pending" {
		return untested("pending")
	}
	if test.State == "unreachable" && test.Reason == "reflector_failed" {
		return observedReachability("unreachable", "reflector_failed", wire.SourceExecutorReported, now)
	}
	if test.State != "reachable" || test.Reason != "" || len(test.Nonce) != connectivity.TokenSize || !bytes.Equal(test.Nonce, receipt.nonce) || vantageExpired(receipt.observed, now) {
		return untested("unconfirmed")
	}
	out := observedReachability("reachable", "", wire.SourceDispatcherObserved, receipt.observed)
	out.Address = receipt.address
	return out
}

// observeConnectivity runs outside registry locks and within the heartbeat's
// admitted mutation. Only locally configured host/ports may receive a packet.
func (d *Dispatcher) observeConnectivity(ctx context.Context, owner *rpc.SessionOwner, report *pb.ConnectivityReport, now time.Time) *wire.Connectivity {
	if report == nil {
		return nil
	}
	d.mu.Lock()
	entry := d.executors[owner.ExecutorID()]
	if d.closed || entry == nil || entry.owner != owner || now.Before(entry.connectivityNext) {
		d.mu.Unlock()
		return nil
	}
	entry.connectivityNext = now.Add(30 * time.Second)
	target, receipts, advertised, source := entry.display, entry.reflections, entry.PublicHost(), entry.sourceIp
	d.mu.Unlock()
	out := &wire.Connectivity{SchemaVersion: 1, IPv4: egressObservation(report.Ipv4, receipts[0], now), IPv6: egressObservation(report.Ipv6, receipts[1], now),
		TCPListener: untested("not_configured"), UDPListener: untested("not_configured"), SCIONListener: untested("no_controlled_peer"), SCIONPaths: untested("not_configured"), Disagreements: []string{}}
	for _, family := range []struct {
		name        string
		observation wire.Reachability
	}{{"ipv4", out.IPv4}, {"ipv6", out.IPv6}} {
		if family.observation.Address == "" {
			continue
		}
		for _, claim := range []struct{ name, value string }{{"public_host", advertised}, {"control_source", source}} {
			ip, err := netip.ParseAddr(claim.value)
			actual, _ := netip.ParseAddr(family.observation.Address)
			if err == nil && ip.Unmap().Is4() == actual.Is4() && ip.Unmap() != actual {
				out.Disagreements = append(out.Disagreements, family.name+"_differs_from_"+claim.name)
			}
		}
	}
	if !report.ListenersEnabled {
		return out
	}
	out.TCPListener, out.UDPListener = untested("no_challenge"), untested("no_challenge")
	for _, item := range []struct {
		reason      string
		observation *wire.Reachability
	}{{report.TcpReason, &out.TCPListener}, {report.UdpReason, &out.UDPListener}} {
		if item.reason == "disabled" {
			*item.observation = untested("disabled")
		}
		if item.reason == "bind_failed" {
			*item.observation = observedReachability("unreachable", "bind_failed", wire.SourceExecutorReported, now)
		}
	}
	if len(report.Listeners) > 2 {
		out.TCPListener, out.UDPListener = untested("invalid_report"), untested("invalid_report")
		return out
	}
	seen := []string{}
	var wg sync.WaitGroup
	for _, probe := range report.Listeners {
		if probe == nil || (probe.Transport != "tcp" && probe.Transport != "udp") || slices.Contains(seen, probe.Transport) || len(probe.Token) != connectivity.TokenSize {
			wg.Wait()
			out.TCPListener, out.UDPListener = untested("invalid_report"), untested("invalid_report")
			return out
		}
		seen = append(seen, probe.Transport)
		result := &out.TCPListener
		if probe.Transport == "udp" {
			result = &out.UDPListener
		}
		endpoint, allowed := target.ConnectivityTarget(probe.Port)
		if !allowed {
			*result = untested("unapproved_target")
			continue
		}
		advertisedIP, err := netip.ParseAddr(advertised)
		if err != nil || advertisedIP.Unmap() != endpoint.Addr() {
			*result = untested("advertised_host_mismatch")
			out.Disagreements = append(out.Disagreements, probe.Transport+"_target_differs_from_public_host")
			continue
		}
		wg.Add(1)
		go func(probe *pb.ListenerChallenge, result *wire.Reachability) {
			defer wg.Done()
			err := connectivity.Check(ctx, probe.Transport, endpoint.String(), probe.Token)
			state, reason := "reachable", ""
			if err != nil {
				state, reason = "unreachable", "challenge_failed"
			}
			*result = observedReachability(state, reason, wire.SourceDispatcherObserved, now)
			result.Endpoint = endpoint.String()
		}(probe, result)
	}
	wg.Wait()
	return out
}

// Connectivity returns detached, explicitly stale observations. The API uses
// private=false except for an established operator; results retain full facts.
func (e *RegisteredExecutor) Connectivity(private bool) *wire.Connectivity {
	return wire.CloneConnectivity(e.connectivity, time.Time{}, private)
}

func (e *RegisteredExecutor) CapabilityObservation() *wire.CapabilityObservation {
	if e.capabilityObservation == nil {
		return &wire.CapabilityObservation{State: "unknown"}
	}
	out := *e.capabilityObservation
	if out.ObservedAt != nil {
		value := *out.ObservedAt
		out.ObservedAt = &value
	}
	if out.ExpiresAt != nil {
		value := *out.ExpiresAt
		out.ExpiresAt = &value
	}
	return &out
}
