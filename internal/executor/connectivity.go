// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"crypto/rand"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connectivity"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func (e *Executor) initialConnectivityReport() *pb.ConnectivityReport {
	test := func(endpoint string) *pb.EgressTest {
		reason := "not_configured"
		if endpoint != "" {
			reason = "pending"
		}
		return &pb.EgressTest{State: "untested", Reason: reason}
	}
	return &pb.ConnectivityReport{Ipv4: test(e.cfg.Connectivity.IPv4Reflector), Ipv6: test(e.cfg.Connectivity.IPv6Reflector), ListenersEnabled: e.cfg.Connectivity.Listeners}
}

// probeConnectivity is called only by the serialized heartbeat loop. The
// temporary listeners remain bound until the matching heartbeat returns, then
// finish joins their responders and releases their actual pool reservations.
func (e *Executor) probeConnectivity(ctx context.Context, binding controlsession.Binding, vantage *pb.VantagePointReport) func() {
	e.observeAddresses(ctx, binding)
	if vantage == nil {
		return func() {}
	}
	vantage.AddressCheck = e.addressSelfCheck()
	now := time.Now()
	e.capabilityMu.Lock()
	if now.Before(e.connectivityNext) {
		e.capabilityMu.Unlock()
		return func() {}
	}
	e.connectivityNext = now.Add(30 * time.Second)
	e.capabilityMu.Unlock()
	cfg := e.cfg.Connectivity
	report := &pb.ConnectivityReport{ListenersEnabled: cfg.Listeners}
	vantage.Connectivity = report
	var wg sync.WaitGroup
	for _, item := range []struct {
		endpoint string
		output   **pb.EgressTest
	}{{cfg.IPv4Reflector, &report.Ipv4}, {cfg.IPv6Reflector, &report.Ipv6}} {
		wg.Add(1)
		go func(endpoint string, output **pb.EgressTest) {
			defer wg.Done()
			*output = &pb.EgressTest{State: "untested", Reason: "not_configured"}
			if endpoint == "" {
				return
			}
			*output = &pb.EgressTest{State: "unreachable", Reason: "reflector_failed"}
			if e.Bidi == nil {
				return
			}
			nonce := make([]byte, connectivity.TokenSize)
			if _, err := rand.Read(nonce); err != nil {
				return
			}
			callCtx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
			defer cancel()
			response, err := e.Bidi.ReflectAddress(callCtx, binding, endpoint, &pb.ReflectAddressRequest{ExecutorId: e.cfg.Identity.ExecutorID, Nonce: nonce})
			if err != nil {
				return
			}
			ip, err := netip.ParseAddr(response.GetAddress())
			target, targetErr := netip.ParseAddrPort(endpoint)
			if err != nil || targetErr != nil || ip.Is4() != target.Addr().Is4() {
				return
			}
			*output = &pb.EgressTest{State: "reachable", Nonce: nonce}
		}(item.endpoint, item.output)
	}
	wg.Wait()
	stops := []func(){}
	if cfg.Listeners {
		for _, transport := range []string{"tcp", "udp"} {
			reason := &report.TcpReason
			if transport == "udp" {
				reason = &report.UdpReason
			}
			*reason = "disabled"
			if !slices.Contains(vantage.Listeners, transport) {
				continue
			}
			*reason = "bind_failed"
			token := make([]byte, connectivity.TokenSize)
			if _, err := rand.Read(token); err != nil {
				continue
			}
			var port int
			var stop func()
			if transport == "tcp" {
				listener, allocated, _, err := e.portManager.ListenTCP(nil)
				if err != nil {
					continue
				}
				port, stop = allocated, connectivity.ServeTCP(listener, token)
			} else {
				conn, allocated, _, err := e.portManager.ListenUDP(nil)
				if err != nil {
					continue
				}
				port, stop = allocated, connectivity.ServeUDP(conn, token)
			}
			*reason = ""
			report.Listeners = append(report.Listeners, &pb.ListenerChallenge{Transport: transport, Port: uint32(port), Token: token})
			stops = append(stops, func() { stop(); e.portManager.Release(port) })
		}
	}
	return func() {
		for _, stop := range stops {
			stop()
		}
	}
}
