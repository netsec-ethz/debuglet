// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

type capabilityDaemon struct {
	sdpb.UnimplementedDaemonServiceServer
	blocked atomic.Bool
	calls   atomic.Int32
}

func (d *capabilityDaemon) AS(ctx context.Context, _ *sdpb.ASRequest) (*sdpb.ASResponse, error) {
	d.calls.Add(1)
	if d.blocked.Load() {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	return &sdpb.ASResponse{IsdAs: 1, Mtu: 1500}, nil
}
func (*capabilityDaemon) Services(context.Context, *sdpb.ServicesRequest) (*sdpb.ServicesResponse, error) {
	return &sdpb.ServicesResponse{Services: map[string]*sdpb.ListService{"cs": {Services: []*sdpb.Service{{Uri: "127.0.0.1:30254"}}}}}, nil
}

func TestCapabilityReportsUseLocalRuntimeObservations(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	daemon := &capabilityDaemon{}
	server := grpc.NewServer()
	sdpb.RegisterDaemonServiceServer(server, daemon)
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); <-done })
	t.Setenv("SCION_DAEMON_ADDRESS", listener.Addr().String())
	enabled, disabled := true, false
	plainConfig, scionConfig := fixtureConfig(), fixtureConfig()
	plainConfig.Network.Policy.ICMP = &disabled
	scionConfig.Network.Policy.SCION = &enabled
	// Both acquire actual fallback counters; configuration alone is not the
	// source of the reported enforcement mode.
	plain := newFixtureExecutor(t, plainConfig, nil, newFixtureMemoryStorage(t))
	scion := newFixtureExecutor(t, scionConfig, nil, newFixtureMemoryStorage(t))
	p, _ := plain.OnHello(t.Context(), nil)
	s, _ := scion.OnHello(t.Context(), nil)
	if p.GetCapabilities().GetEnforcementMode() != "fallback" || s.GetCapabilities().GetEnforcementMode() != "fallback" {
		t.Fatal("actual fallback counter missing")
	}
	if slices.Contains(p.Capabilities.Protocols, "icmp") || slices.Contains(p.Capabilities.Protocols, "scion") {
		t.Fatal("disabled transport advertised")
	}
	if !slices.Contains(s.Capabilities.Protocols, "scion") || slices.Contains(s.Capabilities.Protocols, "icmp") != (netpolicy.ICMPPermitted() == nil) {
		t.Fatalf("local observations not reflected: %v", s.Capabilities)
	}
	calls := daemon.calls.Load()
	for i := 0; i < 20; i++ {
		if scion.capabilityReport(t.Context(), false) != nil {
			t.Fatal("frequent heartbeat renewed a cached observation")
		}
	}
	if daemon.calls.Load() != calls {
		t.Fatal("frequent heartbeat reprobed SCION")
	}

	daemon.blocked.Store(true)
	scion.capabilityNext = time.Time{} // Expire the existing throttle without a 30s sleep.
	began := time.Now()
	report := scion.capabilityReport(t.Context(), false)
	if elapsed := time.Since(began); elapsed > time.Second {
		t.Fatalf("SCION probe blocked heartbeat for %s", elapsed)
	}
	if report == nil || slices.Contains(report.Protocols, "scion") {
		t.Fatal("unresponsive daemon remained positive")
	}
	if scion.capabilityReport(t.Context(), false) != nil {
		t.Fatal("slow probe was immediately repeated")
	}

	t.Setenv("SCION_DAEMON_ADDRESS", "localhost:30255")
	if scionAvailable(t.Context()) {
		t.Fatal("hostname unexpectedly passed literal-only discovery")
	}
}
