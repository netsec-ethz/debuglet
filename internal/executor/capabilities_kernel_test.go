// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"syscall"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/ebpf"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
	"google.golang.org/grpc"
)

// Two local executors built through the production node path report differing
// enforcement, ICMP and SCION observations; client selection follows them. The
// kernel lane requires this to pass: there the eBPF counter must actually load.
func TestHeterogeneousExecutorCapabilitiesSelection(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	probe, err := ebpf.NewBPFCount(lo)
	if err != nil {
		for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EACCES, syscall.EINVAL} {
			if errors.Is(err, errno) {
				t.Skipf("counter load requires kernel capabilities (%s): %v", errno, err)
			}
		}
		t.Fatal(err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	sdpb.RegisterDaemonServiceServer(server, &capabilityDaemon{})
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); <-done })
	t.Setenv("SCION_DAEMON_ADDRESS", listener.Addr().String())

	enabled, disabled := true, false
	kernelConfig, scionConfig := fixtureConfig(), fixtureConfig()
	kernelConfig.Network.PacketCounter, kernelConfig.Network.Interface = "auto", "lo"
	kernelConfig.Network.Policy.ICMP = &enabled
	scionConfig.Network.Policy.ICMP, scionConfig.Network.Policy.SCION = &disabled, &enabled
	// nil counters: each node acquires its counter through ratelimit.New.
	kernel := newFixtureExecutor(t, kernelConfig, nil, newFixtureMemoryStorage(t))
	scion := newFixtureExecutor(t, scionConfig, nil, newFixtureMemoryStorage(t))
	nodes := []client.Node{}
	for i, e := range []*Executor{kernel, scion} {
		hello, err := e.OnHello(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		report := hello.GetCapabilities()
		nodes = append(nodes, client.Node{ID: []string{"kernel", "scion"}[i], Ready: true, Capabilities: &wire.ExecutorCapabilities{
			SchemaVersion: report.GetSchemaVersion(), Protocols: report.GetProtocols(), EnforcementMode: report.GetEnforcementMode()}})
	}
	t.Logf("reports: kernel=%+v scion=%+v", *nodes[0].Capabilities, *nodes[1].Capabilities)
	icmp := netpolicy.ICMPPermitted() == nil
	if got := nodes[0].Capabilities; got.EnforcementMode != "ebpf" || slices.Contains(got.Protocols, "scion") || slices.Contains(got.Protocols, "icmp") != icmp {
		t.Fatalf("kernel executor report: %+v", got)
	}
	if got := nodes[1].Capabilities; got.EnforcementMode != "fallback" || !slices.Contains(got.Protocols, "scion") || slices.Contains(got.Protocols, "icmp") {
		t.Fatalf("SCION executor report: %+v", got)
	}

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(nodes) }))
	t.Cleanup(api.Close)
	c, err := client.New(api.URL, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	selects := map[string]client.ExecutorFilter{
		"kernel": {EnforcementMode: "ebpf"},
		"scion":  {EnforcementMode: "fallback", Protocols: []string{"scion"}},
	}
	if icmp {
		selects["kernel"] = client.ExecutorFilter{EnforcementMode: "ebpf", Protocols: []string{"icmp"}}
	}
	for want, filter := range selects {
		if got, err := c.SelectExecutor(t.Context(), "", filter); err != nil || got.ID != want {
			t.Fatalf("filter %+v selected %q (%v), want %q", filter, got.ID, err, want)
		}
	}
	for _, reject := range []struct {
		id     string
		filter client.ExecutorFilter
	}{
		{"", client.ExecutorFilter{EnforcementMode: "ebpf", Protocols: []string{"scion"}}},
		{"", client.ExecutorFilter{EnforcementMode: "fallback", Protocols: []string{"icmp"}}},
		{"kernel", client.ExecutorFilter{EnforcementMode: "fallback"}},
		{"scion", client.ExecutorFilter{EnforcementMode: "ebpf"}},
	} {
		if got, err := c.SelectExecutor(t.Context(), reject.id, reject.filter); !errors.Is(err, client.ErrNoMatchingExecutor) {
			t.Fatalf("mismatch %q %+v selected %q (%v)", reject.id, reject.filter, got.ID, err)
		}
	}
	matched, err := c.DiscoverExecutors(t.Context(), client.ExecutorFilter{Protocols: []string{"tcp"}})
	if err != nil || len(matched) != 2 {
		t.Fatalf("shared protocol discovery: %v %v", matched, err)
	}
}
