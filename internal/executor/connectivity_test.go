// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/connectivity"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func TestConnectivityListenerReservationsReturnAfterHeartbeat(t *testing.T) {
	// Reserve two ephemeral ports while choosing the pool; all traffic stays on
	// loopback, and no fixed host port is assumed to be free.
	a, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ports := fmt.Sprintf("%d,%d", a.Addr().(*net.TCPAddr).Port, b.Addr().(*net.TCPAddr).Port)
	a.Close()
	b.Close()
	pool, err := socket.NewPortManager("127.0.0.1", ports)
	if err != nil {
		t.Fatal(err)
	}
	e := &Executor{portManager: pool, cfg: config.ExecutorConfig{Connectivity: config.ConnectivityConfig{Listeners: true, IPv4Reflector: "127.0.0.1:1"}}}
	initial := e.initialConnectivityReport()
	if initial.Ipv4.Reason != "pending" || initial.Ipv6.Reason != "not_configured" || !initial.ListenersEnabled {
		t.Fatalf("initial report: %+v", initial)
	}
	report := &pb.VantagePointReport{Listeners: []string{"tcp", "udp"}}
	finish := e.probeConnectivity(context.Background(), controlsession.Binding{}, report)
	defer finish()
	if len(report.Connectivity.Listeners) != 2 {
		t.Fatalf("missing bound listeners: %+v", report.Connectivity)
	}
	for _, probe := range report.Connectivity.Listeners {
		endpoint := fmt.Sprintf("127.0.0.1:%d", probe.Port)
		if err := connectivity.Check(t.Context(), probe.Transport, endpoint, probe.Token); err != nil {
			t.Fatalf("%s did not answer actual challenge: %v", probe.Transport, err)
		}
	}
	if l, _, _, err := pool.ListenTCP(nil); err == nil {
		l.Close()
		t.Fatal("temporary proof listeners did not reserve the pool")
	}
	throttled := &pb.VantagePointReport{Listeners: []string{"tcp", "udp"}}
	e.probeConnectivity(t.Context(), controlsession.Binding{}, throttled)()
	if throttled.Connectivity != nil {
		t.Fatal("second report bypassed observation interval")
	}
	finish()
	for range 2 {
		l, port, _, err := pool.ListenTCP(nil)
		if err != nil {
			t.Fatalf("finished heartbeat retained a port or responder: %v", err)
		}
		defer l.Close()
		defer pool.Release(port)
	}
}
