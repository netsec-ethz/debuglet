// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

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
	e := &Executor{portManager: pool, listenerSetup: make(chan struct{}, 1), cfg: config.ExecutorConfig{Connectivity: config.ConnectivityConfig{Listeners: true, IPv4Reflector: "127.0.0.1:1"}}}
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
		t.Fatal("second report bypassed listener setup exclusion")
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

func TestConnectivityFollowsCapabilityCadenceWithHeartbeatJitter(t *testing.T) {
	e := newFixtureExecutor(t, fixtureConfig(), nil, newFixtureMemoryStorage(t))
	// Start beyond epoch zero: attribution becoming available intentionally
	// triggers an extra immediate report on hosts that support packet tagging.
	base := time.Now().Add(time.Minute)
	lastReport := time.Time{}
	reports := 0
	// A 15s heartbeat can arrive just before its next 30s report deadline.
	// The sole producer schedule may then wait 45s, but connectivity must not
	// impose a second deadline and skip another fresh capability report.
	for _, ms := range []int{2, 15001, 30002, 45001, 60002, 75001, 90001, 105002, 120001, 135002} {
		now := base.Add(time.Duration(ms) * time.Millisecond)
		_, vantage := e.capabilityReportAt(t.Context(), false, now)
		e.probeConnectivity(t.Context(), controlsession.Binding{}, vantage)()
		if vantage == nil {
			continue
		}
		if vantage.Connectivity == nil {
			t.Fatalf("fresh capability report at %s omitted its connectivity probe", now.Sub(base))
		}
		if !lastReport.IsZero() && now.Sub(lastReport) > 45*time.Second {
			t.Fatalf("healthy heartbeat left a %s observation gap", now.Sub(lastReport))
		}
		lastReport = now
		reports++
	}
	if reports != 5 {
		t.Fatalf("got %d fresh reports, want 5", reports)
	}
}
