// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestConnectivitySelectionRequiresFreshMeasuredEvidence(t *testing.T) {
	now := time.Unix(1700000000, 0)
	at, expiry := now.Unix(), now.Add(90*time.Second).Unix()
	good := wire.Reachability{State: "reachable", Source: wire.SourceDispatcherObserved, ObservedAt: &at, ExpiresAt: &expiry}
	c := &wire.Connectivity{SchemaVersion: 1, IPv4: good, TCPListener: good}
	f := ExecutorFilter{AddressFamilies: []string{"ipv4"}, ReachableListeners: []string{"tcp"}}
	if !matchesConnectivity(c, f, now) {
		t.Fatal("fresh controlled observations did not match")
	}
	if matchesConnectivity(c, f, now.Add(90*time.Second)) || matchesConnectivity(nil, f, now) {
		t.Fatal("expired/absent observations matched")
	}
	c.TCPListener.State = "untested"
	if matchesConnectivity(c, f, now) {
		t.Fatal("unmeasured listener matched")
	}
	c.TCPListener = good
	c.IPv4.Stale = true
	if matchesConnectivity(c, f, now) {
		t.Fatal("explicitly stale family matched")
	}
}

func TestResultConnectivityRejectsInconsistentProvenance(t *testing.T) {
	unknown := wire.Reachability{State: "untested", Reason: "not_configured"}
	c := &wire.Connectivity{SchemaVersion: 1, IPv4: unknown, IPv6: unknown, TCPListener: unknown, UDPListener: unknown, SCIONListener: unknown, SCIONPaths: unknown, Disagreements: []string{}}
	if !validConnectivity(c) {
		t.Fatal("explicit untested metadata rejected")
	}
	at, expiry := int64(1700000000), int64(1700000090)
	c.IPv4 = wire.Reachability{State: "reachable", Source: wire.SourceDispatcherObserved, ObservedAt: &at, ExpiresAt: &expiry, Address: "127.0.0.1"}
	if !validConnectivity(c) {
		t.Fatal("observed metadata rejected")
	}
	c.IPv4.ExpiresAt = nil
	if validConnectivity(c) {
		t.Fatal("positive result without expiry accepted")
	}
	c.IPv4 = unknown
	c.IPv4.Source = wire.SourceDispatcherObserved
	if validConnectivity(c) {
		t.Fatal("untested result claimed observation")
	}
}
