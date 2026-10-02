// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import "testing"

func TestConnectBackTargetsRequireLocalOperatorApproval(t *testing.T) {
	for _, c := range []ExecutorDisplay{{ConnectivityHost: "localhost", ConnectivityPorts: "4200"}, {ConnectivityHost: "127.0.0.1"}, {ConnectivityPorts: "4200"}, {ConnectivityHost: "0.0.0.0", ConnectivityPorts: "4200"}, {ConnectivityHost: "127.0.0.1", ConnectivityPorts: "1-257"}} {
		if err := validateConnectivityTarget("node", c); err == nil {
			t.Fatalf("invalid target accepted: %+v", c)
		}
	}
	c := ExecutorDisplay{ConnectivityHost: "::1", ConnectivityPorts: "4200-4201"}
	if err := validateConnectivityTarget("node", c); err != nil {
		t.Fatal(err)
	}
	if target, ok := c.ConnectivityTarget(4200); !ok || target.String() != "[::1]:4200" {
		t.Fatal("approved target missing")
	}
	for _, port := range []uint32{0, 4199, 4202, 65536} {
		if _, ok := c.ConnectivityTarget(port); ok {
			t.Fatalf("port %d escaped approved range", port)
		}
	}
}
