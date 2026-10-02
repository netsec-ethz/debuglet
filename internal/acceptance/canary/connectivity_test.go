// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestNodeConnectivityKeepsExactOptionalShape(t *testing.T) {
	u := wire.Reachability{State: "untested", Reason: "not_configured"}
	value := &wire.Connectivity{SchemaVersion: 1, IPv4: u, IPv6: u, TCPListener: u, UDPListener: u, SCIONListener: u, SCIONPaths: u, Disagreements: []string{}}
	encoded, _ := json.Marshal(value)
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{string(encoded), true}, {"null", false},
		{strings.Replace(string(encoded), `"state":`, `"State":`, 1), false},
		{strings.Replace(string(encoded), `"stale":false`, `"stale":null`, 1), false},
		{strings.Replace(string(encoded), `"state":"untested"`, `"state":"untested","state":"untested"`, 1), false},
		{strings.Replace(string(encoded), `"disagreements":[]`, `"disagreements":[null]`, 1), false},
	} {
		raw := []byte(`[{"id":"` + testExecutor + `","ready":true,"last_seen":1790598500,"version":"test","tesla_delay_sec":2,"tesla_anchor_timestamp_ns":0,"tesla_anchor_key":null,"price_per_bw":0,"currency":"TEST","connectivity":` + tc.value + `}]`)
		var nodes []client.Node
		if err := decodeCommand(commandResult{Started: true, Stdout: raw}, &nodes); (err == nil) != tc.valid {
			t.Fatalf("valid=%t error=%v", tc.valid, err)
		}
	}
}
