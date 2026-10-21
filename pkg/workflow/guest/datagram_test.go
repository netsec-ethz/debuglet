// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import "testing"

func TestDatagramBlocksRejectInvalidInputsBeforeIO(t *testing.T) {
	for _, inputs := range []map[string]any{{"max_bytes": float64(0)}, {"max_bytes": float64(8193)}, {"timeout_ms": float64(0)}, {"encoding": "hex"}} {
		if _, err := UDPReceive(inputs); err == nil {
			t.Fatalf("receive accepted %v", inputs)
		}
	}
	for _, inputs := range []map[string]any{
		{"destination": "example.org:53"}, {"destination": "127.0.0.1:0"},
		{"destination": "127.0.0.1:53", "encoding": "base64", "payload": "!!"},
		{"destination": "127.0.0.1:53", "timeout_ms": float64(60001)},
	} {
		if _, err := UDPReply(inputs); err == nil {
			t.Fatalf("reply accepted %v", inputs)
		}
	}
}
