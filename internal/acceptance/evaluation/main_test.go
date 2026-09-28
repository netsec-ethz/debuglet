// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetemRejectsRetainedRate(t *testing.T) {
	// Captured tc output: replacing a shaped netem with loss-only options
	// kept its earlier rate. Zero replies alone did not detect this mismatch.
	if _, err := readNetem("testdata/loss100-retained-rate.json", conditions[5]); err == nil || !strings.Contains(err.Error(), "rate 16000 B/s") {
		t.Fatalf("retained undeclared rate was not refused: %v", err)
	}
}

func TestNetemDeclaredUnits(t *testing.T) {
	for _, tc := range []struct {
		name      string
		condition int
		options   string
		valid     bool
	}{
		{"baseline", 0, `"limit":512`, true},
		{"delay-seconds", 1, `"limit":512,"delay":{"delay":0.02}`, true},
		{"delay-wrong-units", 1, `"limit":512,"delay":{"delay":20}`, false},
		{"loss-fraction", 3, `"limit":512,"loss-random":{"loss":0.2499999998}`, true},
		{"loss-wrong-units", 3, `"limit":512,"loss-random":{"loss":25}`, false},
		{"rate-bytes", 4, `"limit":512,"rate":{"rate":16000}`, true},
		{"rate-wrong-units", 4, `"limit":512,"rate":{"rate":128000}`, false},
		{"total-loss", 5, `"limit":512,"loss-random":{"loss":1}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "qdisc.json")
			if err := os.WriteFile(path, []byte(`[{"kind":"netem","handle":"20:","parent":"1:2","options":{`+tc.options+`}}]`), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := readNetem(path, conditions[tc.condition])
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t: %v", tc.valid, err)
			}
		})
	}
}
