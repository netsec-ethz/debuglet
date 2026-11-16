// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// tcp-check reports three bounded TCP connection times; CI decides whether they
// meet its threshold. A network failure is a measurement, not a program crash.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

func main() {
	// Debuglet supplies guest arguments without a program-name element.
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "expected one target host:port")
		os.Exit(1)
	}
	type sample struct {
		ConnectMS float64 `json:"connect_ms"`
		Error     string  `json:"error,omitempty"`
	}
	samples := make([]sample, 0, 3)
	for range 3 {
		started := time.Now()
		conn, err := debuglet.DialTimeout("tcp", os.Args[0], 1500*time.Millisecond)
		measured := sample{ConnectMS: float64(time.Since(started)) / float64(time.Millisecond)}
		if err != nil {
			measured.Error = err.Error()
		} else {
			_ = conn.Close()
		}
		samples = append(samples, measured)
		time.Sleep(100 * time.Millisecond)
	}
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		Target  string   `json:"target"`
		Samples []sample `json:"samples"`
	}{os.Args[0], samples}); err != nil {
		os.Exit(1)
	}
}
