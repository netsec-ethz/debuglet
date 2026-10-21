// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build wasip1

package debuglet

import (
	"encoding/json"
	"fmt"
	"time"
)

//go:wasmimport debuglet_io_v1 tls_inspect
func hostTLSInspect(ptr, length, out, size uint32, timeout int64) uint64

//go:wasmimport debuglet_io_v1 hop_probe
func hostHopProbe(ptr, length, ttl, out, size uint32, timeout int64) uint64

func inspectTLS(address string, timeout time.Duration) (TLSInfo, error) {
	var result TLSInfo
	buffer := make([]byte, MaxIOBytes)
	n, err := ioOutcome(hostTLSInspect(strPtr(address), uint32(len(address)), bytePtr(buffer), uint32(len(buffer)), int64(timeout)))
	if err == nil {
		err = decodeProbe(buffer, n, &result)
	}
	return result, err
}

func probeHop(address string, ttl uint32, timeout time.Duration) (HopReply, error) {
	var result HopReply
	buffer := make([]byte, MaxIOBytes)
	n, err := ioOutcome(hostHopProbe(strPtr(address), uint32(len(address)), ttl, bytePtr(buffer), uint32(len(buffer)), int64(timeout)))
	if err == nil {
		err = decodeProbe(buffer, n, &result)
	}
	return result, err
}

func decodeProbe(buffer []byte, n int, result any) error {
	if n <= 0 || n > len(buffer) {
		return fmt.Errorf("debuglet: invalid probe result size")
	}
	return json.Unmarshal(buffer[:n], result)
}
