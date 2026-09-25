//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

// Package ebpf provides a stub eBPF tagger for non-Linux platforms.
//
// On macOS and other non-Linux systems the eBPF kernel hooks are unavailable.
// This stub exports the same BPFTagger type and constructor so that the rest
// of the codebase compiles unchanged; the stub simply reports that eBPF is
// not supported and falls through to the pure-Go tagger.
package ebpf

import (
	"fmt"
	"net"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// BPFTagger is a no-op stub on non-Linux platforms.
type BPFTagger struct{}

// NewBPFTagger always returns an error on non-Linux platforms.
// Callers should fall back to the pure-Go tagger.
func NewBPFTagger(iface *net.Interface, schedule *tesla.KeySchedule, measurementID []byte) (*BPFTagger, error) {
	return nil, fmt.Errorf("ebpf: eBPF tagger is only available on Linux (current platform is non-Linux)")
}

// TagPacket is a no-op stub.
func (bt *BPFTagger) TagPacket(pkt []byte) ([]byte, error) {
	return pkt, nil
}

// SetSocketMark is a no-op stub.
func (bt *BPFTagger) SetSocketMark(fd int) error { return nil }

// Close is a no-op stub.
func (bt *BPFTagger) Close() error { return nil }

// Schedule is a no-op stub.
func (bt *BPFTagger) Schedule() *tesla.KeySchedule { return nil }
