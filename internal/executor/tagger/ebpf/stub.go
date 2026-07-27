//go:build !linux

// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

	"debuglet/internal/executor/tagger/tesla"
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
