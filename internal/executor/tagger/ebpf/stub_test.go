//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package ebpf

import (
	"net"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// TestNewBPFTaggerUnavailable verifies that the stub correctly reports that
// the eBPF tagger is unavailable on the current (non-Linux) platform.
func TestNewBPFTaggerUnavailable(t *testing.T) {
	ks, err := tesla.NewKeySchedule(tesla.Config{
		Seed:  make([]byte, 32),
		Delay: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}

	iface, err := net.InterfaceByName("lo")
	_, err = NewBPFTagger(zap.NewNop(), iface, ks, []byte("test-measurement"))
	if err == nil {
		t.Error("expected error from NewBPFTagger on non-Linux, got nil")
	}
	t.Logf("expected error: %v", err)
}

// TestBPFTaggerStubTagPacket verifies that the stub TagPacket is a no-op.
func TestBPFTaggerStubTagPacket(t *testing.T) {
	bt := &BPFTagger{}
	pkt := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
		0x00, 0x00, 127, 0, 0, 1, 127, 0, 0, 2}
	result, err := bt.TagPacket(pkt)
	if err != nil {
		t.Fatalf("stub TagPacket returned error: %v", err)
	}
	if string(result) != string(pkt) {
		t.Error("stub TagPacket modified the packet")
	}
}
