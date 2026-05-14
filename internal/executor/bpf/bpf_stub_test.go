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

package bpf

import (
	"testing"
	"time"

	"debuglet/pkg/tesla"
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

	_, err = NewBPFTagger("lo", ks, []byte("test-measurement"))
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
