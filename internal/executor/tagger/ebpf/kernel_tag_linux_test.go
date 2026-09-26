// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// skbContext is the leading part of struct __sk_buff. BPF_PROG_TEST_RUN
// accepts it as the program's context; the fields before mark must be zero.
type skbContext struct {
	Len     uint32
	PktType uint32
	Mark    uint32
}

// TestKernelTagMatchesGoTagger runs tagger.c on marked IPv4 frames and
// requires the tag the kernel writes to equal the one the pure-Go fallback
// writes for the same packet, epoch and measurement.
func TestKernelTagMatchesGoTagger(t *testing.T) {
	// The long delay keeps the kernel and the Go tagger in the same epoch.
	ks, err := tesla.NewKeySchedule(tesla.Config{
		Seed:  make([]byte, 32),
		Delay: time.Hour,
		Epoch: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("InterfaceByName: %v", err)
	}
	measurementID := []byte("kernel-parity-measurement")
	bt, err := NewBPFTagger(zap.NewNop(), iface, ks, measurementID)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping test: insufficient privileges for eBPF: %v", err)
		}
		t.Fatalf("NewBPFTagger: %v", err)
	}
	defer bt.Close()
	goTagger := tagger.New(ks, measurementID)

	for _, payloadLen := range []int{1, 8, 13, 44, 45, 100, 1400} {
		ip := make([]byte, 20+payloadLen)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
		ip[8] = 64
		ip[9] = 17
		copy(ip[12:16], net.IPv4(127, 0, 0, 1).To4())
		copy(ip[16:20], net.IPv4(127, 0, 0, 2).To4())
		for i := 20; i < len(ip); i++ {
			ip[i] = byte(i*13 + payloadLen)
		}
		binary.BigEndian.PutUint16(ip[10:12], tagger.IPv4Checksum(ip[:20]))

		frame := make([]byte, 14+len(ip))
		binary.BigEndian.PutUint16(frame[12:14], 0x0800)
		copy(frame[14:], ip)
		out := make([]byte, len(frame))
		if _, err := bt.objs.DebugletTag.Run(&ebpf.RunOptions{
			Data:    frame,
			DataOut: out,
			Context: skbContext{Mark: bt.MapKey()},
		}); err != nil {
			t.Fatalf("payload %d: run tagger.c: %v", payloadLen, err)
		}
		kernelTag := binary.BigEndian.Uint16(out[14+4 : 14+6])

		goTagged, err := goTagger.TagPacket(append([]byte(nil), ip...))
		if err != nil {
			t.Fatalf("payload %d: TagPacket: %v", payloadLen, err)
		}
		if goTag := tagger.ReadIPID(goTagged); goTag != kernelTag {
			t.Errorf("payload %d: Go tag %04x, kernel tag %04x", payloadLen, goTag, kernelTag)
		}
		if kernelTag == 0 {
			t.Errorf("payload %d: the kernel left the packet untagged", payloadLen)
		}
	}
}
