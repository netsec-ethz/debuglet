// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tagvectors"
)

// TestKernelTagVectorsV1 runs the committed tagger.c object on every packet
// of testdata/tag-vectors-v1.json, the vectors of the independent Python
// reference, and requires the exact tagged packet: tag in the IP ID, DF set
// and the incrementally updated header checksum. A packet v1 does not tag must
// leave the program unchanged, including an IPv6 frame whose destination MAC
// starts with the nibble 4, as a random locally administered MAC does one
// time in sixteen: it must not be mistaken for a raw IPv4 header.
func TestKernelTagVectorsV1(t *testing.T) {
	f := tagvectors.Load(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("skipping test: insufficient privileges for eBPF: %v", err)
		}
		t.Fatalf("remove memlock: %v", err)
	}
	var objs taggerObjects
	if err := loadTaggerObjects(&objs, nil); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("skipping test: insufficient privileges for eBPF: %v", err)
		}
		t.Fatalf("load tagger objects: %v", err)
	}
	defer objs.Close()

	const mark = 0x5eed
	key := uint32(mark)
	entry := akFromKey(tagvectors.Hex(t, f.AKHex))
	if err := objs.AkMap.Put(&key, &entry); err != nil {
		t.Fatalf("install vector key: %v", err)
	}

	for _, v := range f.Vectors {
		pkt := tagvectors.Hex(t, v.PacketHex)
		want := pkt
		if v.Supported {
			want = tagvectors.Hex(t, v.TaggedPacketHex)
		}
		// Linux 7.0's TC test interface rejects an IPv4 frame shorter than
		// Ethernet plus the minimum IP header. Pad only the test frame: the
		// 19-byte capture and its total length (100) stay unchanged, so even
		// with padding it remains too short for the tag input. Check that
		// the program leaves both the fixture bytes and padding untouched.
		frame := make([]byte, 14+max(len(pkt), 20))
		wantPacket := make([]byte, len(frame)-14)
		copy(wantPacket, want)
		// Read as a raw IPv4 header these MACs (the source under the 00:00:0c
		// OUI) give IHL 6, Total Length 48 and no fragment bits.
		copy(frame[0:6], []byte{0x46, 0x00, 0x00, 0x30, 0x00, 0x00})
		copy(frame[6:12], []byte{0x00, 0x00, 0x0c, 0x00, 0x00, 0x01})
		etherType := uint16(0x0800)
		if len(pkt) > 0 && pkt[0]>>4 == 6 {
			etherType = 0x86DD
		}
		binary.BigEndian.PutUint16(frame[12:14], etherType)
		copy(frame[14:], pkt)
		out := make([]byte, len(frame))
		verdict, err := objs.DebugletTag.Run(&ebpf.RunOptions{
			Data:    frame,
			DataOut: out,
			Context: skbContext{Mark: mark},
		})
		if err != nil {
			t.Fatalf("%s: run tagger.c: %v", v.Name, err)
		}
		if verdict != ^uint32(0) { // TCX_NEXT (-1): continue the hook chain.
			t.Errorf("%s: kernel verdict %#x, want TCX_NEXT", v.Name, verdict)
		}
		if !bytes.Equal(out[:14], frame[:14]) {
			t.Errorf("%s: kernel changed the Ethernet header\n got %s\nwant %s", v.Name, hex.EncodeToString(out[:14]), hex.EncodeToString(frame[:14]))
		}
		if got := out[14:]; !bytes.Equal(got, wantPacket) {
			t.Errorf("%s: kernel output\n got %s\nwant %s", v.Name, hex.EncodeToString(got), hex.EncodeToString(wantPacket))
		}
	}
}
