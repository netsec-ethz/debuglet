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
// leave the program unchanged.
func TestKernelTagVectorsV1(t *testing.T) {
	f := tagvectors.Load(t)
	if err := rlimit.RemoveMemlock(); err != nil {
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
		frame := make([]byte, 14+len(pkt))
		binary.BigEndian.PutUint16(frame[12:14], 0x0800)
		copy(frame[14:], pkt)
		out := make([]byte, len(frame))
		if _, err := objs.DebugletTag.Run(&ebpf.RunOptions{
			Data:    frame,
			DataOut: out,
			Context: skbContext{Mark: mark},
		}); err != nil {
			t.Fatalf("%s: run tagger.c: %v", v.Name, err)
		}
		if got := out[14:]; !bytes.Equal(got, want) {
			t.Errorf("%s: kernel output\n got %s\nwant %s", v.Name, hex.EncodeToString(got), hex.EncodeToString(want))
		}
	}
}
