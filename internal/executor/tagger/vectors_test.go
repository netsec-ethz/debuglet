// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tagger

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tagvectors"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// vectorSchedule is the key schedule of testdata/tag-vectors-v1.json, placed
// so that now falls in its signing epoch.
func vectorSchedule(t *testing.T, f *tagvectors.File) *tesla.KeySchedule {
	t.Helper()
	delay := time.Hour
	ks, err := tesla.NewKeySchedule(tesla.Config{
		Seed:        tagvectors.Hex(t, f.Chain.TailHex),
		ChainLength: f.Chain.ChainLength,
		Delay:       delay,
		Epoch:       time.Now().Add(-time.Duration(f.Chain.SigningEpoch)*delay - delay/2),
	})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}
	return ks
}

// TestTagPacketVectorsV1 requires the pure-Go tagger to turn every vector
// packet into exactly the tagged packet of the independent reference: the
// tag in the IP ID, DF set and a valid header checksum. A packet v1 does not
// tag must come back unchanged.
func TestTagPacketVectorsV1(t *testing.T) {
	f := tagvectors.Load(t)
	tgr := New(vectorSchedule(t, f), []byte(f.MeasurementID))
	for _, v := range f.Vectors {
		pkt := tagvectors.Hex(t, v.PacketHex)
		want := pkt
		if v.Supported {
			want = tagvectors.Hex(t, v.TaggedPacketHex)
		}
		got, err := tgr.TagPacket(append([]byte(nil), pkt...))
		if err != nil {
			t.Errorf("%s: TagPacket: %v", v.Name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: TagPacket\n got %s\nwant %s", v.Name, hex.EncodeToString(got), hex.EncodeToString(want))
		}
		if v.Supported && IPv4Checksum(got[:int(got[0]&0x0f)*4]) != 0 {
			t.Errorf("%s: the tagged header checksum does not verify", v.Name)
		}
	}
}
