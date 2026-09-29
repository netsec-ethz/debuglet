// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tesla

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tagvectors"
)

// testIPv4 wraps payload in an IPv4/UDP packet, the only kind v1 tags.
func testIPv4(payload []byte) []byte {
	pkt := make([]byte, 28+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], []byte{192, 0, 2, 1})
	copy(pkt[16:20], []byte{192, 0, 2, 2})
	binary.BigEndian.PutUint16(pkt[20:22], 40000)
	binary.BigEndian.PutUint16(pkt[22:24], 33434)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	copy(pkt[28:], payload)
	return pkt
}

// TestHashInputIgnoresMutableFields checks the canonical form directly: the
// fields routers, NAT fix-ups and offloads rewrite do not reach the input.
func TestHashInputIgnoresMutableFields(t *testing.T) {
	base := testIPv4([]byte("canonical form payload that is longer than the input"))
	want, err := HashInput(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != MaxTagInput {
		t.Fatalf("input is %d bytes, want %d", len(want), MaxTagInput)
	}
	for name, mutate := range map[string]func([]byte){
		"tos":          func(p []byte) { p[1] = 0xff },
		"ipid":         func(p []byte) { p[4], p[5] = 0xab, 0xcd },
		"df":           func(p []byte) { p[6] |= 0x40 },
		"ttl":          func(p []byte) { p[8] = 1 },
		"checksum":     func(p []byte) { p[10], p[11] = 0x12, 0x34 },
		"udp checksum": func(p []byte) { p[26], p[27] = 0x56, 0x78 },
		"after input":  func(p []byte) { p[MaxTagInput] ^= 0xff },
	} {
		p := append([]byte(nil), base...)
		mutate(p)
		if got, err := HashInput(p); err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s changed the input: %x, %v", name, got, err)
		}
	}
	for name, mutate := range map[string]func([]byte){
		"source":  func(p []byte) { p[12] ^= 1 },
		"port":    func(p []byte) { p[22] ^= 1 },
		"payload": func(p []byte) { p[MaxTagInput-1] ^= 1 },
	} {
		p := append([]byte(nil), base...)
		mutate(p)
		if got, _ := HashInput(p); bytes.Equal(got, want) {
			t.Errorf("%s did not change the input", name)
		}
	}
}

// TestSipHashReferenceVectors checks SipHash24 against the 64 reference
// outputs published with SipHash, including every partial final block.
func TestSipHashReferenceVectors(t *testing.T) {
	f := tagvectors.Load(t)
	key := tagvectors.Hex(t, f.SipHashReference.KeyHex)
	if len(f.SipHashReference.OutputsHex) != 64 {
		t.Fatalf("%d reference outputs, want 64", len(f.SipHashReference.OutputsHex))
	}
	for n, want := range f.SipHashReference.OutputsHex {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte(i)
		}
		var out [8]byte
		binary.LittleEndian.PutUint64(out[:], SipHash24(key, msg))
		if got := hex.EncodeToString(out[:]); got != want {
			t.Errorf("SipHash-2-4 of %d bytes = %s, want %s", n, got, want)
		}
	}
}

// TestTagVectorsV1 reproduces every known-answer vector of the independent
// Python reference: the canonical input, the SipHash output, the tag and the
// unsupported reason of a packet v1 does not tag.
func TestTagVectorsV1(t *testing.T) {
	f := tagvectors.Load(t)
	if f.Spec != TagSpec {
		t.Fatalf("vector file is %q, this build implements %q", f.Spec, TagSpec)
	}
	chainKey := tagvectors.Hex(t, f.KtHex)
	ak, err := DeriveAK(chainKey, []byte(f.MeasurementID))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ak, tagvectors.Hex(t, f.AKHex)) {
		t.Fatalf("DeriveAK = %x, want %s", ak, f.AKHex)
	}
	anchorAK, err := DeriveAK(tagvectors.Hex(t, f.Chain.AnchorHex), []byte(f.MeasurementID))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(anchorAK, tagvectors.Hex(t, f.AnchorAKHex)) {
		t.Fatalf("DeriveAK(anchor) = %x, want %s", anchorAK, f.AnchorAKHex)
	}
	tags := map[string]uint16{}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			pkt := tagvectors.Hex(t, v.PacketHex)
			orig := append([]byte(nil), pkt...)
			in, err := HashInput(pkt)
			if !bytes.Equal(pkt, orig) {
				t.Fatal("HashInput modified the packet")
			}
			if !v.Supported {
				var u *UnsupportedError
				if !errors.As(err, &u) || u.Reason != v.UnsupportedReason {
					t.Fatalf("HashInput error %v, want unsupported %q", err, v.UnsupportedReason)
				}
				if _, err := VerifyTag(chainKey, 1, []byte(f.MeasurementID), pkt, 0); !errors.As(err, &u) {
					t.Fatalf("VerifyTag error %v, want unsupported", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("HashInput: %v", err)
			}
			if got := hex.EncodeToString(in); got != v.InputHex {
				t.Fatalf("input %s\nwant  %s", got, v.InputHex)
			}
			var out [8]byte
			binary.LittleEndian.PutUint64(out[:], SipHash24(ak, in))
			if got := hex.EncodeToString(out[:]); got != v.SipHashHex {
				t.Errorf("SipHash %s, want %s", got, v.SipHashHex)
			}
			if tag, err := PacketTag(ak, pkt); err != nil || tag != v.Tag {
				t.Errorf("PacketTag = %04x, %v; want %04x", tag, err, v.Tag)
			}
			if tag, _ := PacketTag(anchorAK, pkt); tag != v.AnchorTag {
				t.Errorf("anchor tag = %04x, want %04x", tag, v.AnchorTag)
			}
			tagged := tagvectors.Hex(t, v.TaggedPacketHex)
			ok, err := VerifyTag(chainKey, 1, []byte(f.MeasurementID), tagged, binary.BigEndian.Uint16(tagged[4:6]))
			if err != nil || !ok {
				t.Errorf("VerifyTag(tagged packet) = %v, %v; want true", ok, err)
			}
			tags[v.Name] = v.Tag
		})
	}
	for _, v := range f.Vectors {
		if v.SameTagAs != "" && tags[v.Name] != tags[v.SameTagAs] {
			t.Errorf("%s: tag %04x, want the tag of %s", v.Name, tags[v.Name], v.SameTagAs)
		}
		if v.TagDiffersFrom != "" && tags[v.Name] == tags[v.TagDiffersFrom] {
			t.Errorf("%s: tag equals that of %s", v.Name, v.TagDiffersFrom)
		}
	}
}

// TestTagVectorsFirstSigningEpoch is the known-answer fixture of the key
// schedule: the chain of the vectors reproduces, epoch 0 (the public anchor)
// never signs, and the first accepted tag, from epoch 1, is not the tag the
// anchor produces.
func TestTagVectorsFirstSigningEpoch(t *testing.T) {
	f := tagvectors.Load(t)
	delay := time.Minute
	start := time.Unix(1_700_000_000, 0)
	ks, err := NewKeySchedule(Config{
		Seed:        tagvectors.Hex(t, f.Chain.TailHex),
		ChainLength: f.Chain.ChainLength,
		EpochLength: delay,
		Epoch:       start,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ks.Anchor(), tagvectors.Hex(t, f.Chain.AnchorHex)) {
		t.Fatalf("anchor %x, want %s", ks.Anchor(), f.Chain.AnchorHex)
	}
	for i, want := range f.Chain.KeysHex {
		if k, err := ks.KeyAtEpoch(int64(i)); err != nil || hex.EncodeToString(k) != want {
			t.Errorf("k_%d = %x, %v; want %s", i, k, err, want)
		}
	}
	var base *tagvectors.Vector
	for i := range f.Vectors {
		if f.Vectors[i].Name == "udp_base" {
			base = &f.Vectors[i]
		}
	}
	if base == nil {
		t.Fatal("no udp_base vector")
	}
	pkt := tagvectors.Hex(t, base.PacketHex)
	mid := []byte(f.MeasurementID)
	if ks.CurrentKey(start.Add(delay/2)) != nil {
		t.Error("epoch 0 has a signing key")
	}
	if _, err := ks.ComputeTagForPacket(start.Add(delay/2), mid, pkt); err == nil {
		t.Error("a tag was produced in epoch 0")
	}
	tag, err := ks.ComputeTagForPacket(start.Add(time.Duration(f.Chain.SigningEpoch)*delay), mid, pkt)
	if err != nil || tag != base.Tag {
		t.Fatalf("epoch %d tag = %04x, %v; want %04x", f.Chain.SigningEpoch, tag, err, base.Tag)
	}
	if base.AnchorTag == base.Tag {
		t.Fatal("fixture: the anchor-derived tag equals the accepted tag")
	}
	if ok, _ := VerifyTag(ks.CurrentKey(start.Add(delay)), 1, mid, pkt, base.AnchorTag); ok {
		t.Error("the anchor-derived tag verifies under k_1")
	}
}
