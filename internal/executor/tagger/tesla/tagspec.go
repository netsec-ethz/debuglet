// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tesla

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"time"
)

// TagSpec identifies the packet-tag algorithm this build implements, defined
// in docs/tag-spec.md. Taggers and verifiers of one fleet use one version;
// results record it so evidence names the algorithm its tags follow.
const TagSpec = "debuglet-tag-v1"

// MaxTagInput is the most packet bytes the tag authenticates.
const MaxTagInput = 64

// Reasons why a packet has no v1 tag. The tagger leaves such a packet
// unchanged, and a verifier reports it unsupported rather than unmatched.
const (
	UnsupportedIPv6      = "ipv6"      // IPv6 is not specified in v1.
	UnsupportedNotIPv4   = "not_ipv4"  // Neither IPv4 nor IPv6.
	UnsupportedTooShort  = "too_short" // Fewer bytes than the header or the tag input.
	UnsupportedMalformed = "malformed" // IHL below 5 or a total length below the header.
	UnsupportedFragment  = "fragment"  // MF set or a non-zero fragment offset.
)

// UnsupportedError is returned for a packet the specification assigns no tag.
type UnsupportedError struct{ Reason string }

func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("tesla: packet not covered by %s: %s", TagSpec, e.Reason)
}

// l4Checksum is the checksum offset inside the transport header of the IP
// protocols whose checksum the canonical form zeroes: ICMP, TCP and UDP.
func l4Checksum(proto byte) (int, bool) {
	switch proto {
	case 1:
		return 2, true
	case 6:
		return 16, true
	case 17:
		return 6, true
	}
	return 0, false
}

// HashInput returns the canonical tag input of an IPv4 packet: its first
// min(64, total length) bytes with TOS, IP ID, flags and fragment offset, TTL,
// header checksum, IP options and the ICMP, TCP or UDP checksum zeroed. It
// fails with an *UnsupportedError for a packet v1 does not tag. packet is not
// modified.
func HashInput(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, &UnsupportedError{UnsupportedTooShort}
	}
	switch packet[0] >> 4 {
	case 4:
	case 6:
		return nil, &UnsupportedError{UnsupportedIPv6}
	default:
		return nil, &UnsupportedError{UnsupportedNotIPv4}
	}
	if len(packet) < 20 {
		return nil, &UnsupportedError{UnsupportedTooShort}
	}
	ihl := int(packet[0]&0x0F) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if ihl < 20 || total < ihl {
		return nil, &UnsupportedError{UnsupportedMalformed}
	}
	if binary.BigEndian.Uint16(packet[6:8])&0x3FFF != 0 {
		return nil, &UnsupportedError{UnsupportedFragment}
	}
	n := min(total, MaxTagInput)
	if len(packet) < n {
		return nil, &UnsupportedError{UnsupportedTooShort}
	}
	in := make([]byte, n)
	copy(in, packet)
	for _, i := range []int{1, 4, 5, 6, 7, 8, 10, 11} {
		in[i] = 0
	}
	for i := 20; i < min(ihl, n); i++ {
		in[i] = 0
	}
	if off, ok := l4Checksum(in[9]); ok {
		for _, i := range []int{ihl + off, ihl + off + 1} {
			if i < n {
				in[i] = 0
			}
		}
	}
	return in, nil
}

// SipHash24 is standard SipHash-2-4 (Aumasson and Bernstein) keyed with the
// 16-byte key, including the final partial block.
func SipHash24(key, data []byte) uint64 {
	k0 := binary.LittleEndian.Uint64(key[0:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573
	round := func() {
		v0 += v1
		v1 = bits.RotateLeft64(v1, 13)
		v1 ^= v0
		v0 = bits.RotateLeft64(v0, 32)
		v2 += v3
		v3 = bits.RotateLeft64(v3, 16)
		v3 ^= v2
		v0 += v3
		v3 = bits.RotateLeft64(v3, 21)
		v3 ^= v0
		v2 += v1
		v1 = bits.RotateLeft64(v1, 17)
		v1 ^= v2
		v2 = bits.RotateLeft64(v2, 32)
	}
	compress := func(m uint64) {
		v3 ^= m
		round()
		round()
		v0 ^= m
	}
	full := len(data) &^ 7
	for i := 0; i < full; i += 8 {
		compress(binary.LittleEndian.Uint64(data[i:]))
	}
	last := uint64(len(data)) << 56
	for i, b := range data[full:] {
		last |= uint64(b) << (8 * i)
	}
	compress(last)
	v2 ^= 0xff
	for range 4 {
		round()
	}
	return v0 ^ v1 ^ v2 ^ v3
}

// ComputeTag is the 16-bit tag of an already canonical input: the low 16 bits
// of SipHash-2-4 keyed with ak[0:16]. Every input byte is hashed; HashInput
// bounds a packet's input to MaxTagInput bytes.
func ComputeTag(ak, input []byte) (uint16, error) {
	if len(ak) < 16 {
		return 0, fmt.Errorf("tesla: ak too short")
	}
	return uint16(SipHash24(ak[:16], input)), nil
}

// PacketTag is the v1 tag of an IPv4 packet under ak.
func PacketTag(ak, packet []byte) (uint16, error) {
	in, err := HashInput(packet)
	if err != nil {
		return 0, err
	}
	return ComputeTag(ak, in)
}

// ComputeTagForPacket derives ak from the chain key at time t and returns the
// v1 tag of packet. It fails while no chain key is usable and with an
// *UnsupportedError for a packet v1 does not tag.
func (ks *KeySchedule) ComputeTagForPacket(t time.Time, measurementID, packet []byte) (uint16, error) {
	ak, err := ks.currentAK(t, measurementID)
	if err != nil {
		return 0, err
	}
	return PacketTag(ak, packet)
}

// VerifyTag checks whether tag is the v1 tag of an IPv4 packet at a given
// epoch, given the chain key of that epoch and the measurement ID. Choosing
// the candidate epochs is the caller's (docs/tag-spec.md). A packet v1 does
// not cover fails with an *UnsupportedError rather than a mismatch.
func VerifyTag(chainKey []byte, epoch int64, measurementID, packet []byte, tag uint16) (bool, error) {
	in, err := HashInput(packet)
	if err != nil {
		return false, err
	}
	ak, err := DeriveAK(chainKey, measurementID)
	if err != nil {
		return false, err
	}
	expected, err := ComputeTag(ak, in)
	if err != nil {
		return false, err
	}
	return expected == tag, nil
}
