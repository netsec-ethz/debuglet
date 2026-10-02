// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package tagspec implements the pure functions of the packet tag
// specification debuglet-tag-v1 (docs/tag-spec.md): the canonical tag input
// of an IPv4 packet, SipHash-2-4, the per-measurement key and the 16-bit tag.
// It holds no key schedule and no state, so taggers (internal/executor/tagger)
// and verifiers (pkg/client) share one implementation. The known-answer
// vectors in testdata/tag-vectors-v1.json pin it.
package tagspec

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"

	"golang.org/x/crypto/hkdf"
)

// ID identifies the packet-tag algorithm this package implements. Taggers and
// verifiers of one fleet use one version; results record it so evidence names
// the algorithm its tags follow.
const ID = "debuglet-tag-v1"

// Version is the numeric form of ID that the dispatcher's attribution history
// reports per chain. Zero there is an executor that predates the versioned
// specification (the unversioned pre-v1 tag), which no verifier accepts.
const Version = 1

// MaxInput is the most packet bytes the tag authenticates.
const MaxInput = 64

// MinDisclosureDelay is the shortest disclosure delay d, in epochs, that a
// tagger uses and a verifier accepts. A verifier tries a packet's epoch t and
// t-1; with d = 1 the key of t-1 is already public during epoch t.
const MinDisclosureDelay = 2

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
	return fmt.Sprintf("tagspec: packet not covered by %s: %s", ID, e.Reason)
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
	n := min(total, MaxInput)
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

// DeriveAK computes the per-measurement authentication key of §2:
//
//	ak = HKDF-SHA256(secret=k, salt=absent, info=measurementID, length=32)
//
// where measurementID is the ASCII of the run's canonical lowercase UUID.
func DeriveAK(k []byte, measurementID []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, k, nil, measurementID)
	ak := make([]byte, 32)
	if _, err := io.ReadFull(r, ak); err != nil {
		return nil, fmt.Errorf("tagspec: HKDF failed: %w", err)
	}
	return ak, nil
}

// ComputeTag is the 16-bit tag of an already canonical input: the low 16 bits
// of SipHash-2-4 keyed with ak[0:16]. Every input byte is hashed; HashInput
// bounds a packet's input to MaxInput bytes.
func ComputeTag(ak, input []byte) (uint16, error) {
	if len(ak) < 16 {
		return 0, fmt.Errorf("tagspec: ak too short")
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

// PacketID returns the Identification field of an IPv4 packet, where the tag
// is carried, and false for a packet too short to hold it.
func PacketID(packet []byte) (uint16, bool) {
	if len(packet) < 6 {
		return 0, false
	}
	return binary.BigEndian.Uint16(packet[4:6]), true
}
