// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tesla

import (
	"time"

	"github.com/netsec-ethz/debuglet/pkg/tagspec"
)

// The tag functions of docs/tag-spec.md live in pkg/tagspec so that verifiers
// outside the executor (pkg/client) share this implementation. The names below
// are the executor's view of them.

// TagSpec identifies the packet-tag algorithm this build implements, defined
// in docs/tag-spec.md. Taggers and verifiers of one fleet use one version;
// results record it so evidence names the algorithm its tags follow.
const TagSpec = tagspec.ID

// MaxTagInput is the most packet bytes the tag authenticates.
const MaxTagInput = tagspec.MaxInput

// Reasons why a packet has no v1 tag. The tagger leaves such a packet
// unchanged, and a verifier reports it unsupported rather than unmatched.
const (
	UnsupportedIPv6      = tagspec.UnsupportedIPv6
	UnsupportedNotIPv4   = tagspec.UnsupportedNotIPv4
	UnsupportedTooShort  = tagspec.UnsupportedTooShort
	UnsupportedMalformed = tagspec.UnsupportedMalformed
	UnsupportedFragment  = tagspec.UnsupportedFragment
)

// UnsupportedError is returned for a packet the specification assigns no tag.
type UnsupportedError = tagspec.UnsupportedError

// HashInput returns the canonical tag input of an IPv4 packet (tagspec.HashInput).
func HashInput(packet []byte) ([]byte, error) { return tagspec.HashInput(packet) }

// SipHash24 is standard SipHash-2-4 (tagspec.SipHash24).
func SipHash24(key, data []byte) uint64 { return tagspec.SipHash24(key, data) }

// ComputeTag is the 16-bit tag of an already canonical input (tagspec.ComputeTag).
func ComputeTag(ak, input []byte) (uint16, error) { return tagspec.ComputeTag(ak, input) }

// PacketTag is the v1 tag of an IPv4 packet under ak (tagspec.PacketTag).
func PacketTag(ak, packet []byte) (uint16, error) { return tagspec.PacketTag(ak, packet) }

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
