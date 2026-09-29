// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

// Package tagger provides a transparent IPv4 IPID tagger that injects a
// 16-bit TESLA-derived authentication tag into every outgoing IPv4 packet.
//
// The tagger operates at the Go socket layer and is invisible to the WASM
// debuglet module. It wraps outgoing net.Conn and net.PacketConn connections
// via WrappedConn / WrappedPacketConn.
//
// # Tag Placement
//
// The 16-bit tag is written into the IPv4 Identification (IPID) field
// (bytes 4–5 of the IPv4 header, big-endian) and DF is set. The IPv4 header
// checksum is recomputed after the fields are updated. The algorithm is the
// versioned tag specification tesla.TagSpec, docs/tag-spec.md.
//
// # Platform notes
//
// Tagging is performed in pure Go and runs on all platforms. On Linux an
// additional eBPF-based tagger is available for in-kernel, zero-copy tagging
// (see internal/executor/tagger/ebpf).
package tagger

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// TaggerInterface is the abstraction used by both the pure-Go tagger and the
// eBPF tagger, enabling performance comparison.
type TaggerInterface interface {
	// TagPacket rewrites the IPID field of the raw IPv4 packet bytes in-place
	// and returns the modified slice. The slice may be the same underlying
	// array as pkt (modified in-place) or a copy.
	TagPacket(pkt []byte) ([]byte, error)
	SetSocketMark(fd int) error
	Close() error
	Schedule() *tesla.KeySchedule
}

// Tagger is the pure-Go IPv4 IPID tagger backed by a TESLA key schedule.
type Tagger struct {
	schedule      *tesla.KeySchedule
	measurementID []byte
}

// New creates a Tagger for the given key schedule and measurement ID.
// measurementID should be the raw bytes of the measurement UUID string.
func New(schedule *tesla.KeySchedule, measurementID []byte) *Tagger {
	mid := make([]byte, len(measurementID))
	copy(mid, measurementID)
	return &Tagger{schedule: schedule, measurementID: mid}
}

// TagPacket writes the tag of the versioned tag specification tesla.TagSpec
// (docs/tag-spec.md) into the IPID field of a raw IPv4 packet, sets DF and
// recomputes the IPv4 header checksum. The packet is modified in-place; the
// same slice is returned.
//
// The tag is computed over the packet's canonical input (tesla.HashInput),
// in which the fields a router, NAT or checksum offload rewrites are zeroed,
// so a verifier reproduces it from the packet it receives. DF is set after
// hashing and is not part of the input.
//
// A packet v1 does not tag (not IPv4, too short, malformed, or a fragment) is
// returned unmodified without error. While the schedule has no usable signing
// key (epoch 0, whose key is the public anchor) the packet is likewise
// returned unmodified and untagged, as on the eBPF path.
func (t *Tagger) TagPacket(pkt []byte) ([]byte, error) {
	now := time.Now()
	if !isIPv4(pkt) || t.schedule.CurrentKey(now) == nil {
		return pkt, nil
	}
	tag, err := t.schedule.ComputeTagForPacket(now, t.measurementID, pkt)
	var unsupported *tesla.UnsupportedError
	if errors.As(err, &unsupported) {
		return pkt, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tagger: ComputeTagForPacket: %w", err)
	}
	writeIPID(pkt, tag)
	pkt[6] |= 0x40 // DF
	recomputeIPv4Checksum(pkt)
	return pkt, nil
}

func (t *Tagger) Schedule() *tesla.KeySchedule {
	return t.schedule
}

func (t *Tagger) SetSocketMark(fd int) error {
	// No-op for pure-Go tagger
	return nil
}

func (t *Tagger) Close() error {
	// No-op for pure-Go tagger
	return nil
}

// isIPv4 returns true if pkt is long enough to hold an IPv4 header with the
// advertised IHL and the version field equals 4.
func isIPv4(pkt []byte) bool {
	if len(pkt) < 20 {
		return false
	}
	version := pkt[0] >> 4
	if version != 4 {
		return false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl {
		return false
	}
	return true
}

// writeIPID writes tag into bytes 4–5 of pkt (the IPv4 Identification field)
// in network (big-endian) byte order.
func writeIPID(pkt []byte, tag uint16) {
	binary.BigEndian.PutUint16(pkt[4:6], tag)
}

// ReadIPID extracts the IPID field from a raw IPv4 packet. Panics if pkt is
// shorter than 6 bytes; callers should validate with isIPv4 first.
func ReadIPID(pkt []byte) uint16 {
	return binary.BigEndian.Uint16(pkt[4:6])
}

// recomputeIPv4Checksum zero-sets bytes 10–11 and writes the RFC 791 one's
// complement checksum over the IP header.
func recomputeIPv4Checksum(pkt []byte) {
	ihl := int(pkt[0]&0x0F) * 4
	// Clear existing checksum.
	pkt[10] = 0
	pkt[11] = 0
	var sum uint32
	for i := 0; i < ihl; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))
}

// IPv4Checksum computes the one's-complement checksum over an IPv4 header
// (helper exposed for tests).
func IPv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
