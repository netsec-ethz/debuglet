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
// (bytes 4–5 of the IPv4 header, big-endian). The IPv4 header checksum is
// recomputed after the field is updated.
//
// # Platform notes
//
// Tagging is performed in pure Go and runs on all platforms. On Linux an
// additional eBPF-based tagger is available for in-kernel, zero-copy tagging
// (see internal/executor/tagger/ebpf).
package tagger

import (
	"encoding/binary"
	"fmt"
	"net"
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

// TagPacket rewrites the IPID field of a raw IPv4 packet and recomputes the
// IPv4 header checksum. The packet is modified in-place; the same slice is
// returned.
//
// The HMAC tag is computed over the packet in canonical form: both the IPID
// field (bytes 4–5) and the IPv4 header checksum field (bytes 10–11) are
// zeroed before hashing. This allows a verifier to reproduce the same hash
// input without knowing the original checksum or IPID values.
//
// If pkt does not begin with a valid IPv4 header (version 4, IHL ≥ 5) the
// packet is returned unmodified without error.
func (t *Tagger) TagPacket(pkt []byte) ([]byte, error) {
	if !isIPv4(pkt) {
		return pkt, nil
	}
	// Canonical form: zero mutable fields before hashing.
	binary.BigEndian.PutUint16(pkt[4:6], 0)   // IPID
	binary.BigEndian.PutUint16(pkt[10:12], 0) // IPv4 checksum
	tag, err := t.schedule.ComputeTagForPacket(time.Now(), t.measurementID, pkt)
	if err != nil {
		return nil, fmt.Errorf("tagger: ComputeTagForPacket: %w", err)
	}
	writeIPID(pkt, tag)
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

// =============================================================================
// WrappedConn — transparent stream socket wrapper
// =============================================================================

// WrappedConn wraps a net.Conn and tags every Write with the Tagger before
// sending. Reads pass through unmodified. All other net.Conn methods delegate
// to the underlying connection.
type WrappedConn struct {
	net.Conn
	tagger TaggerInterface
}

// WrapConn returns a WrappedConn that tags outgoing packets.
func WrapConn(c net.Conn, t TaggerInterface) *WrappedConn {
	return &WrappedConn{Conn: c, tagger: t}
}

// Write tags b before writing it to the underlying connection.
func (w *WrappedConn) Write(b []byte) (int, error) {
	tagged, err := w.tagger.TagPacket(b)
	if err != nil {
		return 0, fmt.Errorf("WrappedConn.Write: %w", err)
	}
	return w.Conn.Write(tagged)
}

// =============================================================================
// WrappedPacketConn — transparent packet socket wrapper
// =============================================================================

// WrappedPacketConn wraps a net.PacketConn and tags every WriteTo call.
type WrappedPacketConn struct {
	net.PacketConn
	tagger TaggerInterface
}

// WrapPacketConn returns a WrappedPacketConn that tags outgoing packets.
func WrapPacketConn(c net.PacketConn, t TaggerInterface) *WrappedPacketConn {
	return &WrappedPacketConn{PacketConn: c, tagger: t}
}

// WriteTo tags b before sending it to addr via the underlying PacketConn.
func (w *WrappedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	tagged, err := w.tagger.TagPacket(b)
	if err != nil {
		return 0, fmt.Errorf("WrappedPacketConn.WriteTo: %w", err)
	}
	return w.PacketConn.WriteTo(tagged, addr)
}
