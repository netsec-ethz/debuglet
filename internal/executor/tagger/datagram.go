// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tagger

import (
	"encoding/binary"
	"errors"
	"net"
)

// ErrDatagramUntagged reports a connection whose datagrams the pure-Go tagger
// cannot tag: not IPv4, not UDP or ICMP, or no raw socket available. The
// caller keeps using the connection untagged.
var ErrDatagramUntagged = errors.New("tagger: datagrams on this connection cannot be tagged in user space")

const (
	protoICMP = 1
	protoUDP  = 17

	ipv4HeaderLen = 20
	udpHeaderLen  = 8
	defaultTTL    = 64
	flagDontFrag  = 0x4000
)

// ipv4Header writes the 20-byte IPv4 header of one unfragmented packet. The
// IP ID and checksum stay zero: TagPacket writes both.
func ipv4Header(pkt []byte, protocol uint8, src, dst net.IP) {
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[6:8], flagDontFrag)
	pkt[8] = defaultTTL
	pkt[9] = protocol
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
}

// buildUDPPacket returns the IPv4 packet that carries payload from src:srcPort
// to dst:dstPort, with a valid UDP checksum and the IP ID left for the tag.
func buildUDPPacket(src, dst net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	pkt := make([]byte, ipv4HeaderLen+udpHeaderLen+len(payload))
	ipv4Header(pkt, protoUDP, src, dst)
	udp := pkt[ipv4HeaderLen:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[udpHeaderLen:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(pkt[12:16], pkt[16:20], udp))
	return pkt
}

// buildICMPPacket returns the IPv4 packet that carries one ICMP message.
func buildICMPPacket(src, dst net.IP, message []byte) []byte {
	pkt := make([]byte, ipv4HeaderLen+len(message))
	ipv4Header(pkt, protoICMP, src, dst)
	copy(pkt[ipv4HeaderLen:], message)
	return pkt
}

// udpChecksum is the RFC 768 checksum over the IPv4 pseudo-header and the
// UDP segment, whose checksum field is zero. A computed zero is sent as all
// ones, since zero means "no checksum".
func udpChecksum(src, dst, segment []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src)
	add(dst)
	sum += protoUDP + uint32(len(segment))
	add(segment)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	if checksum := ^uint16(sum); checksum != 0 {
		return checksum
	}
	return 0xFFFF
}
