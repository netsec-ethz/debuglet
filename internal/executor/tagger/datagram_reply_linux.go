// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package tagger

import (
	"fmt"
	"net"
)

// WrapUDPReply tags a datagram sent from the listener's existing source port.
// The returned connection owns its raw sending socket, never the listener.
// Packet counters must register SendingSyscallConn as for WrapDatagram.
func (t *Tagger) WrapUDPReply(listener *net.UDPConn, peer *net.UDPAddr) (net.Conn, error) {
	local, ok := listener.LocalAddr().(*net.UDPAddr)
	if !ok || peer.IP.To4() == nil {
		return nil, ErrDatagramUntagged
	}
	source := local.IP.To4()
	if source == nil || source.IsUnspecified() {
		var err error
		source, err = sourceFor(peer.IP)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDatagramUntagged, err)
		}
	}
	raw, err := net.ListenIP("ip4:255", nil)
	if err != nil {
		return nil, fmt.Errorf("%w: raw socket: %v", ErrDatagramUntagged, err)
	}
	return &taggedUDPReplyConn{&taggedDatagramConn{
		Conn: UDPReplyConn(listener, peer), raw: raw, tagger: t,
		protocol: protoUDP, src: source, dst: peer.IP.To4(),
		srcPort: uint16(local.Port), dstPort: uint16(peer.Port),
	}}, nil
}

type taggedUDPReplyConn struct{ *taggedDatagramConn }

// A reply never falls back to sending an untagged or fragmented packet.
func (c *taggedUDPReplyConn) Write(payload []byte) (int, error) {
	pkt := buildUDPPacket(c.src, c.dst, c.srcPort, c.dstPort, payload)
	tagged, err := c.tagger.TagPacket(pkt)
	if err != nil {
		return 0, err
	}
	if _, err = c.raw.WriteToIP(tagged, &net.IPAddr{IP: c.dst}); err != nil {
		return 0, err
	}
	return len(payload), nil
}
