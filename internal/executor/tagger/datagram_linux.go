// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package tagger

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// WrapDatagram returns conn wrapped so that every Write leaves as one IPv4
// packet whose IP ID carries this run's tag, as the eBPF tagger would have
// written it. conn is a connected UDP socket or a connected ip4:icmp socket
// to an IPv4 destination. The packets are sent through a raw IPPROTO_RAW
// socket of the wrapper's own, which needs CAP_NET_RAW; conn itself is left
// as it is and keeps receiving the replies. Any other connection is refused
// with ErrDatagramUntagged and stays usable untagged.
func (t *Tagger) WrapDatagram(conn net.Conn) (net.Conn, error) {
	wrapped := &taggedDatagramConn{Conn: conn, tagger: t}
	switch c := conn.(type) {
	case *net.UDPConn:
		local, lok := c.LocalAddr().(*net.UDPAddr)
		remote, rok := c.RemoteAddr().(*net.UDPAddr)
		if !lok || !rok || local.IP.To4() == nil || remote.IP.To4() == nil {
			return nil, ErrDatagramUntagged
		}
		wrapped.protocol, wrapped.src, wrapped.dst = protoUDP, local.IP.To4(), remote.IP.To4()
		wrapped.srcPort, wrapped.dstPort = uint16(local.Port), uint16(remote.Port)
	case *net.IPConn:
		remote, ok := c.RemoteAddr().(*net.IPAddr)
		if !ok || remote.IP.To4() == nil {
			return nil, ErrDatagramUntagged
		}
		src, err := sourceFor(remote.IP)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDatagramUntagged, err)
		}
		wrapped.protocol, wrapped.src, wrapped.dst = protoICMP, src, remote.IP.To4()
	default:
		return nil, ErrDatagramUntagged
	}
	// IPPROTO_RAW implies IP_HDRINCL: the kernel sends the header as built.
	// A Go connection rather than a bare descriptor, so that a Write racing
	// Close can never reach a descriptor number reused by another socket.
	raw, err := net.ListenIP("ip4:255", nil)
	if err != nil {
		return nil, fmt.Errorf("%w: raw socket: %v", ErrDatagramUntagged, err)
	}
	wrapped.raw = raw
	return wrapped, nil
}

// sourceFor returns the address the kernel sends from towards dst. The tag
// covers the source address, so the packet must carry it before it is hashed
// rather than have the kernel fill it in afterwards. Connecting a UDP socket
// selects the route without sending anything.
func sourceFor(dst net.IP) (net.IP, error) {
	probe, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dst, Port: 9})
	if err != nil {
		return nil, fmt.Errorf("select source address: %w", err)
	}
	defer probe.Close()
	return probe.LocalAddr().(*net.UDPAddr).IP.To4(), nil
}

// taggedDatagramConn sends each Write as one tagged IPv4 packet through raw.
// Reads and addresses are the wrapped connection's; deadlines apply to both.
type taggedDatagramConn struct {
	net.Conn
	raw              *net.IPConn
	tagger           *Tagger
	protocol         uint8
	src, dst         net.IP
	srcPort, dstPort uint16

	closeOnce sync.Once
	closeErr  error
}

func (c *taggedDatagramConn) Write(b []byte) (int, error) {
	var pkt []byte
	if c.protocol == protoUDP {
		pkt = buildUDPPacket(c.src, c.dst, c.srcPort, c.dstPort, b)
	} else {
		pkt = buildICMPPacket(c.src, c.dst, b)
	}
	tagged, err := c.tagger.TagPacket(pkt)
	if err != nil {
		return 0, err
	}
	if _, err := c.raw.WriteToIP(tagged, &net.IPAddr{IP: c.dst}); err != nil {
		if errors.Is(err, syscall.EMSGSIZE) {
			// A raw packet is never fragmented. A message larger than the
			// path allows leaves through the wrapped socket, untagged, and
			// the kernel fragments it as before.
			return c.Conn.Write(b)
		}
		return 0, err
	}
	return len(b), nil
}

func (c *taggedDatagramConn) SetDeadline(t time.Time) error {
	return errors.Join(c.Conn.SetDeadline(t), c.raw.SetDeadline(t))
}

func (c *taggedDatagramConn) SetWriteDeadline(t time.Time) error {
	return errors.Join(c.Conn.SetWriteDeadline(t), c.raw.SetWriteDeadline(t))
}

// SyscallConn exposes the wrapped socket, which a packet counter attaches to.
func (c *taggedDatagramConn) SyscallConn() (syscall.RawConn, error) {
	sc, ok := c.Conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("tagger: wrapped connection has no syscall.Conn")
	}
	return sc.SyscallConn()
}

func (c *taggedDatagramConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = errors.Join(c.Conn.Close(), c.raw.Close())
	})
	return c.closeErr
}
