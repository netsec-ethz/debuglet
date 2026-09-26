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

	"golang.org/x/sys/unix"
)

// WrapDatagram returns conn wrapped so that every Write leaves as one IPv4
// packet whose IP ID carries this run's tag, as the eBPF tagger would have
// written it. conn is a connected UDP socket or a connected ip4:icmp socket
// to an IPv4 destination. UDP is sent through a separate raw socket and ICMP
// through conn itself with IP_HDRINCL, so both need CAP_NET_RAW; replies keep
// arriving on conn. Any other connection is refused with ErrDatagramUntagged
// and stays usable untagged.
func (t *Tagger) WrapDatagram(conn net.Conn) (net.Conn, error) {
	switch c := conn.(type) {
	case *net.UDPConn:
		local, lok := c.LocalAddr().(*net.UDPAddr)
		remote, rok := c.RemoteAddr().(*net.UDPAddr)
		if !lok || !rok || local.IP.To4() == nil || remote.IP.To4() == nil {
			return nil, ErrDatagramUntagged
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
		if err != nil {
			return nil, fmt.Errorf("%w: raw socket: %v", ErrDatagramUntagged, err)
		}
		return &taggedDatagramConn{
			Conn: c, tagger: t, protocol: protoUDP, rawFD: fd,
			src: local.IP.To4(), dst: remote.IP.To4(),
			srcPort: uint16(local.Port), dstPort: uint16(remote.Port),
		}, nil
	case *net.IPConn:
		remote, ok := c.RemoteAddr().(*net.IPAddr)
		if !ok || remote.IP.To4() == nil {
			return nil, ErrDatagramUntagged
		}
		src, err := sourceFor(remote.IP)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDatagramUntagged, err)
		}
		if err := setHeaderIncluded(c); err != nil {
			return nil, fmt.Errorf("%w: IP_HDRINCL: %v", ErrDatagramUntagged, err)
		}
		return &taggedDatagramConn{
			Conn: c, tagger: t, protocol: protoICMP, rawFD: -1,
			src: src, dst: remote.IP.To4(),
		}, nil
	}
	return nil, ErrDatagramUntagged
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

func setHeaderIncluded(c *net.IPConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		optErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	}); err != nil {
		return err
	}
	return optErr
}

// taggedDatagramConn sends each Write as one tagged IPv4 packet. Reads,
// addresses and deadlines are the wrapped connection's; a UDP write does not
// observe the write deadline, since a raw send does not block on the peer.
type taggedDatagramConn struct {
	net.Conn
	tagger           *Tagger
	protocol         uint8
	rawFD            int
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
	if c.protocol == protoICMP {
		if _, err := c.Conn.Write(tagged); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	err = unix.Sendto(c.rawFD, tagged, 0, &unix.SockaddrInet4{Addr: [4]byte(c.dst)})
	if errors.Is(err, unix.EMSGSIZE) {
		// A raw packet is never fragmented. A datagram larger than the path
		// allows leaves through the UDP socket, untagged, as the kernel
		// would have fragmented it.
		return c.Conn.Write(b)
	}
	if err != nil {
		return 0, &net.OpError{Op: "write", Net: "udp", Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: err}
	}
	return len(b), nil
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
		var rawErr error
		if c.rawFD >= 0 {
			rawErr = unix.Close(c.rawFD)
		}
		c.closeErr = errors.Join(c.Conn.Close(), rawErr)
	})
	return c.closeErr
}
