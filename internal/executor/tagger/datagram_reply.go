// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tagger

import (
	"net"
	"syscall"
	"time"
)

// UDPReplyConn exposes one destination of a listener as a write-only connection.
// Closing it does not close the listener. Its caller owns the short-lived write
// deadline and must clear that deadline before another listener operation.
func UDPReplyConn(listener *net.UDPConn, peer *net.UDPAddr) net.Conn {
	return &udpReplyConn{listener: listener, peer: peer}
}

type udpReplyConn struct {
	listener *net.UDPConn
	peer     *net.UDPAddr
}

func (c *udpReplyConn) Read([]byte) (int, error)              { return 0, net.ErrClosed }
func (c *udpReplyConn) Write(b []byte) (int, error)           { return c.listener.WriteToUDP(b, c.peer) }
func (c *udpReplyConn) Close() error                          { return nil }
func (c *udpReplyConn) LocalAddr() net.Addr                   { return c.listener.LocalAddr() }
func (c *udpReplyConn) RemoteAddr() net.Addr                  { return c.peer }
func (c *udpReplyConn) SetDeadline(t time.Time) error         { return c.SetWriteDeadline(t) }
func (c *udpReplyConn) SetReadDeadline(time.Time) error       { return nil }
func (c *udpReplyConn) SetWriteDeadline(t time.Time) error    { return c.listener.SetWriteDeadline(t) }
func (c *udpReplyConn) SyscallConn() (syscall.RawConn, error) { return c.listener.SyscallConn() }
