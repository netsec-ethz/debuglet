// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package socket

import (
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket/netutil"
	"io"
	"net"
)

// SocketType identifies the transport layer of a Socket.
type SocketType int

const (
	SocketTypeTCP SocketType = iota
	SocketTypeTLS
	SocketTypeICMP4
	SocketTypeUDP
	// Future: SocketTypeRaw
)

// Socket is the common interface for all stream-oriented socket types
// exposed to WASM modules.
type Socket interface {
	io.ReadWriteCloser
	// Type returns the transport type of this socket.
	Type() SocketType
	Addr() string
	// RemoteAddr returns the full "host:port" address of the socket's peer.
	RemoteAddr() string
}

type GenericSocket struct {
	conn       net.Conn
	socketType SocketType
	addr       string
}

func NewGenericSocket(conn net.Conn, socketType SocketType, addr string) *GenericSocket {
	return &GenericSocket{conn: conn, socketType: socketType, addr: addr}
}

func (s *GenericSocket) Read(b []byte) (int, error)  { return s.conn.Read(b) }
func (s *GenericSocket) Write(b []byte) (int, error) { return s.conn.Write(b) }
func (s *GenericSocket) Close() error                { return s.conn.Close() }
func (s *GenericSocket) Type() SocketType            { return s.socketType }
func (s *GenericSocket) Addr() string                { addr, _ := netutil.HostFromAddr(s.addr); return addr }
func (s *GenericSocket) RemoteAddr() string          { return s.conn.RemoteAddr().String() }
