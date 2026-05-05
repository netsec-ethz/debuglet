// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package engine

import (
	"crypto/tls"
	"io"
	"net"
)

// SocketType identifies the transport layer of a Socket.
type SocketType int

const (
	SocketTypeTCP SocketType = iota
	SocketTypeTLS
	SocketTypeIP
	SocketTypeUDP
	// Future: SocketTypeUDP, SocketTypeRaw
)

// Socket is the common interface for all stream-oriented socket types
// exposed to WASM modules.
type Socket interface {
	io.ReadWriteCloser
	// Type returns the transport type of this socket.
	Type() SocketType
}

type GenericSocket struct {
	conn       net.Conn
	socketType SocketType
}

func NewGenericSocket(conn net.Conn, socketType SocketType) *GenericSocket {
	return &GenericSocket{conn: conn, socketType: socketType}
}

func (s *GenericSocket) Type() SocketType            { return s.socketType }
func (s *GenericSocket) Read(b []byte) (int, error)  { return s.conn.Read(b) }
func (s *GenericSocket) Write(b []byte) (int, error) { return s.conn.Write(b) }
func (s *GenericSocket) Close() error                { return s.conn.Close() }

// TCPSocket wraps a raw TCP connection.
type TCPSocket struct {
	conn *net.TCPConn
}

func NewTCPSocket(conn *net.TCPConn) *TCPSocket {
	return &TCPSocket{conn: conn}
}

func (s *TCPSocket) Type() SocketType            { return SocketTypeTCP }
func (s *TCPSocket) Read(b []byte) (int, error)  { return s.conn.Read(b) }
func (s *TCPSocket) Write(b []byte) (int, error) { return s.conn.Write(b) }
func (s *TCPSocket) Close() error                { return s.conn.Close() }

// TLSSocket wraps a TLS-over-TCP connection.
type TLSSocket struct {
	conn *tls.Conn
}

func NewTLSSocket(conn *tls.Conn) *TLSSocket {
	return &TLSSocket{conn: conn}
}

func (s *TLSSocket) Type() SocketType            { return SocketTypeTLS }
func (s *TLSSocket) Read(b []byte) (int, error)  { return s.conn.Read(b) }
func (s *TLSSocket) Write(b []byte) (int, error) { return s.conn.Write(b) }
func (s *TLSSocket) Close() error                { return s.conn.Close() }

type IPSocket struct {
	conn *net.IPConn
}

func NewIPSocket(conn *net.IPConn) *IPSocket {
	return &IPSocket{conn: conn}
}

func (s *IPSocket) Type() SocketType            { return SocketTypeIP }
func (s *IPSocket) Read(b []byte) (int, error)  { return s.conn.Read(b) }
func (s *IPSocket) Write(b []byte) (int, error) { return s.conn.Write(b) }
func (s *IPSocket) Close() error                { return s.conn.Close() }
