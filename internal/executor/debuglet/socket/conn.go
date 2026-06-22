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

package socket

import (
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
	// Future: SocketTypeUDP, SocketTypeRaw
)

// Socket is the common interface for all stream-oriented socket types
// exposed to WASM modules.
type Socket interface {
	io.ReadWriteCloser
	// Type returns the transport type of this socket.
	Type() SocketType
	Addr() string
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
func (s *GenericSocket) Addr() string                { addr, _ := hostFromAddr(s.addr); return addr }
