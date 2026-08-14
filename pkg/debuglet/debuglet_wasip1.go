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

//go:build wasip1

package debuglet

import (
	"fmt"
	"unsafe"
)

// =============================================================================
// Raw host imports (wazero "env" module).
//
// These mirror the functions registered in
// internal/executor/debuglet/debuglet.go. Every address and buffer is passed by
// (pointer, length): a 32-bit offset into this module's linear memory plus a
// length. The SDK does the pointer math so callers never touch unsafe.
// =============================================================================

//go:wasmimport env connect_tcp
func connectTCP(addrp, addrLen uint32) int32

//go:wasmimport env connect_tls
func connectTLS(addrp, addrLen uint32) int32

//go:wasmimport env accept_tcp
func acceptTCPHost() int32

//go:wasmimport env get_tcp_addr
func getTCPAddr(bufPtr, bufLen uint32) int32

//go:wasmimport env receive_tcp_data
func receiveTCPData(sock, bufp, bufLen uint32) int32

//go:wasmimport env send_tcp_data
func sendTCPData(sock, bufp, bufLen uint32)

//go:wasmimport env drain_connection
func drain_connection(sock uint32)

//go:wasmimport env close_tcp
func closeTCP(sock uint32)

//go:wasmimport env connect_icmp4
func connectICMP4(addrp, addrLen uint32) int32

//go:wasmimport env receive_icmp4_data
func receiveICMP4Data(sock, bufp, bufLen uint32) int32

//go:wasmimport env send_icmp4_data
func sendICMP4Data(sock, bufp, bufLen uint32)

//go:wasmimport env close_icmp4
func closeICMP4(sock uint32)

// strPtr returns the linear-memory offset of s's backing bytes. The string must
// stay alive (and not be empty) for the duration of the host call.
func strPtr(s string) uint32 {
	return uint32(uintptr(unsafe.Pointer(unsafe.StringData(s))))
}

// bytePtr returns the linear-memory offset of b's backing array. b must be
// non-empty for the duration of the host call.
func bytePtr(b []byte) uint32 {
	return uint32(uintptr(unsafe.Pointer(&b[0])))
}

func dialTCP(addr string, tls bool) (*Conn, error) {
	if addr == "" {
		return nil, fmt.Errorf("%w: empty address", ErrConnect)
	}
	var h int32
	if tls {
		h = connectTLS(strPtr(addr), uint32(len(addr)))
	} else {
		h = connectTCP(strPtr(addr), uint32(len(addr)))
	}
	if h < 0 {
		return nil, fmt.Errorf("%w: %s", ErrConnect, addr)
	}
	return &Conn{handle: h, tr: transportTCP}, nil
}

func dialICMP4(addr string) (*Conn, error) {
	if addr == "" {
		return nil, fmt.Errorf("%w: empty address", ErrConnect)
	}
	h := connectICMP4(strPtr(addr), uint32(len(addr)))
	if h < 0 {
		return nil, fmt.Errorf("%w: %s", ErrConnect, addr)
	}
	return &Conn{handle: h, tr: transportICMP4}, nil
}

func acceptTCP() (*Conn, error) {
	h := acceptTCPHost()
	if h < 0 {
		return nil, fmt.Errorf("debuglet: accept_tcp failed")
	}
	return &Conn{handle: h, tr: transportTCP}, nil
}

func listenAddr() (string, error) {
	buf := make([]byte, 512)
	n := getTCPAddr(bytePtr(buf), uint32(len(buf)))
	if n < 0 {
		return "", fmt.Errorf("debuglet: get_tcp_addr failed. Has the debuglet been started with a TCP listener?")
	}
	return string(buf[:n]), nil
}

// Write writes the whole of b to the connection. The host send functions do not
// report short writes, so Write returns an error only for invalid input.
func (c *Conn) Write(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	switch c.tr {
	case transportICMP4:
		sendICMP4Data(uint32(c.handle), bytePtr(b), uint32(len(b)))
	default:
		sendTCPData(uint32(c.handle), bytePtr(b), uint32(len(b)))
	}
	return nil
}

// Read reads up to len(b) bytes into b and returns the number of bytes read.
func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	var n int32
	switch c.tr {
	case transportICMP4:
		n = receiveICMP4Data(uint32(c.handle), bytePtr(b), uint32(len(b)))
	default:
		n = receiveTCPData(uint32(c.handle), bytePtr(b), uint32(len(b)))
	}
	if n < 0 {
		return 0, fmt.Errorf("debuglet: receive failed (handle %d)", c.handle)
	}
	return int(n), nil
}

// Close releases the connection's host resources.
func (c *Conn) Close() error {
	switch c.tr {
	case transportICMP4:
		closeICMP4(uint32(c.handle))
	default:
		closeTCP(uint32(c.handle))
	}
	return nil
}

func (c *Conn) Drain() error {
	if c.tr != transportTCP {
		return fmt.Errorf("debuglet: drain only supported for TCP connections")
	}
	drain_connection(uint32(c.handle))
	return nil
}
