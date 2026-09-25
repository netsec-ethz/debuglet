// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

//go:build wasip1

package debuglet

import (
	"fmt"
	"io"
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

//go:wasmimport env connect_udp
func connectUDP(addrp, addrLen uint32) int32

//go:wasmimport env accept_tcp
func acceptTCPHost() int32

//go:wasmimport env get_tcp_addr
func getTCPAddr(bufPtr, bufLen uint32) int32

//go:wasmimport env get_udp_addr
func getUDPAddr(bufPtr, bufLen uint32) int32

//go:wasmimport env receive_udp_data
func receiveUDPData(sock, bufp, bufLen uint32) int32

//go:wasmimport env receive_udp_from
func receiveUDPFrom(recvp, recvLen, senderp, senderLen, addrLenp uint32) int32

//go:wasmimport env send_udp_data
func sendUDPData(sock, bufp, bufLen uint32)

//go:wasmimport env receive_tcp_data
func receiveTCPData(sock, bufp, bufLen uint32) int32

//go:wasmimport env send_tcp_data
func sendTCPData(sock, bufp, bufLen uint32)

//go:wasmimport env drain_connection
func drain_connection(sock uint32)

//go:wasmimport env get_remote_addr
func getRemoteAddr(sock, bufPtr, bufLen uint32) int32

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

func dialUDP(addr string) (*Conn, error) {
	if addr == "" {
		return nil, fmt.Errorf("%w: empty address", ErrConnect)
	}
	h := connectUDP(strPtr(addr), uint32(len(addr)))
	if h < 0 {
		return nil, fmt.Errorf("%w: %s", ErrConnect, addr)
	}
	return &Conn{handle: h, tr: transportUDP}, nil
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
	if int(n) > len(buf) {
		return "", fmt.Errorf("debuglet: get_tcp_addr returned %d bytes for a %d-byte buffer", n, len(buf))
	}
	return string(buf[:n]), nil
}

func listenUDPAddr() (string, error) {
	buf := make([]byte, 512)
	n := getUDPAddr(bytePtr(buf), uint32(len(buf)))
	if n < 0 {
		return "", fmt.Errorf("debuglet: get_udp_addr failed. Has the debuglet been started with a UDP listener?")
	}
	if int(n) > len(buf) {
		return "", fmt.Errorf("debuglet: get_udp_addr returned %d bytes for a %d-byte buffer", n, len(buf))
	}
	return string(buf[:n]), nil
}

func readFromUDP(buf []byte) (int, string, error) {
	if len(buf) == 0 {
		return 0, "", fmt.Errorf("debuglet: readfrom requires a non-empty buffer")
	}
	sender := make([]byte, 64)
	var addrLen int32
	n := receiveUDPFrom(bytePtr(buf), uint32(len(buf)), bytePtr(sender), uint32(len(sender)), uint32(uintptr(unsafe.Pointer(&addrLen))))
	if n < 0 {
		return 0, "", fmt.Errorf("debuglet: receive_udp_from failed")
	}
	if int(n) > len(buf) {
		return 0, "", fmt.Errorf("debuglet: receive_udp_from returned %d bytes for a %d-byte buffer", n, len(buf))
	}
	if addrLen < 0 || int(addrLen) > len(sender) {
		return 0, "", fmt.Errorf("debuglet: receive_udp_from returned a %d-byte sender address for a %d-byte buffer", addrLen, len(sender))
	}
	return int(n), string(sender[:addrLen]), nil
}

// Write writes the whole of b to the connection. One host call carries at most
// MaxIOBytes bytes, so a longer stream payload becomes consecutive calls; the
// bytes on a TCP or TLS connection are the same either way.
//
// A datagram cannot be split without changing what the peer receives, so a UDP
// or ICMP payload longer than MaxIOBytes returns ErrTooLarge and sends nothing.
//
// The host send functions do not report short writes: a failure to write aborts
// the guest instead, so Write returns an error only for input it rejects
// itself.
func (c *Conn) Write(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if c.tr != transportTCP && len(b) > MaxIOBytes {
		return fmt.Errorf("%w: %d bytes (limit %d)", ErrTooLarge, len(b), MaxIOBytes)
	}
	for len(b) > 0 {
		chunk := b
		if len(chunk) > MaxIOBytes {
			chunk = chunk[:MaxIOBytes]
		}
		switch c.tr {
		case transportICMP4:
			sendICMP4Data(uint32(c.handle), bytePtr(chunk), uint32(len(chunk)))
		case transportUDP:
			sendUDPData(uint32(c.handle), bytePtr(chunk), uint32(len(chunk)))
		default:
			sendTCPData(uint32(c.handle), bytePtr(chunk), uint32(len(chunk)))
		}
		b = b[len(chunk):]
	}
	return nil
}

// Read reads up to len(b) bytes into b and returns the number of bytes read.
// It follows the io.Reader contract: a short read (0 < n < len(b)) is normal
// and carries no error. One host call transfers at most MaxIOBytes bytes, so a
// larger buffer is filled only that far.
//
// An empty buffer returns (0, nil) without calling the host, even after EOF.
// For TCP streams (ConnectTCP, ConnectTLS and AcceptTCP all use the TCP
// receive import) a host count of zero for a nonempty buffer means the peer
// closed its side and Read returns (0, io.EOF), so io.ReadAll and similar
// helpers terminate normally. For UDP and ICMP a zero count is an empty
// datagram and Read returns (0, nil).
//
// A negative count or a count larger than len(b) is a host-protocol error and
// Read returns 0 bytes with a non-EOF error. Socket errors other than a clean
// TCP EOF, and invalid handles, do not reach this function: the host aborts
// the guest with a trap instead.
func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	var n int32
	switch c.tr {
	case transportICMP4:
		n = receiveICMP4Data(uint32(c.handle), bytePtr(b), uint32(len(b)))
	case transportUDP:
		n = receiveUDPData(uint32(c.handle), bytePtr(b), uint32(len(b)))
	default:
		n = receiveTCPData(uint32(c.handle), bytePtr(b), uint32(len(b)))
	}
	if n < 0 {
		return 0, fmt.Errorf("debuglet: receive failed (handle %d)", c.handle)
	}
	if int(n) > len(b) {
		return 0, fmt.Errorf("debuglet: receive returned %d bytes for a %d-byte buffer (handle %d)", n, len(b), c.handle)
	}
	if n == 0 && c.tr == transportTCP {
		return 0, io.EOF
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

// RemoteAddr returns the remote "host:port" address of the connection.
func (c *Conn) RemoteAddr() (string, error) {
	buf := make([]byte, 512)
	n := getRemoteAddr(uint32(c.handle), bytePtr(buf), uint32(len(buf)))
	if n < 0 {
		return "", fmt.Errorf("debuglet: get_remote_addr failed (handle %d)", c.handle)
	}
	return string(buf[:n]), nil
}
