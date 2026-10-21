// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build wasip1

package debuglet

import (
	"encoding/binary"
	"fmt"
	"time"
)

//go:wasmimport debuglet_io_v1 receive_udp
func socketReceiveUDP(ptr, length, sender, senderLength, metadata uint32, timeout int64) uint64

//go:wasmimport debuglet_io_v1 reply_udp
func socketReplyUDP(addr, addrLength, ptr, length uint32, timeout int64) uint64

func receiveUDPTimeout(buf []byte, timeout time.Duration) (UDPDatagram, error) {
	sender := make([]byte, 128)
	metadata := make([]byte, 12)
	var ptr uint32
	if len(buf) > 0 {
		ptr = bytePtr(buf)
	}
	n, err := ioOutcome(socketReceiveUDP(ptr, uint32(len(buf)), bytePtr(sender), uint32(len(sender)), bytePtr(metadata), int64(timeout)))
	if err != nil {
		return UDPDatagram{}, err
	}
	addrLen := binary.LittleEndian.Uint32(metadata)
	size := int(binary.LittleEndian.Uint32(metadata[4:]))
	truncated := binary.LittleEndian.Uint32(metadata[8:])
	if n < 0 || n > len(buf) || size < n || size > 65535 || addrLen == 0 || addrLen > uint32(len(sender)) || truncated > 1 || (truncated == 1) != (n < size) {
		return UDPDatagram{}, fmt.Errorf("debuglet: invalid UDP receive result")
	}
	return UDPDatagram{N: n, Size: size, From: string(sender[:addrLen]), Truncated: truncated == 1}, nil
}

func replyUDPTimeout(destination string, payload []byte, timeout time.Duration) (int, error) {
	var ptr uint32
	if len(payload) > 0 {
		ptr = bytePtr(payload)
	}
	n, err := ioOutcome(socketReplyUDP(strPtr(destination), uint32(len(destination)), ptr, uint32(len(payload)), int64(timeout)))
	if n < 0 || n > len(payload) {
		return 0, fmt.Errorf("debuglet: invalid UDP reply count")
	}
	return n, err
}
