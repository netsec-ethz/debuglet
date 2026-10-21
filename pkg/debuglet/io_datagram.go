// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"fmt"
	"net/netip"
	"time"
)

// UDPDatagram describes one admitted datagram from the run's UDP listener.
// N bytes were copied to the caller's buffer; Size is the full payload size.
// Truncated is true when N < Size. An empty datagram has N == Size == 0.
type UDPDatagram struct {
	N, Size   int
	From      string
	Truncated bool
}

// ReceiveUDPTimeout receives one admitted datagram on the allocated listener.
// The full datagram is charged even when buf is shorter. buf may be at most
// MaxIOBytes bytes. Zero timeout uses the run lifetime; negative expires now.
// A timeout leaves the listener usable. Requires debuglet_io_v1.receive_udp.
func ReceiveUDPTimeout(buf []byte, timeout time.Duration) (UDPDatagram, error) {
	if len(buf) > MaxIOBytes {
		return UDPDatagram{}, ErrTooLarge
	}
	return receiveUDPTimeout(buf, timeout)
}

// ReplyUDPTimeout sends one datagram from the same allocated listener port.
// destination must equal the last admitted UDPDatagram.From, as a numeric IP:port. Outbound policy,
// destination ports, rate limits and tagging apply to every reply. A userspace
// tagger that cannot tag this reply refuses it instead of silently dropping
// attribution. Requires debuglet_io_v1.reply_udp.
func ReplyUDPTimeout(destination string, payload []byte, timeout time.Duration) (int, error) {
	if len(payload) > MaxIOBytes {
		return 0, ErrTooLarge
	}
	address, err := netip.ParseAddrPort(destination)
	if err != nil || address.Port() == 0 {
		return 0, fmt.Errorf("UDP reply requires an IP:port destination")
	}
	return replyUDPTimeout(destination, payload, timeout)
}
