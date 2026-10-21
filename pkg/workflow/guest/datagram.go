// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

// UDPListener exposes the listener reserved by the submitted program's policy.
func UDPListener(map[string]any) (map[string]any, error) {
	address, err := debuglet.ListenUDPAddr()
	if err != nil {
		return nil, fmt.Errorf("UDP listener: %w", err)
	}
	return map[string]any{"address": address}, nil
}

func datagramEncoding(inputs map[string]any) (string, error) {
	encoding, err := networkString(inputs, "encoding", "text")
	if err != nil || (encoding != "text" && encoding != "base64") {
		return "", fmt.Errorf("encoding must be text or base64")
	}
	return encoding, nil
}

// UDPReceive waits for one admitted datagram; payload_base64 preserves the
// received bytes even when text decoding replaces invalid UTF-8.
func UDPReceive(inputs map[string]any) (map[string]any, error) {
	timeout, err := networkTimeout(inputs)
	if err != nil {
		return nil, err
	}
	limit, err := networkInteger(inputs, "max_bytes", debuglet.MaxIOBytes, 1, debuglet.MaxIOBytes)
	if err != nil {
		return nil, err
	}
	encoding, err := datagramEncoding(inputs)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": false, "error": "", "source": "", "payload": "", "payload_base64": "", "bytes": float64(0), "truncated": false, "duration_ms": float64(0)}
	start := time.Now()
	defer networkDuration(out, start)
	buf := make([]byte, limit)
	packet, err := debuglet.ReceiveUDPTimeout(buf, timeout)
	if err != nil {
		out["error"] = err.Error()
		return out, nil
	}
	buf = buf[:packet.N]
	encoded := base64.StdEncoding.EncodeToString(buf)
	payload := strings.ToValidUTF8(string(buf), "?")
	if encoding == "base64" {
		payload = encoded
	}
	out["ok"], out["source"], out["payload"], out["payload_base64"] = true, packet.From, payload, encoded
	out["bytes"], out["truncated"] = float64(packet.Size), packet.Truncated
	return out, nil
}

// UDPReply sends from this run's allocated listener to an admitted IP:port.
func UDPReply(inputs map[string]any) (map[string]any, error) {
	timeout, err := networkTimeout(inputs)
	if err != nil {
		return nil, err
	}
	destination, err := networkString(inputs, "destination", "")
	if err != nil {
		return nil, err
	}
	peer, err := netip.ParseAddrPort(destination)
	if err != nil || peer.Port() == 0 {
		return nil, fmt.Errorf("destination must be an IP:port from UDP receive")
	}
	payload, err := networkPayload(inputs)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": false, "error": "", "bytes": float64(0), "duration_ms": float64(0)}
	start := time.Now()
	defer networkDuration(out, start)
	n, err := debuglet.ReplyUDPTimeout(destination, payload, timeout)
	out["bytes"] = float64(n)
	if err != nil {
		out["error"] = err.Error()
	} else {
		out["ok"] = true
	}
	return out, nil
}
