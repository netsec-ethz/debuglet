// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

func SCIONQUICEchoStart(in map[string]any) (map[string]any, error) {
	return scionQUICEchoStart(in, debuglet.StartSCIONQUICEcho)
}

func scionQUICEchoStart(in map[string]any, start func(time.Duration) (debuglet.SCIONQUICListener, error)) (map[string]any, error) {
	timeout, err := networkTimeout(in)
	if err != nil {
		return nil, err
	}
	listener, err := start(timeout)
	out := map[string]any{"ok": err == nil, "error": "", "address": listener.Address, "certificate_sha256": listener.CertificateSHA256}
	if err != nil {
		out["error"] = err.Error()
	}
	return out, nil
}

func SCIONQUICEchoStop(map[string]any) (map[string]any, error) {
	err := debuglet.StopSCIONQUICEcho()
	out := map[string]any{"ok": err == nil, "error": ""}
	if err != nil {
		out["error"] = err.Error()
	}
	return out, nil
}

func SCIONQUICExchange(in map[string]any) (map[string]any, error) {
	return scionQUICExchange(in, debuglet.ExchangeSCIONQUIC)
}

func scionQUICExchange(in map[string]any, exchange func(string, string, string, []byte, time.Duration) (debuglet.SCIONQUICExchange, error)) (map[string]any, error) {
	address, err := networkString(in, "address", "")
	if err != nil {
		return nil, err
	}
	ms, err := networkInteger(in, "timeout_ms", 5000, 1, 10000)
	if err != nil {
		return nil, err
	}
	id, err := scionPathID(in)
	if err != nil {
		return nil, err
	}
	pin, err := networkString(in, "certificate_sha256", "")
	if err != nil {
		return nil, err
	}
	if _, err = hex.DecodeString(pin); err != nil || len(pin) != 64 || strings.ToLower(pin) != pin {
		return nil, fmt.Errorf("certificate_sha256 must be a trusted 64-character lowercase hexadecimal SHA256 DER leaf pin")
	}
	payload, err := scionPayload(in)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	result, err := exchange(address, id, pin, payload, time.Duration(ms)*time.Millisecond)
	out := map[string]any{"ok": err == nil && result.Verified, "error": "", "response": strings.ToValidUTF8(string(result.Data), "�"), "response_base64": base64.StdEncoding.EncodeToString(result.Data), "sender": result.Sender, "path_id": result.PathID, "handshake_ms": result.HandshakeMS, "duration_ms": result.DurationMS, "verified": result.Verified}
	if err != nil {
		out["error"] = err.Error()
		if result.DurationMS <= 0 {
			networkDuration(out, started)
		}
	} else if !result.Verified {
		out["error"] = "SCION QUIC peer certificate was not verified"
	}
	return out, nil
}
