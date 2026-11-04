// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

func SCIONPaths(in map[string]any) (map[string]any, error) {
	return scionPaths(in, debuglet.ListSCIONPaths)
}

func scionPaths(in map[string]any, discover func(string, time.Duration) ([]debuglet.SCIONPath, error)) (map[string]any, error) {
	address, timeout, err := scionTarget(in)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": false, "error": "", "paths": []any{}}
	paths, err := discover(address, timeout)
	if err != nil {
		out["error"] = err.Error()
		return out, nil
	}
	values := make([]any, 0, len(paths))
	for _, path := range paths {
		values = append(values, scionPathObject(path))
	}
	out["ok"], out["paths"] = true, values
	return out, nil
}

func SCIONSelectPath(in map[string]any) (map[string]any, error) {
	return scionSelectPath(in, debuglet.SelectSCIONPath)
}

func scionSelectPath(in map[string]any, selectPath func(string, string, time.Duration) (debuglet.SCIONPath, error)) (map[string]any, error) {
	address, timeout, err := scionTarget(in)
	if err != nil {
		return nil, err
	}
	id, err := scionPathID(in)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": false, "error": "", "path": map[string]any{}, "path_id": ""}
	path, err := selectPath(address, id, timeout)
	if err != nil {
		out["error"] = err.Error()
		return out, nil
	}
	out["ok"], out["path"], out["path_id"] = true, scionPathObject(path), path.ID
	return out, nil
}

func SCIONUDPExchange(in map[string]any) (map[string]any, error) {
	return scionUDPExchange(in, debuglet.ExchangeSCION)
}

func scionUDPExchange(in map[string]any, exchange func(string, string, []byte, int, time.Duration) (debuglet.SCIONExchange, error)) (map[string]any, error) {
	address, timeout, err := scionTarget(in)
	if err != nil {
		return nil, err
	}
	id, err := scionPathID(in)
	if err != nil {
		return nil, err
	}
	payload, err := scionPayload(in)
	if err != nil {
		return nil, err
	}
	limit, err := networkInteger(in, "max_bytes", debuglet.SCIONMaxPayload, 1, debuglet.SCIONMaxPayload)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": false, "error": "", "response": "", "response_base64": "", "sender": "", "path_id": "", "duration_ms": float64(0), "received_bytes": float64(0), "complete": false, "truncated": false}
	start := time.Now()
	result, err := exchange(address, id, payload, limit, timeout)
	out["response"], out["response_base64"] = strings.ToValidUTF8(string(result.Data), "�"), base64.StdEncoding.EncodeToString(result.Data)
	out["sender"], out["path_id"] = result.Sender, result.PathID
	out["received_bytes"], out["truncated"] = float64(result.Size), result.Truncated
	out["duration_ms"] = result.DurationMS
	if err != nil {
		out["error"] = err.Error()
		networkDuration(out, start)
	} else if result.Truncated {
		out["error"] = "SCION response exceeds max_bytes"
	} else {
		out["ok"], out["complete"] = true, true
	}
	return out, nil
}

func SCIONListenerAddress(map[string]any) (map[string]any, error) {
	address, err := debuglet.SCIONListenerAddress()
	out := map[string]any{"ok": err == nil, "error": "", "address": address}
	if err != nil {
		out["error"] = err.Error()
	}
	return out, nil
}

func SCIONReceive(in map[string]any) (map[string]any, error) {
	return scionReceive(in, debuglet.ReceiveSCION)
}

func scionReceive(in map[string]any, receive func(int, time.Duration) (debuglet.SCIONDatagram, error)) (map[string]any, error) {
	timeout, err := networkTimeout(in)
	if err != nil {
		return nil, err
	}
	limit, err := networkInteger(in, "max_bytes", debuglet.SCIONMaxPayload, 1, debuglet.SCIONMaxPayload)
	if err != nil {
		return nil, err
	}
	encoding, err := datagramEncoding(in)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": false, "error": "", "payload": "", "payload_base64": "", "sender": "", "received_at_ms": float64(0), "received_bytes": float64(0), "truncated": false}
	result, err := receive(limit, timeout)
	if err != nil {
		out["error"] = err.Error()
		return out, nil
	}
	encoded := base64.StdEncoding.EncodeToString(result.Data)
	payload := strings.ToValidUTF8(string(result.Data), "�")
	if encoding == "base64" {
		payload = encoded
	}
	out["payload"], out["payload_base64"], out["sender"] = payload, encoded, result.Sender
	out["received_at_ms"], out["received_bytes"], out["truncated"] = float64(result.ReceivedAtMS), float64(result.Size), result.Truncated
	out["ok"] = !result.Truncated
	if result.Truncated {
		out["error"] = "SCION datagram exceeds max_bytes"
	}
	return out, nil
}

func SCIONReply(in map[string]any) (map[string]any, error) {
	return scionReply(in, debuglet.ReplySCION)
}

func scionReply(in map[string]any, reply func(string, []byte, time.Duration) (int, error)) (map[string]any, error) {
	timeout, err := networkTimeout(in)
	if err != nil {
		return nil, err
	}
	sender, err := networkString(in, "sender", "")
	if err != nil || sender == "" {
		return nil, fmt.Errorf("sender must come from Receive SCION UDP")
	}
	payload, err := scionPayload(in)
	if err != nil {
		return nil, err
	}
	n, err := reply(sender, payload, timeout)
	out := map[string]any{"ok": err == nil, "error": "", "bytes_sent": float64(n)}
	if err != nil {
		out["error"] = err.Error()
	}
	return out, nil
}

func scionTarget(in map[string]any) (string, time.Duration, error) {
	address, err := networkString(in, "address", "")
	if err != nil || address == "" {
		return "", 0, fmt.Errorf("address must be a SCION endpoint (ISD-AS,IP:port)")
	}
	timeout, err := networkTimeout(in)
	return address, timeout, err
}

func scionPathID(in map[string]any) (string, error) {
	id, err := networkString(in, "path_id", "")
	if err != nil || strings.TrimSpace(id) == "" {
		return "", fmt.Errorf("path_id must be returned by Discover SCION paths")
	}
	return id, nil
}

func scionPayload(in map[string]any) ([]byte, error) {
	payload, err := networkPayload(in)
	if err == nil && len(payload) > debuglet.SCIONMaxPayload {
		err = fmt.Errorf("SCION payload exceeds 4096 bytes")
	}
	return payload, err
}

func scionPathObject(path debuglet.SCIONPath) map[string]any {
	interfaces := make([]any, 0, len(path.Interfaces))
	for _, intf := range path.Interfaces {
		interfaces = append(interfaces, map[string]any{"ia": intf.IA, "id": float64(intf.ID)})
	}
	return map[string]any{"id": path.ID, "source": path.Source, "destination": path.Destination, "interfaces": interfaces, "hop_count": float64(path.HopCount), "mtu": float64(path.MTU), "expires_ms": float64(path.ExpiresMS)}
}
