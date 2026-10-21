// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"fmt"
	"github.com/netsec-ethz/debuglet/pkg/debuglet"
	"net"
	"strings"
	"time"
)

func TLSInspect(inputs map[string]any) (map[string]any, error) {
	target, err := networkString(inputs, "target", "")
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || !networkHost(host) || !networkPort(port) {
		return nil, fmt.Errorf("TLS target must be host:port")
	}
	timeout, err := networkTimeout(inputs)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": false, "error": "", "duration_ms": float64(0), "tls_version": "", "cipher": "", "alpn": "", "server_name": "", "peer_address": "", "verified": false, "certificates": []any{}}
	started := time.Now()
	defer networkDuration(out, started)
	info, err := debuglet.InspectTLS(target, timeout)
	if err != nil {
		out["error"] = err.Error()
		return out, nil
	}
	certificates := make([]any, 0, len(info.Certificates))
	for _, cert := range info.Certificates {
		certificates = append(certificates, map[string]any{"subject": cert.Subject, "issuer": cert.Issuer, "not_before": cert.NotBefore, "not_after": cert.NotAfter, "sha256": cert.SHA256})
	}
	out["ok"], out["verified"] = true, info.Verified
	out["tls_version"], out["cipher"], out["alpn"] = info.Version, info.Cipher, info.ALPN
	out["server_name"], out["peer_address"], out["certificates"] = info.ServerName, info.PeerAddress, certificates
	return out, nil
}

func HopProbe(inputs map[string]any) (map[string]any, error) {
	target, err := networkString(inputs, "target", "")
	if err != nil {
		return nil, err
	}
	if !networkHost(target) || strings.Contains(target, ":") {
		return nil, fmt.Errorf("hop target must be an IPv4 address or hostname")
	}
	ttl, err := networkInteger(inputs, "ttl", 1, 1, 255)
	if err != nil {
		return nil, err
	}
	timeout, err := networkTimeout(inputs)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": false, "error": "", "duration_ms": float64(0), "reply_address": "", "icmp_type": float64(-1), "icmp_code": float64(-1), "reached": false}
	started := time.Now()
	reply, err := debuglet.ProbeHop(target, ttl, timeout)
	if err != nil {
		out["error"] = err.Error()
		networkDuration(out, started)
		return out, nil
	}
	out["ok"], out["duration_ms"], out["reply_address"] = true, reply.DurationMS, reply.Address
	out["icmp_type"], out["icmp_code"], out["reached"] = float64(reply.Type), float64(reply.Code), reply.Reached
	return out, nil
}
