// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

const networkBodyLimit = 16 * 1024

// HTTP performs one request without following redirects. A received response,
// including a non-2xx status, is successful; status checks belong in the graph.
func HTTP(inputs map[string]any) (map[string]any, error) {
	req, timeout, err := networkHTTPRequest(inputs)
	if err != nil {
		return nil, err
	}
	u := req.URL
	out := map[string]any{"ok": false, "error": "", "status": float64(0), "body": "", "headers": map[string]any{}, "duration_ms": float64(0)}
	start := time.Now()
	defer networkDuration(out, start)
	port, transport := u.Port(), "tcp"
	if u.Scheme == "https" {
		transport = "tls"
	}
	if port == "" {
		port = "80"
		if transport == "tls" {
			port = "443"
		}
	}
	conn, err := debuglet.DialTimeout(transport, net.JoinHostPort(u.Hostname(), port), timeout)
	if err != nil {
		out["error"] = err.Error()
		return out, nil
	}
	defer conn.Close()
	deadline := start.Add(timeout)
	if err = conn.SetWriteDeadline(deadline); err == nil {
		err = conn.SetReadDeadline(deadline)
	}
	if err == nil {
		err = req.Write(conn)
	}
	if err == nil {
		var status int
		var body string
		var headers map[string]any
		status, body, headers, err = networkReadHTTP(conn, req)
		out["status"], out["body"], out["headers"] = float64(status), body, headers
	}
	out["ok"] = err == nil
	if err != nil {
		out["error"] = err.Error()
	}
	return out, nil
}

// networkHTTPRequest constructs the exact request before any network access.
func networkHTTPRequest(inputs map[string]any) (*http.Request, time.Duration, error) {
	raw, err := networkString(inputs, "url", "")
	if err != nil {
		return nil, 0, err
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") ||
		!networkHost(u.Hostname()) || u.User != nil || u.Opaque != "" || strings.Contains(raw, "#") ||
		strings.HasSuffix(u.Host, ":") || (u.Port() != "" && !networkPort(u.Port())) {
		return nil, 0, fmt.Errorf("url must be an HTTP(S) URL without credentials or a fragment")
	}
	method, err := networkString(inputs, "method", http.MethodGet)
	if err != nil {
		return nil, 0, err
	}
	body, ok := inputs["body"].(string)
	if _, exists := inputs["body"]; exists && !ok {
		return nil, 0, fmt.Errorf("body must be a string")
	}
	if len(body) > networkBodyLimit {
		return nil, 0, fmt.Errorf("HTTP request body exceeds 16 KiB")
	}
	req, err := http.NewRequest(method, u.String(), strings.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("HTTP request: %w", err)
	}
	timeout, err := networkTimeout(inputs)
	if err != nil {
		return nil, 0, err
	}
	req.Close = true
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "debuglet-workflow/1")
	if value, exists := inputs["headers"]; exists {
		headers, ok := value.(map[string]any)
		if !ok || len(headers) > 64 {
			return nil, 0, fmt.Errorf("headers must be an object with at most 64 fields")
		}
		seen := map[string]bool{}
		size := 0
		for name, raw := range headers {
			value, ok := raw.(string)
			if !ok || !networkHeaderName(name) || !networkHeaderValue(value) {
				return nil, 0, fmt.Errorf("HTTP headers require valid names and string values without control characters")
			}
			key := strings.ToLower(name)
			switch key {
			case "host", "content-length", "transfer-encoding", "connection", "proxy-connection", "keep-alive", "te", "trailer", "upgrade", "expect", "accept-encoding":
				return nil, 0, fmt.Errorf("HTTP header %q is managed by the HTTP block", name)
			}
			if seen[key] {
				return nil, 0, fmt.Errorf("HTTP header %q is specified more than once", name)
			}
			seen[key] = true
			size += len(name) + len(value) + 4
			if size > networkBodyLimit {
				return nil, 0, fmt.Errorf("HTTP request headers exceed 16 KiB")
			}
			req.Header.Set(name, value)
		}
	}
	return req, timeout, nil
}

func networkHeaderName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}

func networkHeaderValue(value string) bool {
	for _, c := range value {
		if c < 32 && c != '\t' || c == 127 {
			return false
		}
	}
	return true
}

// TCPConnect measures resolution and connection establishment, then closes.
func TCPConnect(inputs map[string]any) (map[string]any, error) {
	target, err := networkString(inputs, "target", "")
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || !networkHost(host) || !networkPort(port) {
		return nil, fmt.Errorf("target must be a host:port with a port from 1 to 65535")
	}
	timeout, err := networkTimeout(inputs)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": false, "error": "", "duration_ms": float64(0)}
	start := time.Now()
	defer networkDuration(out, start)
	conn, err := debuglet.DialTimeout("tcp", target, timeout)
	if err == nil {
		err = conn.Close()
	}
	out["ok"] = err == nil
	if err != nil {
		out["error"] = err.Error()
	}
	return out, nil
}

// Ping sends up to ten serial ICMPv4 echo requests. RTTs include only matching
// replies. Loss is a percentage; no successfully sent probes yields 100.
func Ping(inputs map[string]any) (map[string]any, error) {
	target, err := networkString(inputs, "target", "")
	if err != nil {
		return nil, err
	}
	if !networkHost(target) || strings.Contains(target, ":") {
		return nil, fmt.Errorf("target must be an IPv4 address or hostname")
	}
	count, err := networkInteger(inputs, "count", 3, 1, 10)
	if err != nil {
		return nil, err
	}
	timeout, err := networkTimeout(inputs)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": false, "error": "", "rtts_ms": []any{}, "sent": float64(0), "received": float64(0), "loss": float64(100)}
	conn, err := debuglet.DialTimeout("ip4:icmp", target, timeout)
	if err != nil {
		out["error"] = err.Error()
		return out, nil
	}
	defer conn.Close()
	payload := make([]byte, 16)
	if _, err := rand.Read(payload); err != nil {
		return nil, fmt.Errorf("ICMP nonce: %w", err)
	}
	id := binary.BigEndian.Uint16(payload)
	rtts := []any{}
	sent := 0
	var lastErr error
	for seq := 0; seq < count; seq++ {
		start := time.Now()
		deadline := start.Add(timeout)
		err = conn.SetWriteDeadline(deadline)
		if err == nil {
			err = conn.SetReadDeadline(deadline)
		}
		if err == nil {
			packet := networkEcho(id, uint16(seq), payload)
			var n int
			n, err = conn.Write(packet)
			if err == nil && n != len(packet) {
				err = io.ErrShortWrite
			}
		}
		if err != nil {
			lastErr = err
			break
		}
		sent++
		buf := make([]byte, 1500)
		for {
			var n int
			n, err = conn.Read(buf)
			if err != nil {
				lastErr = err
				break
			}
			if networkEchoReply(buf[:n], id, uint16(seq), payload) {
				rtts = append(rtts, float64(time.Since(start))/float64(time.Millisecond))
				break
			}
			if !time.Now().Before(deadline) {
				lastErr = debuglet.ErrTimeout
				break
			}
		}
	}
	out["rtts_ms"], out["sent"], out["received"] = rtts, float64(sent), float64(len(rtts))
	if sent > 0 {
		out["loss"] = 100 * float64(sent-len(rtts)) / float64(sent)
	}
	out["ok"] = len(rtts) == count
	if len(rtts) != count {
		out["error"] = fmt.Sprintf("received %d of %d requested replies", len(rtts), count)
		if lastErr != nil {
			out["error"] = fmt.Sprintf("%s: %v", out["error"], lastErr)
		}
	}
	return out, nil
}

func networkReadHTTP(source io.Reader, req *http.Request) (int, string, map[string]any, error) {
	// Bound status lines and headers as well as the body.
	limited := &io.LimitedReader{R: source, N: 64*1024 + 1}
	reader := bufio.NewReader(limited)
	for n := 0; n < 8; n++ {
		response, err := http.ReadResponse(reader, req)
		if err != nil {
			return 0, "", map[string]any{}, fmt.Errorf("read HTTP response: %w", err)
		}
		if response.StatusCode == http.StatusSwitchingProtocols {
			return response.StatusCode, "", map[string]any{}, fmt.Errorf("HTTP protocol upgrades are unsupported")
		}
		if response.StatusCode < 200 {
			continue
		}
		headers := map[string]any{}
		headerSize := 0
		for name, values := range response.Header {
			items := make([]any, len(values))
			for i, value := range values {
				headerSize += len(name) + len(value) + 4
				items[i] = value
			}
			headers[strings.ToLower(name)] = items
		}
		if len(headers) > 64 || headerSize > networkBodyLimit || checkValue(headers, 0) != nil {
			return response.StatusCode, "", map[string]any{}, fmt.Errorf("HTTP response headers exceed 16 KiB or 64 fields")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, networkBodyLimit+1))
		// The owner closes the underlying socket. Closing Body here could drain
		// an arbitrarily long response before returning its bounded prefix.
		if len(body) > networkBodyLimit {
			body = body[:networkBodyLimit]
			err = fmt.Errorf("HTTP response body exceeds 16 KiB")
		} else if limited.N == 0 {
			err = fmt.Errorf("HTTP response exceeds 64 KiB including headers")
		}
		return response.StatusCode, string(body), headers, err
	}
	return 0, "", map[string]any{}, fmt.Errorf("too many informational HTTP responses")
}

func networkEcho(id, seq uint16, payload []byte) []byte {
	packet := make([]byte, 8+len(payload))
	packet[0] = 8
	binary.BigEndian.PutUint16(packet[4:6], id)
	binary.BigEndian.PutUint16(packet[6:8], seq)
	copy(packet[8:], payload)
	binary.BigEndian.PutUint16(packet[2:4], networkChecksum(packet))
	return packet
}

func networkEchoReply(packet []byte, id, seq uint16, payload []byte) bool {
	if len(packet) >= 20 && packet[0]>>4 == 4 {
		header := int(packet[0]&15) * 4
		length := int(binary.BigEndian.Uint16(packet[2:4]))
		if header < 20 || header > len(packet) || length < header || length > len(packet) || packet[9] != 1 {
			return false
		}
		packet = packet[header:length]
	}
	return len(packet) == 8+len(payload) && packet[0] == 0 && packet[1] == 0 &&
		networkChecksum(packet) == 0 &&
		binary.BigEndian.Uint16(packet[4:6]) == id &&
		binary.BigEndian.Uint16(packet[6:8]) == seq && bytes.Equal(packet[8:], payload)
}

func networkChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func networkString(inputs map[string]any, key, fallback string) (string, error) {
	value, exists := inputs[key]
	if !exists {
		value = fallback
	}
	s, ok := value.(string)
	if !ok || s == "" || s != strings.TrimSpace(s) {
		return "", fmt.Errorf("%s must be a non-empty string without surrounding whitespace", key)
	}
	return s, nil
}

func networkInteger(inputs map[string]any, key string, fallback, minimum, maximum int) (int, error) {
	value, exists := inputs[key]
	if !exists {
		return fallback, nil
	}
	var number float64
	switch v := value.(type) {
	case float64:
		number = v
	case int:
		number = float64(v)
	case json.Number:
		var err error
		number, err = v.Float64()
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer from %d to %d", key, minimum, maximum)
		}
	default:
		return 0, fmt.Errorf("%s must be an integer from %d to %d", key, minimum, maximum)
	}
	if math.IsNaN(number) || math.IsInf(number, 0) || number < float64(minimum) || number > float64(maximum) || math.Trunc(number) != number {
		return 0, fmt.Errorf("%s must be an integer from %d to %d", key, minimum, maximum)
	}
	return int(number), nil
}

func networkTimeout(inputs map[string]any) (time.Duration, error) {
	ms, err := networkInteger(inputs, "timeout_ms", 2000, 1, 60000)
	return time.Duration(ms) * time.Millisecond, err
}

func networkHost(host string) bool {
	if host == "" || strings.ContainsAny(host, " \t\r\n/@?#%[]") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func networkPort(port string) bool {
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n != 0
}

func networkDuration(out map[string]any, start time.Time) {
	out["duration_ms"] = float64(time.Since(start)) / float64(time.Millisecond)
}
