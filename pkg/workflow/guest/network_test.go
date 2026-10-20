// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"
)

func TestNetworkInvalidInputsDoNotDial(t *testing.T) {
	for name, test := range map[string]struct {
		run    func(map[string]any) (map[string]any, error)
		inputs map[string]any
	}{
		"HTTP scheme":      {HTTP, map[string]any{"url": "ftp://example.test/"}},
		"HTTP credentials": {HTTP, map[string]any{"url": "https://user:pass@example.test/"}},
		"HTTP fragment":    {HTTP, map[string]any{"url": "https://example.test/#fragment"}},
		"HTTP port":        {HTTP, map[string]any{"url": "https://example.test:0/"}},
		"HTTP method":      {HTTP, map[string]any{"url": "https://example.test/", "method": "GET\r\nX: y"}},
		"HTTP timeout":     {HTTP, map[string]any{"url": "https://example.test/", "timeout_ms": float64(0)}},
		"TCP port":         {TCPConnect, map[string]any{"target": "example.test:65536"}},
		"TCP address":      {TCPConnect, map[string]any{"target": "https://example.test"}},
		"TCP host":         {TCPConnect, map[string]any{"target": "bad host:80"}},
		"Ping IPv6":        {Ping, map[string]any{"target": "::1"}},
		"Ping count":       {Ping, map[string]any{"target": "example.test", "count": float64(11)}},
		"Ping fractional":  {Ping, map[string]any{"target": "example.test", "count": 1.5}},
		"Ping NaN":         {Ping, map[string]any{"target": "example.test", "timeout_ms": math.NaN()}},
		"Ping infinite":    {Ping, map[string]any{"target": "example.test", "timeout_ms": math.Inf(1)}},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := test.run(test.inputs)
			if err == nil || out != nil {
				t.Fatalf("invalid configuration returned output %v, error %v", out, err)
			}
		})
	}
}

func TestNetworkHTTPResponse(t *testing.T) {
	for name, test := range map[string]struct {
		wire    string
		status  int
		body    string
		wantErr string
	}{
		"redirect remains observable": {
			wire:   "HTTP/1.1 301 Moved Permanently\r\nContent-Length: 4\r\nLocation: https://other.test/\r\n\r\nmove",
			status: 301, body: "move",
		},
		"error status remains observable": {
			wire:   "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\ndown",
			status: 503, body: "down",
		},
		"chunked": {
			wire:   "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
			status: 200, body: "body",
		},
		"early hints": {
			wire:   "HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
			status: 200, body: "ok",
		},
		"truncated": {
			wire:   "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nno",
			status: 200, body: "no", wantErr: "unexpected EOF",
		},
		"upgrade": {
			wire:   "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n",
			status: 101, wantErr: "upgrades are unsupported",
		},
		"large body": {
			wire:   fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", networkBodyLimit+1) + strings.Repeat("x", networkBodyLimit+1),
			status: 200, body: strings.Repeat("x", networkBodyLimit), wantErr: "exceeds 16 KiB",
		},
		"oversized headers": {
			wire:    "HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", 70*1024) + "\r\n\r\n",
			wantErr: "read HTTP response",
		},
		"too many hints": {
			wire:    strings.Repeat("HTTP/1.1 103 Early Hints\r\n\r\n", 8),
			wantErr: "too many informational",
		},
	} {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
			status, body, _, err := networkReadHTTP(strings.NewReader(test.wire), req)
			if status != test.status || body != test.body {
				t.Fatalf("response = (%d, %d body bytes), want (%d, %d body bytes)", status, len(body), test.status, len(test.body))
			}
			if test.wantErr == "" && err != nil || test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestNetworkEchoReply(t *testing.T) {
	payload := []byte("probe-nonce-1234")
	request := networkEcho(123, 7, payload)
	if request[0] != 8 || networkChecksum(request) != 0 {
		t.Fatal("request type or checksum is invalid")
	}
	reply := append([]byte(nil), request...)
	reply[0], reply[2], reply[3] = 0, 0, 0
	binary.BigEndian.PutUint16(reply[2:4], networkChecksum(reply))
	ipv4 := make([]byte, 24)
	ipv4[0], ipv4[9] = 0x46, 1
	binary.BigEndian.PutUint16(ipv4[2:4], uint16(len(ipv4)+len(reply)))
	ipv4 = append(ipv4, reply...)
	badChecksum := append([]byte(nil), reply...)
	badChecksum[len(badChecksum)-1] ^= 1
	for name, test := range map[string]struct {
		packet  []byte
		id, seq uint16
		payload []byte
		want    bool
	}{
		"plain reply":   {reply, 123, 7, payload, true},
		"IPv4 options":  {ipv4, 123, 7, payload, true},
		"echo request":  {request, 123, 7, payload, false},
		"wrong id":      {reply, 124, 7, payload, false},
		"wrong seq":     {reply, 123, 8, payload, false},
		"wrong nonce":   {reply, 123, 7, bytes.Repeat([]byte{0}, len(payload)), false},
		"bad checksum":  {badChecksum, 123, 7, payload, false},
		"short reply":   {reply[:7], 123, 7, payload, false},
		"truncated IP":  {ipv4[:len(ipv4)-1], 123, 7, payload, false},
		"extra payload": {append(append([]byte(nil), reply...), 0), 123, 7, payload, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := networkEchoReply(test.packet, test.id, test.seq, test.payload); got != test.want {
				t.Fatalf("match = %v, want %v", got, test.want)
			}
		})
	}
}

func TestNetworkChecksumOddLength(t *testing.T) {
	if got := networkChecksum([]byte{0x01, 0x02, 0x03}); got != 0xfbfd {
		t.Fatalf("checksum = %#x, want 0xfbfd", got)
	}
}
