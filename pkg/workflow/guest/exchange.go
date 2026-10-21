// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

// UDPExchange sends one datagram and receives one reply. A response larger than
// max_bytes is incomplete; it is never presented as a successful exchange.
func UDPExchange(inputs map[string]any) (map[string]any, error) {
	return networkExchange(inputs, false)
}

// TCPExchange writes one payload and reads to an explicit framing boundary:
// delimiter (included), exactly max_bytes, or EOF. It never retries a write.
func TCPExchange(inputs map[string]any) (map[string]any, error) {
	return networkExchange(inputs, true)
}

type exchangeConfig struct {
	target, readUntil  string
	payload, delimiter []byte
	limit              int
	timeout            time.Duration
}

func networkExchangeConfig(inputs map[string]any, stream bool) (exchangeConfig, error) {
	var c exchangeConfig
	var err error
	c.target, err = networkString(inputs, "target", "")
	if err != nil {
		return c, err
	}
	host, port, err := net.SplitHostPort(c.target)
	if err != nil || !networkHost(host) || !networkPort(port) {
		return c, fmt.Errorf("target must be a host:port with a port from 1 to 65535")
	}
	c.payload, err = networkPayload(inputs)
	if err != nil {
		return c, err
	}
	maximum := debuglet.MaxIOBytes - 1 // The extra byte detects datagram truncation.
	if stream {
		maximum = debuglet.MaxIOBytes
	}
	c.limit, err = networkInteger(inputs, "max_bytes", 4096, 1, maximum)
	if err != nil {
		return c, err
	}
	c.timeout, err = networkTimeout(inputs)
	if err != nil || !stream {
		return c, err
	}
	c.readUntil, err = networkString(inputs, "read_until", "delimiter")
	if err != nil {
		return c, err
	}
	switch c.readUntil {
	case "delimiter":
		delimiter, exists := inputs["delimiter"]
		if !exists {
			delimiter = "\n"
		}
		text, ok := delimiter.(string)
		if !ok || len(text) == 0 || len(text) > 256 || len(text) > c.limit {
			return c, fmt.Errorf("delimiter must contain 1–256 bytes and fit within max_bytes")
		}
		c.delimiter = []byte(text)
	case "bytes", "eof":
	default:
		return c, fmt.Errorf("read_until must be delimiter, bytes or eof")
	}
	return c, nil
}

func networkPayload(inputs map[string]any) ([]byte, error) {
	value, exists := inputs["payload"]
	if !exists {
		value = ""
	}
	text, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("payload must be a string")
	}
	encoding, err := networkString(inputs, "encoding", "text")
	if err != nil {
		return nil, err
	}
	var payload []byte
	switch encoding {
	case "text":
		payload = []byte(text)
	case "base64":
		if len(text) > base64.StdEncoding.EncodedLen(debuglet.MaxIOBytes) {
			return nil, fmt.Errorf("payload exceeds 8 KiB")
		}
		payload, err = base64.StdEncoding.Strict().DecodeString(text)
		if err != nil {
			return nil, fmt.Errorf("payload must be valid padded base64: %w", err)
		}
	default:
		return nil, fmt.Errorf("encoding must be text or base64")
	}
	if len(payload) > debuglet.MaxIOBytes {
		return nil, fmt.Errorf("payload exceeds 8 KiB")
	}
	return payload, nil
}

func networkExchange(inputs map[string]any, stream bool) (map[string]any, error) {
	c, err := networkExchangeConfig(inputs, stream)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": false, "error": "", "response": "", "response_base64": "", "received_bytes": float64(0), "sent_bytes": float64(0), "duration_ms": float64(0), "complete": false, "truncated": false}
	start := time.Now()
	defer networkDuration(out, start)
	deadline := start.Add(c.timeout)
	transport := "udp"
	if stream {
		transport = "tcp"
	}
	conn, err := debuglet.DialTimeout(transport, c.target, time.Until(deadline))
	if err != nil {
		out["error"] = err.Error()
		return out, nil
	}
	defer conn.Close()
	if err = conn.SetWriteDeadline(deadline); err == nil {
		err = conn.SetReadDeadline(deadline)
	}
	if err == nil {
		var n int
		n, err = conn.Write(c.payload)
		out["sent_bytes"] = float64(n)
		if err == nil && n != len(c.payload) {
			err = io.ErrShortWrite
		}
	}
	var response []byte
	var complete, truncated bool
	if err == nil {
		if stream {
			response, complete, truncated, err = networkReadExchange(conn, c)
		} else {
			buf := make([]byte, c.limit+1)
			var n int
			n, err = conn.Read(buf)
			truncated = n > c.limit
			response = buf[:min(n, c.limit)]
			complete = err == nil && !truncated
			if truncated {
				err = fmt.Errorf("response exceeds max_bytes")
			}
		}
	}
	out["response"] = strings.ToValidUTF8(string(response), "�")
	out["response_base64"] = base64.StdEncoding.EncodeToString(response)
	out["received_bytes"] = float64(len(response))
	out["complete"], out["truncated"], out["ok"] = complete, truncated, err == nil && complete
	if err != nil {
		out["error"] = err.Error()
	}
	return out, nil
}

func networkReadExchange(reader io.Reader, c exchangeConfig) ([]byte, bool, bool, error) {
	buf := make([]byte, c.limit+1)
	n := 0
	for {
		end := len(buf)
		if c.readUntil == "bytes" {
			end = c.limit
		}
		count, err := reader.Read(buf[n:end])
		if count < 0 || count > end-n {
			return buf[:n], false, false, fmt.Errorf("invalid response byte count")
		}
		n += count
		if c.readUntil == "delimiter" {
			if at := bytes.Index(buf[:n], c.delimiter); at >= 0 && at+len(c.delimiter) <= c.limit {
				return buf[:at+len(c.delimiter)], true, false, nil
			}
		}
		if c.readUntil == "bytes" && n == c.limit {
			return buf[:n], true, false, nil
		}
		if n > c.limit {
			return buf[:c.limit], false, true, fmt.Errorf("response exceeds max_bytes")
		}
		if err != nil {
			if err == io.EOF && c.readUntil == "eof" {
				return buf[:n], true, false, nil
			}
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return buf[:n], false, false, err
		}
		if count == 0 {
			return buf[:n], false, false, io.ErrNoProgress
		}
	}
}
