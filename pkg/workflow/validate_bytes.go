// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"fmt"
	"math"

	"github.com/netsec-ethz/debuglet/pkg/workflow/internal/bytevalue"
)

// Validate literals only when their encoding is also known. Connected values
// are checked by the same decoder in the generated guest before network I/O.
func validateByteInputs(n Node, connected map[Endpoint]bool, add func(string, string, string)) {
	decode := func(field, encodingField, fallback string, maximum int) ([]byte, bool) {
		if connected[Endpoint{n.ID, encodingField}] {
			return nil, false
		}
		encoding := "text"
		if raw, exists := n.Inputs[encodingField]; exists {
			var ok bool
			encoding, ok = raw.(string)
			if !ok {
				return nil, false // The ordinary port type check reports this.
			}
		}
		if encoding != "text" && encoding != "hex" && encoding != "base64" {
			add(n.ID, encodingField, "choose text, hex, base64")
			return nil, false
		}
		if connected[Endpoint{n.ID, field}] {
			return nil, false
		}
		value := fallback
		if raw, exists := n.Inputs[field]; exists {
			var ok bool
			value, ok = raw.(string)
			if !ok {
				return nil, false
			}
		}
		data, err := bytevalue.Decode(value, encoding, maximum)
		if err != nil {
			add(n.ID, field, err.Error())
		}
		return data, err == nil
	}
	switch n.Block {
	case "byte_payload":
		pattern, known := decode("value", "encoding", "", 8192)
		if raw, exists := n.Inputs["size_bytes"]; exists {
			if size, ok := asNumber(raw); ok {
				if size < -1 || size > 8192 || math.Trunc(size) != size {
					add(n.ID, "size_bytes", "must be -1 to preserve bytes or an integer from 0 to 8192")
				} else if known && size > 0 && len(pattern) == 0 {
					add(n.ID, "value", "must contain a byte when size_bytes is positive")
				}
			}
		}
	case "http":
		decode("body", "encoding", "", 16384)
	case "udp_exchange", "tcp_exchange", "udp_reply", "scion_udp_exchange", "scion_reply":
		maximum := 8192
		if n.Block == "scion_udp_exchange" || n.Block == "scion_reply" {
			maximum = 4096
		}
		decode("payload", "encoding", "", maximum)
		if n.Block == "tcp_exchange" {
			mode, _ := n.Inputs["read_until"].(string)
			if !connected[Endpoint{n.ID, "read_until"}] && (mode == "" || mode == "delimiter") {
				data, known := decode("delimiter", "delimiter_encoding", "\n", 256)
				if known && len(data) == 0 {
					add(n.ID, "delimiter", "must contain at least one decoded byte")
				}
				if maximum, ok := asNumber(n.Inputs["max_bytes"]); known && ok && float64(len(data)) > maximum {
					add(n.ID, "delimiter", fmt.Sprintf("%d decoded bytes must fit within max_bytes", len(data)))
				}
			}
		}
	}
}
