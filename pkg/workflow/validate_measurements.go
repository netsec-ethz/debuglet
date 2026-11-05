// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"fmt"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

func validateMeasurementInputs(n Node, add func(string, string, string)) {
	enum := func(field string, values ...string) {
		if value, ok := n.Inputs[field].(string); ok && !slices.Contains(values, value) {
			add(n.ID, field, "choose "+strings.Join(values, ", "))
		}
	}
	integer := func(field string, max int) {
		if value, ok := asNumber(n.Inputs[field]); ok && (value < 1 || value > float64(max) || math.Trunc(value) != value) {
			add(n.ID, field, fmt.Sprintf("must be an integer from 1 to %d", max))
		}
	}
	validateSCIONInputs(n, add)
	switch n.Block {
	case "log_event":
		if value, ok := n.Inputs["message"].(string); ok && (!utf8.ValidString(value) || strings.TrimSpace(value) == "" || len(value) > 1024) {
			add(n.ID, "message", "must contain 1–1024 UTF-8 bytes and not be blank")
		}
	case "plot_sample":
		for _, field := range []struct {
			name     string
			min, max int
		}{{"name", 1, 160}, {"series", 0, 160}, {"unit", 0, 40}} {
			if value, ok := n.Inputs[field.name].(string); ok && (!utf8.ValidString(value) || len(value) < field.min || len(value) > field.max) {
				add(n.ID, field.name, fmt.Sprintf("must contain %d–%d UTF-8 bytes", field.min, field.max))
			}
		}
	case "dns_query":
		enum("transport", "udp", "tcp")
		if resolver, ok := n.Inputs["resolver"].(string); ok {
			host, port, err := net.SplitHostPort(resolver)
			p, parseErr := strconv.Atoi(port)
			if err != nil || net.ParseIP(host) == nil || parseErr != nil || p < 1 || p > 65535 {
				add(n.ID, "resolver", "enter a resolver IP and port, such as 192.0.2.53:53")
			}
		}
	case "scion_udp_exchange", "scion_receive":
		enum("encoding", "text", "hex", "base64")
		integer("max_bytes", 4096)
	case "scion_reply":
		enum("encoding", "text", "hex", "base64")
	case "udp_exchange":
		enum("encoding", "text", "hex", "base64")
		integer("max_bytes", 8191)
	case "tcp_exchange":
		enum("delimiter_encoding", "text", "hex", "base64")
		enum("encoding", "text", "hex", "base64")
		enum("read_until", "delimiter", "bytes", "eof")
		integer("max_bytes", 8192)
		if mode, _ := n.Inputs["read_until"].(string); mode == "" || mode == "delimiter" {
			if delimiter, ok := n.Inputs["delimiter"].(string); ok && delimiter == "" {
				add(n.ID, "delimiter", "delimiter must not be empty")
			}
		}
	case "udp_receive":
		enum("encoding", "text", "hex", "base64")
		integer("max_bytes", 8192)
	case "udp_reply":
		enum("encoding", "text", "hex", "base64")
	case "hop_probe":
		integer("ttl", 255)
	}
}
