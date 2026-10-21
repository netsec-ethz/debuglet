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
	switch n.Block {
	case "dns_query":
		enum("transport", "udp", "tcp")
		if resolver, ok := n.Inputs["resolver"].(string); ok {
			host, port, err := net.SplitHostPort(resolver)
			p, parseErr := strconv.Atoi(port)
			if err != nil || net.ParseIP(host) == nil || parseErr != nil || p < 1 || p > 65535 {
				add(n.ID, "resolver", "enter a resolver IP and port, such as 192.0.2.53:53")
			}
		}
	case "udp_exchange":
		enum("encoding", "text", "base64")
		integer("max_bytes", 8191)
	case "tcp_exchange":
		enum("encoding", "text", "base64")
		enum("read_until", "delimiter", "bytes", "eof")
		integer("max_bytes", 8192)
		if mode, _ := n.Inputs["read_until"].(string); mode == "" || mode == "delimiter" {
			if delimiter, ok := n.Inputs["delimiter"].(string); ok && delimiter == "" {
				add(n.ID, "delimiter", "delimiter must not be empty")
			}
		}
	case "udp_receive":
		enum("encoding", "text", "base64")
		integer("max_bytes", 8192)
	case "udp_reply":
		enum("encoding", "text", "base64")
	case "hop_probe":
		integer("ttl", 255)
	}
}
