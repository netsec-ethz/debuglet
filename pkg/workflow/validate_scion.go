// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/scionproto/scion/pkg/addr"
)

// SCION permissions are scoped to the endpoint host IP. ISD-AS and UDP port
// remain part of the transport address and must not enter IP-only allowlists.
func scionDestinationHost(endpoint string) (string, error) {
	iaText, address, ok := strings.Cut(endpoint, ",")
	ia, err := addr.ParseIA(iaText)
	if !ok || err != nil || ia.ISD() == 0 || ia.AS() == 0 {
		return "", fmt.Errorf("use a SCION endpoint such as 1-ff00:0:110,192.0.2.1:4000")
	}
	host, port, err := net.SplitHostPort(address)
	p, parseErr := strconv.Atoi(port)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || parseErr != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("SCION endpoint requires a literal IP and a port from 1 to 65535")
	}
	return ip.String(), nil
}

func validateSCIONInputs(n Node, add func(string, string, string)) {
	if scionHostFunction(n.Block) == "" {
		return
	}
	if address, ok := n.Inputs["address"].(string); ok {
		if _, err := scionDestinationHost(address); err != nil {
			add(n.ID, "address", err.Error())
		}
	}
	if id, ok := n.Inputs["path_id"].(string); ok && strings.TrimSpace(id) == "" {
		add(n.ID, "path_id", "choose a stable path id returned by Discover SCION paths")
	}
}
