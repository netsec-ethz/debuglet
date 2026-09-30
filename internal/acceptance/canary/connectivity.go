// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"encoding/json"
	"errors"
)

func checkNodeConnectivity(raw json.RawMessage) error {
	fields, err := strictFields(raw, []string{"schema_version", "ipv4", "ipv6", "tcp_listener", "udp_listener", "scion_listener", "scion_host", "scion_paths", "disagreements"}, nil, nil)
	if err != nil {
		return err
	}
	for _, name := range []string{"ipv4", "ipv6", "tcp_listener", "udp_listener", "scion_listener", "scion_paths"} {
		if _, err := strictFields(fields[name], []string{"state", "reason", "source", "observed_at", "expires_at", "stale"}, []string{"address", "endpoint"}, map[string]bool{"observed_at": true, "expires_at": true}); err != nil {
			return err
		}
	}
	if _, err := strictFields(fields["scion_host"], []string{"value", "source", "observed_at"}, nil, map[string]bool{"value": true, "source": true, "observed_at": true}); err != nil {
		return err
	}
	var disagreements []*string
	if json.Unmarshal(fields["disagreements"], &disagreements) != nil {
		return errors.New("invalid connectivity disagreements")
	}
	for _, value := range disagreements {
		if value == nil {
			return errors.New("invalid connectivity disagreement")
		}
	}
	return nil
}
