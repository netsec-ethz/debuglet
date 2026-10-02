// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import "testing"

func TestConnectivityConfigurationIsLiteralAndTransportBound(t *testing.T) {
	for _, tc := range []struct {
		cfg              ConnectivityConfig
		plaintext, valid bool
	}{
		{ConnectivityConfig{}, true, true},
		{ConnectivityConfig{IPv4Reflector: "127.0.0.1:4200", IPv6Reflector: "[::1]:4200"}, true, true},
		{ConnectivityConfig{IPv4Reflector: "192.0.2.1:4200"}, true, false},
		{ConnectivityConfig{IPv4Reflector: "192.0.2.1:4200"}, false, true},
		{ConnectivityConfig{IPv4Reflector: "localhost:4200"}, false, false},
		{ConnectivityConfig{IPv4Reflector: "127.0.0.1:0"}, true, false},
		{ConnectivityConfig{IPv4Reflector: "[::1]:4200"}, true, false},
		{ConnectivityConfig{IPv6Reflector: "127.0.0.1:4200"}, true, false},
		{ConnectivityConfig{IPv6Reflector: "[::ffff:127.0.0.1]:4200"}, true, false},
		{ConnectivityConfig{SCIONPathTarget: "1-ff00:0:111"}, true, true},
		{ConnectivityConfig{SCIONPathTarget: "0-0"}, true, false},
	} {
		if err := tc.cfg.Validate(tc.plaintext); (err == nil) != tc.valid {
			t.Errorf("%+v: %v", tc, err)
		}
	}
}
