// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import "testing"

func TestAuthenticationConfiguration(t *testing.T) {
	good := DispatcherConfig{Server: ServerConfig{BehindTLSTerminator: true}, TLS: TLSConfig{Disable: true},
		Authentication: AuthenticationConfig{PublicURL: "https://example.org/api", DeviceVerificationURL: "https://example.org/console/device"},
		CILogonOIDC:    CILogonConfig{Enabled: true, Issuer: "https://cilogon.org", CallbackURL: "https://example.org/api/auth/cilogon/callback", SuccessURL: "https://example.org/console/"}}
	if err := good.validateAuthentication(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*DispatcherConfig)
	}{
		{"unknown issuer", func(c *DispatcherConfig) { c.CILogonOIDC.Issuer = "https://other.example" }},
		{"cross-origin callback", func(c *DispatcherConfig) { c.CILogonOIDC.CallbackURL = "https://other.example/callback" }},
		{"insecure callback", func(c *DispatcherConfig) { c.CILogonOIDC.CallbackURL = "http://example.org/callback" }},
		{"callback query", func(c *DispatcherConfig) { c.CILogonOIDC.CallbackURL += "?redirect=somewhere" }},
		{"missing audience", func(c *DispatcherConfig) { c.Authentication.PublicURL = "" }},
		{"cross-origin device", func(c *DispatcherConfig) { c.Authentication.DeviceVerificationURL = "https://other.example/device" }},
		{"insecure cookies", func(c *DispatcherConfig) { c.Server.BehindTLSTerminator = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := good
			tc.change(&cfg)
			if err := cfg.validateAuthentication(); err == nil {
				t.Fatal("invalid authentication configuration accepted")
			}
		})
	}
}
