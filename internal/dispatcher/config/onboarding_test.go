// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"strings"
	"testing"
)

func TestExecutorOnboardingConfig(t *testing.T) {
	const body = `
[database]
path = "dispatcher.db"
[tls]
cert_file = "dispatcher.crt"
key_file = "dispatcher.key"
ca_file = "trusted-ca.crt"
require_client_cert = true
[executor_onboarding]
enabled = true
ca_cert = "enrollment-ca.crt"
ca_key = "enrollment-ca.key"
dispatcher_url = "https://dispatcher.example/api/"
grpc_address = "dispatcher.example:443"
yamux_address = "[::1]:8443"
[executors."existing-node"]
display_name = "Research node"
country = "CH"
`
	cfg, _, err := DecodeConfig([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ExecutorOnboarding.Enabled || cfg.ExecutorOnboarding.CACert != "enrollment-ca.crt" || cfg.ExecutorOnboarding.CAKey != "enrollment-ca.key" || cfg.ExecutorOnboarding.DispatcherURL != "https://dispatcher.example/api/" || cfg.ExecutorOnboarding.GRPCAddress != "dispatcher.example:443" || cfg.ExecutorOnboarding.YamuxAddress != "[::1]:8443" {
		t.Fatalf("onboarding config: %+v", cfg.ExecutorOnboarding)
	}
	if display := cfg.Executors["existing-node"]; display.DisplayName != "Research node" || display.Country != "CH" {
		t.Fatalf("executor display config: %+v", cfg.Executors)
	}
	for _, tc := range []struct{ name, from, to, want string }{
		{"invalid display country", `country = "CH"`, `country = "ZZ"`, "country"},
		{"plaintext", "require_client_cert = true", "disable = true", "requires TLS"},
		{"optional client identity", "require_client_cert = true", "require_client_cert = false", "tls.require_client_cert"},
		{"no signing certificate", `ca_cert = "enrollment-ca.crt"`, `ca_cert = ""`, "executor_onboarding.ca_cert"},
		{"no signing key", `ca_key = "enrollment-ca.key"`, `ca_key = ""`, "executor_onboarding.ca_key"},
		{"HTTP URL", "https://dispatcher.example/api/", "http://dispatcher.example/api/", "executor_onboarding.dispatcher_url"},
		{"URL credentials", "https://dispatcher.example/api/", "https://user:password@dispatcher.example/", "executor_onboarding.dispatcher_url"},
		{"URL query", "https://dispatcher.example/api/", "https://dispatcher.example/?a=b", "executor_onboarding.dispatcher_url"},
		{"URL empty query", "https://dispatcher.example/api/", "https://dispatcher.example/?", "executor_onboarding.dispatcher_url"},
		{"URL fragment", "https://dispatcher.example/api/", "https://dispatcher.example/#section", "executor_onboarding.dispatcher_url"},
		{"URL invalid port", "https://dispatcher.example/api/", "https://dispatcher.example:65536/", "executor_onboarding.dispatcher_url"},
		{"gRPC missing port", `grpc_address = "dispatcher.example:443"`, `grpc_address = "dispatcher.example"`, "executor_onboarding.grpc_address"},
		{"Yamux zero port", `yamux_address = "[::1]:8443"`, `yamux_address = "[::1]:0"`, "executor_onboarding.yamux_address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := DecodeConfig([]byte(strings.Replace(body, tc.from, tc.to, 1)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	for _, body := range []string{baseSections, baseSections + "\n[executor_onboarding]\nenabled = false\nca_key = 'unused'\ndispatcher_url = 'unused'\n"} {
		cfg, _, err := DecodeConfig([]byte(body))
		if err != nil || cfg.ExecutorOnboarding.Enabled {
			t.Fatalf("disabled onboarding: %+v %v", cfg, err)
		}
	}
}
