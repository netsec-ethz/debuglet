// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import "testing"

func TestEgressConfigRejectsUnboundedAuthority(t *testing.T) {
	limit := EgressLimits{BitsPerSecond: 8000, BurstBytes: 1024, Bytes: 4096, AttemptsPerSecond: 2, AttemptBurst: 4, Attempts: 32, Targets: 4}
	valid := EgressConfig{Enabled: true, WindowSeconds: 3600, Run: limit, Account: limit, Node: limit, Groups: []EgressGroup{{Name: "local", Prefixes: []string{"127.0.0.0/8"}, Limits: limit}}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*EgressConfig){
		"zero window":       func(c *EgressConfig) { c.WindowSeconds = 0 },
		"zero limit":        func(c *EgressConfig) { c.Account.Bytes = 0 },
		"overflow":          func(c *EgressConfig) { c.Node.Bytes = 1 << 62 },
		"unbounded targets": func(c *EgressConfig) { c.Run.Targets = 257 },
		"unbounded burst":   func(c *EgressConfig) { c.Run.BurstBytes = 17 << 20 },
		"duplicate group":   func(c *EgressConfig) { c.Groups = append(c.Groups, c.Groups[0]) },
		"invalid prefix": func(c *EgressConfig) {
			c.Groups = []EgressGroup{{Name: "bad", Prefixes: []string{"invalid"}, Limits: limit}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := valid
			change(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	if err := (EgressConfig{}).Validate(); err != nil {
		t.Fatalf("disabled default: %v", err)
	}
}
