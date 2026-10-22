// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import "testing"

func TestAssistantConfiguration(t *testing.T) {
	valid := AssistantConfig{Enabled: true, Endpoint: "https://models.example/v1/chat/completions", Model: "glm", APIKeyFile: "/etc/debuglet/model.key"}
	for _, test := range []struct {
		name  string
		edit  func(*AssistantConfig)
		valid bool
	}{
		{"enabled", func(*AssistantConfig) {}, true},
		{"disabled", func(c *AssistantConfig) { *c = AssistantConfig{} }, true},
		{"loopback", func(c *AssistantConfig) { c.Endpoint = "http://127.0.0.1:9090/v1/chat/completions" }, true},
		{"http", func(c *AssistantConfig) { c.Endpoint = "http://models.example/v1/chat/completions" }, false},
		{"explicit http", func(c *AssistantConfig) {
			c.Endpoint = "http://models.example/v1/chat/completions"
			c.AllowInsecureHTTP = true
		}, true},
		{"http opt-in keeps URL checks", func(c *AssistantConfig) { c.Endpoint = "http://secret@models.example"; c.AllowInsecureHTTP = true }, false},
		{"http opt-in rejects other schemes", func(c *AssistantConfig) { c.Endpoint = "ftp://models.example"; c.AllowInsecureHTTP = true }, false},
		{"credentials", func(c *AssistantConfig) { c.Endpoint = "https://secret@models.example" }, false},
		{"query", func(c *AssistantConfig) { c.Endpoint = "https://models.example?key=secret" }, false},
		{"missing model", func(c *AssistantConfig) { c.Model = "" }, false},
		{"relative key", func(c *AssistantConfig) { c.APIKeyFile = "model.key" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := valid
			test.edit(&c)
			err := (StudioConfig{Assistant: c}).Validate()
			if (err == nil) != test.valid {
				t.Fatalf("Validate = %v, valid %v", err, test.valid)
			}
		})
	}
}
