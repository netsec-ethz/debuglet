// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
)

func TestConfiguredAssistantCredentials(t *testing.T) {
	t.Setenv("DEBUGLET_ASSISTANT_API_KEY", "")
	cfg := config.AssistantConfig{Enabled: true, Endpoint: "https://models.example/v1/chat/completions", Model: "glm"}
	if a, err := configuredAssistant(config.AssistantConfig{}); a != nil || err != nil {
		t.Fatalf("disabled: %v %v", a, err)
	}
	if _, err := configuredAssistant(cfg); err == nil {
		t.Fatal("enabled without credential")
	}
	t.Setenv("DEBUGLET_ASSISTANT_API_KEY", "environment-test-key")
	if a, err := configuredAssistant(cfg); err != nil || a.Model() != "glm" {
		t.Fatalf("environment: %v", err)
	}
	cfg.APIKeyFile = filepath.Join(t.TempDir(), "model.key")
	t.Setenv("DEBUGLET_ASSISTANT_API_KEY", "bad env key")
	if err := os.WriteFile(cfg.APIKeyFile, []byte("file-test-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := configuredAssistant(cfg); err != nil {
		t.Fatalf("private file overrides environment: %v", err)
	}
	if err := os.Chmod(cfg.APIKeyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := configuredAssistant(cfg); err == nil || strings.Contains(err.Error(), "file-test-key") {
		t.Fatalf("public file: %v", err)
	}
	if err := os.Chmod(cfg.APIKeyFile, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.APIKeyFile, []byte(strings.Repeat("x", 8193)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := configuredAssistant(cfg); err == nil {
		t.Fatal("oversized key accepted")
	}
}

func TestConfiguredAssistantForwardsHTTPOptIn(t *testing.T) {
	t.Setenv("DEBUGLET_ASSISTANT_API_KEY", "environment-test-key")
	cfg := config.AssistantConfig{Enabled: true, Endpoint: "http://models.example/v1/chat/completions", Model: "glm", AllowInsecureHTTP: true}
	if _, err := configuredAssistant(cfg); err != nil {
		t.Fatalf("explicit HTTP provider configuration: %v", err)
	}
}
