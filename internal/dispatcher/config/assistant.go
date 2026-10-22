// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strings"
)

// AssistantConfig enables graph authoring through an operator-selected model.
// APIKeyFile contains the provider credential; an empty path selects the
// DEBUGLET_ASSISTANT_API_KEY environment variable instead.
type AssistantConfig struct {
	Enabled           bool   `toml:"enabled"`
	Endpoint          string `toml:"endpoint"`
	Model             string `toml:"model"`
	APIKeyFile        string `toml:"api_key_file"`
	AllowInsecureHTTP bool   `toml:"allow_insecure_http"`
	ReasoningEffort   string `toml:"reasoning_effort"`
}

func (cfg AssistantConfig) Validate() error {
	if !cfg.Enabled {
		return nil
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && (cfg.AllowInsecureHTTP || net.ParseIP(u.Hostname()).IsLoopback()))) {
		return errors.New("studio.assistant.endpoint requires HTTPS, literal loopback HTTP or allow_insecure_http; URL credentials, query and fragment are forbidden")
	}
	if strings.TrimSpace(cfg.Model) == "" || len(cfg.Model) > 128 || strings.TrimSpace(cfg.Model) != cfg.Model || strings.ContainsAny(cfg.Model, "\r\n\x00") {
		return errors.New("studio.assistant.model must be a non-empty model identifier of at most 128 bytes")
	}
	switch cfg.ReasoningEffort {
	case "", "low", "high", "max":
	default:
		return errors.New("studio.assistant.reasoning_effort must be empty, low, high or max")
	}
	if cfg.APIKeyFile != "" && (!filepath.IsAbs(cfg.APIKeyFile) || filepath.Clean(cfg.APIKeyFile) != cfg.APIKeyFile || strings.ContainsAny(cfg.APIKeyFile, "\r\n\x00")) {
		return errors.New("studio.assistant.api_key_file must be a clean absolute path")
	}
	return nil
}
