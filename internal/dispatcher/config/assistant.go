// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"unicode"
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
	PersonalKeyFile   string `toml:"personal_key_file"`
	PersonalModel     string `toml:"personal_model"`
}

func (cfg AssistantConfig) Validate() error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.PersonalKeyFile != "" || cfg.PersonalModel != "" {
		if !privateAssistantPath(cfg.PersonalKeyFile) || !assistantModel(cfg.PersonalModel) {
			return errors.New("personal assistant keys require a clean absolute personal_key_file and a non-empty personal_model of at most 128 bytes")
		}
	}
	if cfg.Endpoint != "" || cfg.PersonalKeyFile == "" {
		u, err := url.Parse(cfg.Endpoint)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" ||
			(u.Scheme != "https" && !(u.Scheme == "http" && (cfg.AllowInsecureHTTP || net.ParseIP(u.Hostname()).IsLoopback()))) {
			return errors.New("studio.assistant.endpoint requires HTTPS, literal loopback HTTP or allow_insecure_http; URL credentials, query and fragment are forbidden")
		}
		if !assistantModel(cfg.Model) {
			return errors.New("studio.assistant.model must be a non-empty model identifier of at most 128 bytes")
		}
	} else if cfg.Model != "" || cfg.APIKeyFile != "" {
		return errors.New("operator assistant model and api_key_file require an endpoint")
	}
	switch cfg.ReasoningEffort {
	case "", "none", "low", "high", "max":
	default:
		return errors.New("studio.assistant.reasoning_effort must be empty, none, low, high or max")
	}
	if cfg.APIKeyFile != "" && !privateAssistantPath(cfg.APIKeyFile) {
		return errors.New("studio.assistant.api_key_file must be a clean absolute path")
	}
	return nil
}

func privateAssistantPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\r\n\x00")
}

func assistantModel(model string) bool {
	return strings.TrimSpace(model) != "" && len(model) <= 128 && strings.TrimSpace(model) == model && !strings.ContainsFunc(model, unicode.IsControl)
}
