// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"errors"
	"io"
	"os"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/studio"
)

func configuredAssistant(cfg config.AssistantConfig) (*studio.Assistant, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	key := os.Getenv("DEBUGLET_ASSISTANT_API_KEY")
	if cfg.APIKeyFile != "" {
		file, err := os.Open(cfg.APIKeyFile)
		if err != nil {
			return nil, errors.New("could not open studio.assistant.api_key_file")
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0037 != 0 {
			return nil, errors.New("studio.assistant.api_key_file must be a private regular file (0600 or 0640)")
		}
		data, err := io.ReadAll(io.LimitReader(file, 8193))
		if err != nil || len(data) > 8192 {
			return nil, errors.New("could not read bounded studio.assistant.api_key_file")
		}
		key = strings.TrimSpace(string(data))
	}
	return studio.NewAssistant(studio.AssistantConfig{Endpoint: cfg.Endpoint, Model: cfg.Model, APIKey: key})
}
