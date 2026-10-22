// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"errors"
	"path/filepath"

	"github.com/netsec-ethz/debuglet/internal/configcheck"
)

// StudioConfig enables hosted compilation through a separate local worker.
// An omitted or empty socket_path leaves the routes authenticated but unavailable.
type StudioConfig struct {
	SocketPath string          `toml:"socket_path"`
	Assistant  AssistantConfig `toml:"assistant"`
}

func (cfg StudioConfig) Validate() error {
	if err := cfg.Assistant.Validate(); err != nil {
		return err
	}
	if cfg.SocketPath == "" {
		return nil
	}
	if err := configcheck.Path("studio.socket_path", cfg.SocketPath); err != nil {
		return err
	}
	// Linux sockaddr_un reserves one byte for its terminating NUL. Resolve no
	// files here: the worker may start after the dispatcher, and the proxy must
	// recover when the worker restarts without restarting the dispatcher.
	if !filepath.IsAbs(cfg.SocketPath) || filepath.Clean(cfg.SocketPath) != cfg.SocketPath || len(cfg.SocketPath) > 107 {
		return errors.New("studio.socket_path must be a clean absolute Unix socket path of at most 107 bytes")
	}
	return nil
}
