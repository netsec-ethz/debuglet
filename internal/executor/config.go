// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package executor

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config represents the structure of executor.toml
type Config struct {
	ExecutorID     string `toml:"executor_id"`
	Version        string `toml:"version"`
	DispatcherAddr string `toml:"dispatcher_addr"`
	LogLevel       string `toml:"log_level"`
	Capacity       int64  `toml:"capacity"`
	TeslaSeed      string `toml:"tesla_seed"`
	TeslaDelay     int64  `toml:"tesla_delay"` // in seconds

	Credentials CredentialConfig `toml:"credentials"`
}

type CredentialConfig struct {
	CACert     string `toml:"ca_cert"`
	ClientCert string `toml:"client_cert"`
	ClientKey  string `toml:"client_key"`
}

const DefaultConfigPath = "/etc/debuglet/executor/executor.toml"

// LoadConfig reads and parses the executor configuration from the given path
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", path)
	}

	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	// Basic validation
	if cfg.Capacity == 0 {
		return nil, fmt.Errorf("invalid config: missing capacity")
	} else if cfg.ExecutorID == "" {
		return nil, fmt.Errorf("invalid config: missing dispatcher_addr")
	} else if cfg.DispatcherAddr == "" {
		return nil, fmt.Errorf("invalid config: missing dispatcher_addr")
	}

	if cfg.TeslaDelay == 0 {
		cfg.TeslaDelay = 3600 // default 1 hour epochs
	}

	return &cfg, nil
}
