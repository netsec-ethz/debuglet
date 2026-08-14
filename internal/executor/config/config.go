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

package config

import (
	"debuglet/internal/executor/ratelimit"
	"fmt"
	"log"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// Config represents the structure of executor.toml
type Config struct {
	ExecutorID          string           `toml:"executor_id"`
	Version             string           `toml:"version"`
	DispatcherAddr      string           `toml:"dispatcher_addr"`
	DispatcherYamuxAddr string           `toml:"dispatcher_yamux_addr"`
	LogLevel            string           `toml:"log_level"`
	Capacity            int64            `toml:"capacity"`
	PricePerBw          int64            `toml:"price_per_bw"`
	TeslaSeed           string           `toml:"tesla_seed"`
	TeslaDelay          int64            `toml:"tesla_delay"` // in seconds
	MaxDebuglets        int              `toml:"max_debuglets"`
	Credentials         CredentialConfig `toml:"credentials"`
	DisableTLS          bool             `toml:"disable_tls"`
	JSONLogs            bool             `toml:"json_logs"`
	NetworkInterface    string           `toml:"network_interface"`
	Database            DatabaseConfig   `toml:"database"`
}

type DatabaseConfig struct {
	Path string `toml:"path"`
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

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal toml: %w", err)
	}

	// defaults
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.MaxDebuglets == 0 {
		cfg.MaxDebuglets = 100
	}

	// Basic validation
	if cfg.Capacity == 0 {
		return nil, fmt.Errorf("invalid config: missing capacity")
	}
	if cfg.ExecutorID == "" {
		return nil, fmt.Errorf("invalid config: missing executor_id")
	}
	if cfg.DispatcherAddr == "" {
		return nil, fmt.Errorf("invalid config: missing dispatcher_addr")
	}
	if cfg.DispatcherYamuxAddr == "" {
		cfg.DispatcherYamuxAddr = cfg.DispatcherAddr
	}
	if cfg.NetworkInterface == "" {
		iface, err := ratelimit.GetDefaultInterface()
		if err == nil {
			cfg.NetworkInterface = iface.Name
		} else {
			log.Printf("Warning: could not determine default network interface: %v", err)
		}
	}

	return &cfg, nil
}
