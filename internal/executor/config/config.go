// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package config

import (
	"debuglet/internal/executor/ratelimit"
	"fmt"
	"log"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// ExecutorConfig represents the structure of executor.toml
type ExecutorConfig struct {
	Identity    IdentityConfig
	Dispatcher  DispatcherConfig
	TLS         TLSConfig
	Resources   ResourcesConfig
	Tesla       TeslaConfig
	Network     NetworkConfig
	Logging     LoggingConfig
	Credentials CredentialConfig
	Database    DatabaseConfig
	Pricing     PricingConfig
}

type IdentityConfig struct {
	ExecutorID string `toml:"executor_id"`
	Version    string
}

type DispatcherConfig struct {
	Addr      string
	YamuxAddr string `toml:"yamux_addr"`
}

type TLSConfig struct {
	Disable bool
}

type ResourcesConfig struct {
	Capacity     int64
	MaxDebuglets int `toml:"max_debuglets"`
}

type TeslaConfig struct {
	Seed  string `toml:"seed"`
	Delay int64  `toml:"delay"` // epoch duration, in seconds
	// ChainLength is the number of epochs the hash chain covers. Zero
	// derives it from Delay so the chain lasts tesla.DefaultChainHorizon.
	// The schedule stops advancing once the chain runs out, and packets
	// tagged after that point can never be verified, so this must exceed
	// the executor's expected uptime between restarts.
	ChainLength int64 `toml:"chain_length"`
}

type NetworkConfig struct {
	Interface   string
	PublicHost  string `toml:"public_host"`  // public IP or domain for TCP/UDP listeners; empty disables listening
	PublicPorts string `toml:"public_ports"` // allowed public listener ports as comma-separated ranges, e.g. "2022,2025-3005,56000-62000"
}

type LoggingConfig struct {
	LogLevel string `toml:"log_level"`
	JSONLogs bool   `toml:"json_logs"`
}

type CredentialConfig struct {
	CACert     string `toml:"ca_cert"`
	ClientCert string `toml:"client_cert"`
	ClientKey  string `toml:"client_key"`
}

type DatabaseConfig struct {
	Path string
}

type PricingConfig struct {
	PricePerBwS     int64  `toml:"price_per_bw_s"`
	Currency        string `toml:"currency"`
	SuiWallet       string `toml:"sui_wallet"`
	TrialPriceLimit int64  `toml:"trial_price_limit"`
	TrialTimeLimit  int64  `toml:"trial_time_limit"`
}

const DefaultConfigPath = "/etc/debuglet/executor/executor.toml"

// LoadConfig reads and parses the executor configuration from the given path
func LoadConfig(path string) (*ExecutorConfig, error) {
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

	var cfg ExecutorConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal toml: %w", err)
	}

	// defaults
	if cfg.Logging.LogLevel == "" {
		cfg.Logging.LogLevel = "info"
	}
	if cfg.Resources.MaxDebuglets == 0 {
		cfg.Resources.MaxDebuglets = 100
	}
	if (cfg.Network.PublicHost == "") != (cfg.Network.PublicPorts == "") {
		log.Println("Warning: both public_host and public_ports must be set for TCP/UDP listeners; listening is disabled")
	}

	// Basic validation
	if cfg.Resources.Capacity == 0 {
		return nil, fmt.Errorf("invalid config: missing capacity")
	}
	if cfg.Identity.ExecutorID == "" {
		return nil, fmt.Errorf("invalid config: missing executor_id")
	}
	if cfg.Dispatcher.Addr == "" {
		return nil, fmt.Errorf("invalid config: missing dispatcher.addr")
	}
	if cfg.Dispatcher.YamuxAddr == "" {
		cfg.Dispatcher.YamuxAddr = cfg.Dispatcher.Addr
	}
	if cfg.Network.Interface == "" {
		iface, err := ratelimit.GetDefaultInterface()
		if err == nil {
			cfg.Network.Interface = iface.Name
		} else {
			log.Printf("Warning: could not determine default network interface: %v", err)
		}
	}

	return &cfg, nil
}
