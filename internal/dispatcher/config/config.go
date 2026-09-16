// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package config

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

type DispatcherConfig struct {
	Server    ServerConfig    `toml:"server"`
	Logging   LoggingConfig   `toml:"logging"`
	Scheduler SchedulerConfig `toml:"scheduler"`
	TLS       TLSConfig       `toml:"tls"`
	Database  DatabaseConfig  `toml:"database"`
	Sui       SuiConfig       `toml:"sui"`
	CORS      CORSConfig      `toml:"cors"`
}

type ServerConfig struct {
	Version  string `toml:"version"`
	GRPCPort int    `toml:"grpc_port"`
	HTTPPort int    `toml:"http_port"`
}

type LoggingConfig struct {
	LogLevel string `toml:"log_level"`
	JSONLogs bool   `toml:"json_logs"`
}

type SchedulerConfig struct {
	// ExecutorTimeout is the maximum amount of seconds between heartbeats.
	ExecutorTimeout int `toml:"executor_timeout"`
	// SchedulerGranularityMs is the scheduler granularity in milliseconds for time-range capacity tracking.
	SchedulerGranularityMs int64 `toml:"scheduler_granularity_ms"`
}

type TLSConfig struct {
	Disable  bool   `toml:"disable"`
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
	CAFile   string `toml:"ca_file,omitempty"` // optional for client cert validation
}

type DatabaseConfig struct {
	Path string `toml:"path"`
}

type CORSConfig struct {
	// AllowedOrigins is the list of origins allowed to make credentialed
	// (cookie-based) requests to the API. Cookie auth (session_token) only
	// works cross-origin for origins listed here — an empty list leaves CORS
	// wide open ("*") but without credentials, so browser clients can't send
	// the session cookie at all.
	AllowedOrigins []string `toml:"allowed_origins"`
}

type SuiConfig struct {
	Network           string `toml:"network"`       //testnet or mainnet
	GRPCEndpoint      string `toml:"grpc_endpoint"` // host:port, e.g. fullnode.testnet.sui.io:443
	GraphQLURL        string `toml:"graphql_url"`   // Sui GraphQL RPC, used to catch up on PaymentReceipt events by type
	Address           string `toml:"address"`
	PaymentRegistryId string `toml:"payment_registry_id"`
	PaymentKitPackage string `toml:"payment_kit_package"`
	KeystorePath      string `toml:"keystore_path"`
}

// LoadConfig reads a TOML config file and unmarshals it
func LoadConfig(path string) (*DispatcherConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	var cfg DispatcherConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal toml: %w", err)
	}

	if cfg.Logging.LogLevel == "" {
		cfg.Logging.LogLevel = "info"
	}
	if cfg.Server.Version == "" {
		cfg.Server.Version = "unknown"
	}

	return &cfg, nil
}
