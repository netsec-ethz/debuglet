// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/netsec-ethz/debuglet/internal/configcheck"
)

type DispatcherConfig struct {
	Server      ServerConfig      `toml:"server"`
	Logging     LoggingConfig     `toml:"logging"`
	Scheduler   SchedulerConfig   `toml:"scheduler"`
	TLS         TLSConfig         `toml:"tls"`
	Database    DatabaseConfig    `toml:"database"`
	Sui         SuiConfig         `toml:"sui"`
	CORS        CORSConfig        `toml:"cors"`
	GitHubOAuth GitHubOAuthConfig `toml:"github_oauth"`
}

type GitHubOAuthConfig struct {
	Enabled     bool   `toml:"enabled"`
	CallbackURL string `toml:"callback_url"`
	SuccessURL  string `toml:"success_url"`
}

type ServerConfig struct {
	BindHost string `toml:"bind_host"`
	Version  string `toml:"version"`
	GRPCPort int    `toml:"grpc_port"`
	HTTPPort int    `toml:"http_port"`
	// LocalDevelopment asks the HTTP API for its local development profile, in
	// which a request that presents no credential at all is served as the
	// dispatcher's own local operator. It is an explicit opt-in and is never
	// inferred: the daemon additionally requires the environment it describes
	// (blockchain payments off, TLS listener off, both listeners on loopback)
	// and refuses to start when the key is set without it. Omitted or false
	// keeps authentication and authorization enforced.
	LocalDevelopment bool `toml:"local_development"`
	// BehindTLSTerminator states that a TLS terminator stands in front of this
	// dispatcher, so the session cookie is marked Secure although the daemon
	// itself serves cleartext. It is configuration because a request cannot be
	// trusted to describe its own scheme: X-Forwarded-Proto and its relatives
	// are set by whoever sent the request.
	BehindTLSTerminator bool `toml:"behind_tls_terminator"`
}

type LoggingConfig struct {
	LogLevel string `toml:"log_level"`
	JSONLogs bool   `toml:"json_logs"`
}

type SchedulerConfig struct {
	// ExecutorTimeout is the negotiated control lease in seconds, from 1 to 300.
	// Heartbeat telemetry is separate from lease renewal.
	ExecutorTimeout int `toml:"executor_timeout"`
	// SchedulerGranularityMs is the scheduler granularity in milliseconds for time-range capacity tracking.
	SchedulerGranularityMs int64 `toml:"scheduler_granularity_ms"`
}

type TLSConfig struct {
	Disable  bool   `toml:"disable"`
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
	CAFile   string `toml:"ca_file,omitempty"` // optional for client cert validation
	// RequireClientCert makes an executor present a certificate issued by
	// CAFile on both control channels: the direct gRPC listener refuses a
	// missing identity during the handshake, and the reverse control stream
	// on the combined listener is refused after it. The HTTP API shares that
	// listener and keeps working without a client certificate.
	RequireClientCert bool `toml:"require_client_cert"`
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
	// Disabled switches blockchain payments off explicitly. When true, the
	// dispatcher constructs neither the Sui client/listener nor the payout
	// ticker and rejects USDC/SUI payment actions; TEST payments keep working.
	// The other Sui fields are ignored in that mode. Omitted or false keeps
	// the enabled semantics unchanged; nothing is inferred from empty fields.
	Disabled bool `toml:"disabled"`
}

// Documented defaults for keys the configuration file may omit.
const (
	DefaultExecutorTimeout = 60
	DefaultLogLevel        = "info"
	DefaultVersion         = "unknown"
)

// Documented bounds for the negotiated control lease, in seconds.
const (
	MinExecutorTimeout = 1
	MaxExecutorTimeout = 300
)

// LoadConfig reads a TOML config file, applies the documented defaults for
// omitted keys and validates every supported key. It fails before the command
// opens the database or binds a listener, so a misspelled or unusable field
// never reaches a partially started daemon.
func LoadConfig(path string) (*DispatcherConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	var cfg DispatcherConfig
	document, err := configcheck.Decode(data, &cfg)
	if err != nil {
		return nil, err
	}
	if !document.Set("scheduler", "executor_timeout") {
		cfg.Scheduler.ExecutorTimeout = DefaultExecutorTimeout
	}
	if !document.Set("logging", "log_level") {
		cfg.Logging.LogLevel = DefaultLogLevel
	}
	if !document.Set("server", "version") {
		cfg.Server.Version = DefaultVersion
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate reports the first unusable configuration field. Defaults for omitted
// keys are applied by LoadConfig before this runs, so every value seen here is
// the one the daemon would actually use.
func (cfg *DispatcherConfig) Validate() error {
	if cfg.Server.BindHost != "" {
		// An empty bind host keeps the documented "all interfaces" binding.
		if err := configcheck.Host("server.bind_host", cfg.Server.BindHost); err != nil {
			return err
		}
	}
	if err := configcheck.Port("server.http_port", cfg.Server.HTTPPort); err != nil {
		return err
	}
	if err := configcheck.Port("server.grpc_port", cfg.Server.GRPCPort); err != nil {
		return err
	}
	// Port zero asks the operating system for an unused port for each listener.
	if cfg.Server.HTTPPort != 0 && cfg.Server.HTTPPort == cfg.Server.GRPCPort {
		return fmt.Errorf("server.http_port and server.grpc_port must differ, both are %d", cfg.Server.HTTPPort)
	}
	if cfg.Server.Version == "" {
		return errors.New("server.version must not be empty")
	}
	// The local development profile serves unauthenticated requests as an
	// operator, so the keys that describe a local environment must agree with
	// it here, before a listener exists. Whether the listeners are actually on
	// loopback is checked by the daemon once they are bound.
	if cfg.Server.LocalDevelopment {
		switch {
		case !cfg.TLS.Disable:
			return errors.New("server.local_development requires tls.disable = true; it serves unauthenticated requests as an operator and is only for a local environment")
		case !cfg.Sui.Disabled:
			return errors.New("server.local_development requires sui.disabled = true; it serves unauthenticated requests as an operator and is only for a local environment")
		case cfg.Server.BindHost == "":
			return errors.New("server.local_development requires server.bind_host to be a loopback address; it serves unauthenticated requests as an operator and must not listen on every interface")
		}
	}
	if err := configcheck.LogLevel("logging.log_level", cfg.Logging.LogLevel); err != nil {
		return err
	}
	// Validate before the command converts seconds to a time.Duration. This
	// also rejects an overflowing operator value without wrapping it positive.
	if cfg.Scheduler.ExecutorTimeout < MinExecutorTimeout || cfg.Scheduler.ExecutorTimeout > MaxExecutorTimeout {
		return fmt.Errorf("scheduler.executor_timeout must be between %d and %d seconds, got %d",
			MinExecutorTimeout, MaxExecutorTimeout, cfg.Scheduler.ExecutorTimeout)
	}
	if err := configcheck.Milliseconds("scheduler.scheduler_granularity_ms", cfg.Scheduler.SchedulerGranularityMs); err != nil {
		return err
	}
	if err := configcheck.Path("database.path", cfg.Database.Path); err != nil {
		return err
	}
	if err := cfg.validateTLS(); err != nil {
		return err
	}
	for i, origin := range cfg.CORS.AllowedOrigins {
		field := fmt.Sprintf("cors.allowed_origins[%d]", i)
		if origin == "*" {
			return fmt.Errorf("%s: a wildcard cannot be combined with cookie credentials; "+
				"leave cors.allowed_origins empty for credential-free wildcard CORS", field)
		}
		if err := configcheck.Origin(field, origin); err != nil {
			return err
		}
	}
	if cfg.GitHubOAuth.Enabled {
		for field, value := range map[string]string{"github_oauth.callback_url": cfg.GitHubOAuth.CallbackURL, "github_oauth.success_url": cfg.GitHubOAuth.SuccessURL} {
			parsed, err := url.Parse(value)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
				return fmt.Errorf("%s must be an absolute HTTPS URL without credentials or a fragment", field)
			}
		}
	}
	return nil
}

// validateTLS checks that the HTTP API names the certificate files it needs. A
// disabled listener keeps unused paths as they are; nothing reads them in that
// mode. Whether the named files exist depends on the machine, not on the file,
// so TLSFiles checks that at startup.
func (cfg *DispatcherConfig) validateTLS() error {
	if cfg.TLS.Disable {
		if cfg.TLS.RequireClientCert {
			return errors.New("tls.require_client_cert needs tls.disable = false: a plaintext listener has no client certificate to verify")
		}
		return nil
	}
	for _, file := range cfg.TLSFiles() {
		if file.Path == "" {
			return fmt.Errorf("%s is required unless tls.disable is true", file.Field)
		}
	}
	if cfg.TLS.RequireClientCert && cfg.TLS.CAFile == "" {
		return errors.New("tls.require_client_cert needs tls.ca_file, which names the authority that issues executor certificates")
	}
	return nil
}

// ConfiguredFile is a configured path together with the key that named it.
type ConfiguredFile struct {
	Field, Path string
}

// TLSFiles lists the certificate files the HTTP API reads, and nothing when
// TLS is disabled. An optional file is included only when it is configured.
func (cfg *DispatcherConfig) TLSFiles() []ConfiguredFile {
	if cfg.TLS.Disable {
		return nil
	}
	files := []ConfiguredFile{
		{Field: "tls.cert_file", Path: cfg.TLS.CertFile},
		{Field: "tls.key_file", Path: cfg.TLS.KeyFile},
	}
	if cfg.TLS.CAFile != "" {
		files = append(files, ConfiguredFile{Field: "tls.ca_file", Path: cfg.TLS.CAFile})
	}
	return files
}
