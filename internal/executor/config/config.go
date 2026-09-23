// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package config

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/configcheck"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
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
	// ServerName overrides the dispatcher name verified in the certificate
	// presented on both control channels. Empty verifies the host part of
	// dispatcher.addr and dispatcher.yamux_addr, which is what a certificate
	// issued for the dispatcher's own name carries. Set it when the executor
	// dials an address that is not that name, such as a literal IP or the
	// service name of a TLS terminator standing in front of the dispatcher.
	ServerName string `toml:"server_name"`
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
	PacketCounter string `toml:"packet_counter"` // empty and auto retain interface discovery
	// DisableSCIONEnvironment skips external configuration loading; it does
	// not restrict traffic or enforce a network policy.
	DisableSCIONEnvironment bool `toml:"disable_scion_environment"`
	Interface               string
	PublicHost              string `toml:"public_host"`  // public IP or domain for TCP/UDP listeners; empty disables listening
	PublicPorts             string `toml:"public_ports"` // allowed public listener ports as comma-separated ranges, e.g. "2022,2025-3005,56000-62000"
	// Policy is the operator's traffic policy for guests.
	Policy PolicyConfig `toml:"policy"`
}

// PolicyConfig is the operator's network policy for guest traffic: which
// transports a guest may use and which destinations it may reach on them. It
// is independent of the destinations a submitter declares for a run; both are
// checked, and either one refusing is a refusal.
//
// Every switch is optional and keeps its documented default when the file
// omits it. The defaults are the local profile's: the transports this build
// supports are on, SCION is off, and loopback destinations are reachable while
// the other reserved and internal ranges are not.
type PolicyConfig struct {
	TCP     *bool `toml:"tcp"`
	TLS     *bool `toml:"tls"`
	UDP     *bool `toml:"udp"`
	ICMP    *bool `toml:"icmp"`
	SCION   *bool `toml:"scion"`
	Inbound *bool `toml:"inbound"`
	// LocalTargets keeps loopback destinations reachable. It belongs to the
	// local profile, where the guest, the executor and the measured target run
	// on one machine; an executor that serves submitters it does not trust
	// sets it to false.
	LocalTargets *bool `toml:"local_targets"`
	// DeniedDestinations are operator denials in addition to the reserved and
	// internal ranges, as a comma-separated list of CIDR blocks, IP addresses
	// and DNS names. A name denies the name and the addresses it resolves to,
	// which is how a destination that opted out stays unreachable.
	DeniedDestinations string `toml:"denied_destinations"`
	// PermittedPorts are the destination ports a guest may reach, written as
	// comma-separated ports and ranges. Empty permits every port.
	PermittedPorts string `toml:"permitted_ports"`
}

// Spec resolves the omitted switches to netpolicy.Defaults and returns the
// policy as the enforcement path takes it.
func (cfg PolicyConfig) Spec() netpolicy.Spec {
	spec := netpolicy.Defaults()
	spec.TCP = switchedOn(cfg.TCP, spec.TCP)
	spec.TLS = switchedOn(cfg.TLS, spec.TLS)
	spec.UDP = switchedOn(cfg.UDP, spec.UDP)
	spec.ICMP = switchedOn(cfg.ICMP, spec.ICMP)
	spec.SCION = switchedOn(cfg.SCION, spec.SCION)
	spec.Inbound = switchedOn(cfg.Inbound, spec.Inbound)
	spec.LocalTargets = switchedOn(cfg.LocalTargets, spec.LocalTargets)
	spec.DeniedDestinations = cfg.DeniedDestinations
	spec.PermittedPorts = cfg.PermittedPorts
	return spec
}

// Compile returns the policy the executor applies to every guest transport.
func (cfg PolicyConfig) Compile() (netpolicy.Operator, error) {
	operator, err := netpolicy.Parse(cfg.Spec())
	if err != nil {
		return netpolicy.Operator{}, fmt.Errorf("network.policy.%w", err)
	}
	return operator, nil
}

func switchedOn(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

type LoggingConfig struct {
	LogLevel string `toml:"log_level"`
	JSONLogs bool   `toml:"json_logs"`
}

type CredentialConfig struct {
	CACert     string `toml:"ca_cert"`
	ClientCert string `toml:"client_cert"`
	ClientKey  string `toml:"client_key"`
	// EnrollmentToken is the single-use token an operator created for this
	// executor's ID on the dispatcher host. It is presented once, in the
	// first Hello, to bind this node's client certificate to that ID; after
	// that it is spent and the key can be removed.
	EnrollmentToken string `toml:"enrollment_token"`
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

// Documented defaults for keys the configuration file may omit.
const (
	DefaultLogLevel     = "info"
	DefaultMaxDebuglets = 100
)

// MaxChainLength bounds an explicitly configured TESLA chain. It matches one
// epoch per second over tesla.DefaultChainHorizon, the longest chain the
// executor derives on its own, and keeps the precomputed chain in memory
// bounded. Zero still derives the length from the epoch duration.
const MaxChainLength = int64(tesla.DefaultChainHorizon / time.Second)

// maxInterfaceName is the kernel limit for a network interface name.
const maxInterfaceName = 15

// LoadConfig reads and parses the executor configuration from the given path
func LoadConfig(path string) (*ExecutorConfig, error) {
	return loadConfig(path, ratelimit.GetDefaultInterface)
}

// loadConfig validates every supported key before it looks at the host: the
// default network interface is only discovered once the configuration is known
// to be usable, and well before the node acquires its packet counter.
func loadConfig(path string, defaultInterface func() (*net.Interface, error)) (*ExecutorConfig, error) {
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
	document, err := configcheck.Decode(data, &cfg)
	if err != nil {
		return nil, err
	}

	// defaults
	if !document.Set("logging", "log_level") {
		cfg.Logging.LogLevel = DefaultLogLevel
	}
	if !document.Set("resources", "max_debuglets") {
		cfg.Resources.MaxDebuglets = DefaultMaxDebuglets
	}
	if cfg.Dispatcher.YamuxAddr == "" {
		cfg.Dispatcher.YamuxAddr = cfg.Dispatcher.Addr
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if (cfg.Network.PublicHost == "") != (cfg.Network.PublicPorts == "") {
		log.Println("Warning: both public_host and public_ports must be set for TCP/UDP listeners; listening is disabled")
	}
	if cfg.Network.PacketCounter != "fallback" && cfg.Network.Interface == "" {
		iface, err := defaultInterface()
		if err == nil {
			cfg.Network.Interface = iface.Name
		} else {
			log.Printf("Warning: could not determine default network interface: %v", err)
		}
	}

	return &cfg, nil
}

// Validate reports the first unusable configuration field. Defaults for omitted
// keys are applied by LoadConfig before this runs. Resource, TESLA and payment
// semantics stay with the subsystems that own them; this checks the values the
// daemon needs before it opens storage, connects or acquires a packet counter.
func (cfg *ExecutorConfig) Validate() error {
	if err := configcheck.Label("identity.executor_id", cfg.Identity.ExecutorID, 128); err != nil {
		return err
	}
	if err := configcheck.Endpoint("dispatcher.addr", cfg.Dispatcher.Addr); err != nil {
		return err
	}
	if err := configcheck.Endpoint("dispatcher.yamux_addr", cfg.Dispatcher.YamuxAddr); err != nil {
		return err
	}
	if err := configcheck.LogLevel("logging.log_level", cfg.Logging.LogLevel); err != nil {
		return err
	}
	if err := configcheck.Path("database.path", cfg.Database.Path); err != nil {
		return err
	}
	if err := cfg.validateResources(); err != nil {
		return err
	}
	if err := cfg.validateTesla(); err != nil {
		return err
	}
	if err := cfg.Network.Validate(); err != nil {
		return err
	}
	if err := cfg.validateCredentials(); err != nil {
		return err
	}
	return cfg.validatePricing()
}

func (cfg *ExecutorConfig) validateResources() error {
	if cfg.Resources.Capacity <= 0 {
		return fmt.Errorf("resources.capacity is required and must be positive, got %d", cfg.Resources.Capacity)
	}
	if cfg.Resources.MaxDebuglets <= 0 {
		return fmt.Errorf("resources.max_debuglets must be positive, got %d", cfg.Resources.MaxDebuglets)
	}
	return nil
}

// validateTesla checks the boundaries of the configured numbers. Whether a
// schedule is long enough for the expected uptime remains a TESLA question.
func (cfg *ExecutorConfig) validateTesla() error {
	if err := configcheck.Seconds("tesla.delay", cfg.Tesla.Delay); err != nil {
		return err
	}
	if cfg.Tesla.ChainLength < 0 || cfg.Tesla.ChainLength > MaxChainLength {
		return fmt.Errorf("tesla.chain_length must be between 0 and %d epochs, got %d", MaxChainLength, cfg.Tesla.ChainLength)
	}
	return nil
}

// validateCredentials checks that the executor names the client material it
// needs, and that a plaintext control transport stays inside the profile that
// supports it. Whether the named files exist depends on the machine, not on the
// configuration file; node construction loads them before it acquires anything.
func (cfg *ExecutorConfig) validateCredentials() error {
	// The token enrols the certificate this executor presents, so without one
	// it can never be spent, whether or not the transport is plaintext.
	if cfg.Credentials.EnrollmentToken != "" && cfg.Credentials.ClientCert == "" {
		return errors.New("credentials.enrollment_token needs credentials.client_cert: the token binds the certificate the executor presents, and there is none")
	}
	if cfg.TLS.Disable {
		if cfg.TLS.ServerName != "" {
			return errors.New("tls.server_name names the dispatcher certificate to verify and needs tls.disable = false")
		}
		// A plaintext control transport carries the session token, every
		// uploaded module and every guest output in the clear. It is supported
		// only for the trusted local profile, where the dispatcher runs on this
		// machine. Refuse a remote endpoint rather than downgrade it silently.
		for _, endpoint := range []struct{ field, value string }{
			{"dispatcher.addr", cfg.Dispatcher.Addr},
			{"dispatcher.yamux_addr", cfg.Dispatcher.YamuxAddr},
		} {
			if !loopbackEndpoint(endpoint.value) {
				return fmt.Errorf("%s is %q: tls.disable = true is supported only for a dispatcher reached at a loopback IP address "+
					"such as 127.0.0.1; set tls.disable = false and configure [credentials] to reach %s", endpoint.field, endpoint.value, endpoint.value)
			}
		}
		return nil
	}
	if cfg.TLS.ServerName != "" {
		if err := configcheck.Host("tls.server_name", cfg.TLS.ServerName); err != nil {
			return err
		}
	}
	for _, file := range []struct{ field, path string }{
		{"credentials.client_cert", cfg.Credentials.ClientCert},
		{"credentials.client_key", cfg.Credentials.ClientKey},
	} {
		if file.path == "" {
			return fmt.Errorf("%s is required unless tls.disable is true", file.field)
		}
		if err := configcheck.Path(file.field, file.path); err != nil {
			return err
		}
	}
	// An omitted authority keeps the host's trust store, which is what a
	// dispatcher certificate from a public authority needs.
	if cfg.Credentials.CACert != "" {
		return configcheck.Path("credentials.ca_cert", cfg.Credentials.CACert)
	}
	return nil
}

// loopbackEndpoint reports whether a "host:port" endpoint is a literal loopback
// address. A name is not accepted, even "localhost": configuration is checked
// before the daemon looks at the host, so a name would have to be trusted
// unresolved, and what it resolves to is a property of the machine rather than
// of the file. This is the rule the SDK applies to its own cleartext endpoints.
func loopbackEndpoint(endpoint string) bool {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validatePricing checks the numeric boundaries only. Currency and wallet
// semantics belong to the payment layer that reads them.
func (cfg *ExecutorConfig) validatePricing() error {
	for _, amount := range []struct {
		field string
		value int64
	}{
		{"pricing.price_per_bw_s", cfg.Pricing.PricePerBwS},
		{"pricing.trial_price_limit", cfg.Pricing.TrialPriceLimit},
		{"pricing.trial_time_limit", cfg.Pricing.TrialTimeLimit},
	} {
		if amount.value < 0 {
			return fmt.Errorf("%s must not be negative, got %d", amount.field, amount.value)
		}
	}
	return nil
}

// Validate checks the network keys, including the listener range the port
// manager parses and the interface the packet counter attaches to.
func (cfg NetworkConfig) Validate() error {
	if err := cfg.ValidatePacketCounter(); err != nil {
		return err
	}
	if cfg.Interface != "" && cfg.PacketCounter != "fallback" {
		if len(cfg.Interface) > maxInterfaceName || strings.ContainsAny(cfg.Interface, " /") ||
			cfg.Interface == "." || cfg.Interface == ".." {
			return fmt.Errorf("network.interface must be a network interface name of at most %d characters, got %q",
				maxInterfaceName, cfg.Interface)
		}
	}
	if cfg.PublicHost != "" {
		if err := configcheck.Host("network.public_host", cfg.PublicHost); err != nil {
			return err
		}
	}
	if _, err := socket.ParsePortRanges(cfg.PublicPorts); err != nil {
		return fmt.Errorf("network.public_ports: %w", err)
	}
	_, err := cfg.Policy.Compile()
	return err
}

func (cfg NetworkConfig) ValidatePacketCounter() error {
	switch cfg.PacketCounter {
	case "", "auto", "fallback":
		return nil
	default:
		return fmt.Errorf("invalid network.packet_counter %q: expected auto or fallback", cfg.PacketCounter)
	}
}
