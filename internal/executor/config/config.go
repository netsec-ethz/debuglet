// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package config

import (
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/executor/isolation"
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
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// ExecutorConfig represents the structure of executor.toml
type ExecutorConfig struct {
	Identity     IdentityConfig
	Dispatcher   DispatcherConfig
	TLS          TLSConfig
	Resources    ResourcesConfig
	Tesla        TeslaConfig
	Network      NetworkConfig
	Logging      LoggingConfig
	Credentials  CredentialConfig
	Database     DatabaseConfig
	Pricing      PricingConfig
	Output       OutputConfig
	Isolation    isolation.Config
	Clock        ClockConfig
	Metadata     MetadataConfig
	Connectivity ConnectivityConfig
}

// MetadataConfig controls publication of automatically derived location and
// of the addresses the dispatcher observes.
type MetadataConfig struct {
	LocationOptOut bool `toml:"location_opt_out"`
	// AddressOptOut makes the executor private (is_public false): the public
	// listing then withholds its observed addresses. Prefix, ASN and
	// location stay public, as for a private RIPE Atlas probe.
	AddressOptOut bool `toml:"address_opt_out"`
	// HostTags describe the host from the fixed vocabulary wire.HostTags,
	// such as home or datacentre and dsl or fibre. They are public.
	HostTags []string `toml:"host_tags"`
}

// ClockConfig bounds the kernel's estimated clock error the executor accepts
// before it reports its clock readiness as degraded. Readiness when the TESLA
// key chain starts decides whether that chain's origin is trusted: a chain
// started on a clock that is not ready tags nothing, and a tagging node then
// admits no runs until it restarts. Later readiness changes are only reported.
type ClockConfig struct {
	MaxErrorMS int64 `toml:"max_error_ms"`
}

// MaxErrorBound is the configured bound as a duration; zero selects
// DefaultClockMaxErrorMS.
func (cfg ClockConfig) MaxErrorBound() time.Duration {
	if cfg.MaxErrorMS == 0 {
		return DefaultClockMaxErrorMS * time.Millisecond
	}
	return time.Duration(cfg.MaxErrorMS) * time.Millisecond
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
	Seed string `toml:"seed"`
	// EpochSeconds is the epoch length I in seconds: each chain key signs
	// for one epoch. Zero keeps tesla.DefaultEpochLength.
	EpochSeconds int64 `toml:"epoch_seconds"`
	// Delay is the deprecated name of EpochSeconds, read when EpochSeconds is
	// unset. It never was a disclosure delay; see DisclosureDelayEpochs.
	Delay int64 `toml:"delay"`
	// DisclosureDelayEpochs is the disclosure delay d: the key of epoch i is
	// disclosed once epoch i+d starts. Zero derives the smallest d whose
	// d·EpochSeconds covers tesla.DefaultDisclosureWindow; an explicit value
	// must be at least tesla.MinDisclosureDelay.
	DisclosureDelayEpochs int64 `toml:"disclosure_delay_epochs"`
	// ChainLength is the number of epochs the hash chain covers. Zero
	// derives it from EpochSeconds so the chain lasts tesla.DefaultChainHorizon.
	// The schedule stops advancing once the chain runs out, and packets
	// tagged after that point can never be verified, so this must exceed
	// the executor's expected uptime between restarts.
	ChainLength int64 `toml:"chain_length"`
}

// EpochLength returns the configured epoch length, zero for the default. It
// reads the deprecated delay key only when epoch_seconds is unset.
func (c TeslaConfig) EpochLength() time.Duration {
	if c.EpochSeconds != 0 {
		return time.Duration(c.EpochSeconds) * time.Second
	}
	return time.Duration(c.Delay) * time.Second
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
	// DefaultClockMaxErrorMS matches hostprobe.DefaultClockErrorBound.
	DefaultClockMaxErrorMS = 100
	// MaxClockMaxErrorMS is one minute, well beyond any disciplined clock.
	MaxClockMaxErrorMS = 60_000
)

// MaxChainLength bounds an explicitly configured TESLA chain. It matches one
// epoch per second over tesla.DefaultChainHorizon, the longest chain the
// executor derives on its own, and keeps the precomputed chain in memory
// bounded. Zero still derives the length from the epoch duration.
const MaxChainLength = int64(tesla.DefaultChainHorizon / time.Second)

// MaxEpochSeconds bounds the epoch length: one day, so the default chain
// still covers a week of epochs.
const MaxEpochSeconds = int64(24 * time.Hour / time.Second)

// MaxDisclosureWindow bounds d·I, the time a key stays secret after its
// epoch. Beyond the default chain horizon every key of a default chain would
// be disclosed only after it expired.
const MaxDisclosureWindow = tesla.DefaultChainHorizon

// MinDisclosureMargin bounds (d−1)·I from below, the time the key of a
// packet's previous epoch stays secret after the packet's epoch ends. A
// verifier refuses a key the dispatcher may have accepted, which it does up to
// 5 seconds early (clockSkew in internal/dispatcher/tag), before the capture
// time plus its own clock tolerance (1 second by default in
// tools/verify_pcap.py). A smaller margin makes tags of whole epochs
// unverifiable: at one-second epochs, d = 2 verifies nothing.
const MinDisclosureMargin = 10 * time.Second

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

	cfg, _, err := DecodeConfig(data)
	if err != nil {
		return nil, err
	}

	if (cfg.Network.PublicHost == "") != (cfg.Network.PublicPorts == "") {
		log.Println("Warning: both public_host and public_ports must be set for TCP/UDP listeners; listening is disabled")
	}
	if cfg.Tesla.Delay != 0 {
		log.Println("Warning: tesla.delay is deprecated; it is the epoch length and is now named tesla.epoch_seconds (the disclosure delay is tesla.disclosure_delay_epochs)")
	}
	if cfg.Network.PacketCounter != "fallback" && cfg.Network.Interface == "" {
		iface, err := defaultInterface()
		if err == nil {
			cfg.Network.Interface = iface.Name
		} else {
			log.Printf("Warning: could not determine default network interface: %v", err)
		}
	}

	return cfg, nil
}

// DecodeConfig applies startup defaults and validation without connecting to
// a network or discovering the default interface. LoadConfig resolves an
// omitted interface afterwards, when the daemon starts.
func DecodeConfig(data []byte) (*ExecutorConfig, configcheck.Document, error) {
	var cfg ExecutorConfig
	document, err := configcheck.Decode(data, &cfg)
	if err != nil {
		return nil, document, err
	}

	// defaults
	if !document.Set("logging", "log_level") {
		cfg.Logging.LogLevel = DefaultLogLevel
	}
	if !document.Set("resources", "max_debuglets") {
		cfg.Resources.MaxDebuglets = DefaultMaxDebuglets
	}
	if !document.Set("clock", "max_error_ms") {
		cfg.Clock.MaxErrorMS = DefaultClockMaxErrorMS
	}
	if cfg.Dispatcher.YamuxAddr == "" {
		cfg.Dispatcher.YamuxAddr = cfg.Dispatcher.Addr
	}
	if !document.Set("connectivity", "observe_addresses") {
		cfg.Connectivity.ObserveAddresses = true
	}
	tags, err := wire.CanonicalHostTags(cfg.Metadata.HostTags)
	if err != nil {
		return nil, document, fmt.Errorf("metadata.host_tags: %w", err)
	}
	cfg.Metadata.HostTags = tags

	if err := cfg.Validate(); err != nil {
		return nil, document, err
	}

	return &cfg, document, nil
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
	if err := cfg.Connectivity.Validate(cfg.TLS.Disable); err != nil {
		return err
	}
	if err := cfg.validateCredentials(); err != nil {
		return err
	}
	if err := cfg.ValidateIsolation(); err != nil {
		return fmt.Errorf("isolation: %w", err)
	}
	if err := cfg.Output.Validate(); err != nil {
		return err
	}
	// Zero selects the default, as for the output limits.
	if cfg.Clock.MaxErrorMS < 0 || cfg.Clock.MaxErrorMS > MaxClockMaxErrorMS {
		return fmt.Errorf("clock.max_error_ms must be between 0 (default) and %d, got %d", MaxClockMaxErrorMS, cfg.Clock.MaxErrorMS)
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
	for _, field := range []struct {
		name  string
		value int64
	}{{"tesla.epoch_seconds", cfg.Tesla.EpochSeconds}, {"tesla.delay", cfg.Tesla.Delay}} {
		if field.value < 0 || field.value > MaxEpochSeconds {
			return fmt.Errorf("%s must be between 0 (the default of %d seconds) and %d seconds, got %d",
				field.name, int64(tesla.DefaultEpochLength/time.Second), MaxEpochSeconds, field.value)
		}
	}
	if cfg.Tesla.EpochSeconds != 0 && cfg.Tesla.Delay != 0 {
		return errors.New("tesla.delay is the deprecated name of tesla.epoch_seconds; set only tesla.epoch_seconds")
	}
	epoch := cfg.Tesla.EpochLength()
	if epoch == 0 {
		epoch = tesla.DefaultEpochLength
	}
	maxDelay := int64(MaxDisclosureWindow / epoch)
	if d := cfg.Tesla.DisclosureDelayEpochs; d != 0 && (d < tesla.MinDisclosureDelay || d > maxDelay) {
		return fmt.Errorf("tesla.disclosure_delay_epochs must be 0 (derive the smallest delay covering %d seconds) or between %d and %d epochs (%d seconds in all at %d-second epochs), got %d",
			int64(tesla.DefaultDisclosureWindow/time.Second), tesla.MinDisclosureDelay, maxDelay, int64(MaxDisclosureWindow/time.Second), int64(epoch/time.Second), d)
	}
	if d := cfg.Tesla.DisclosureDelayEpochs; d != 0 && time.Duration(d-1)*epoch < MinDisclosureMargin {
		minDelay := 1 + int64((MinDisclosureMargin+epoch-1)/epoch)
		return fmt.Errorf("tesla.disclosure_delay_epochs must be at least %d at %d-second epochs, so the key of a packet's previous epoch stays secret for %d seconds after the packet's epoch (clock skew allowance plus verifier tolerance), got %d",
			minDelay, int64(epoch/time.Second), int64(MinDisclosureMargin/time.Second), d)
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

// ValidateIsolation keeps unsupported parent transports outside the shared
// resource profile, including when Node is constructed without loading a file.
func (cfg *ExecutorConfig) ValidateIsolation() error {
	if err := cfg.Isolation.Validate(); err != nil {
		return err
	}
	if cfg.Isolation.Shared() && cfg.Network.Policy.SCION != nil && *cfg.Network.Policy.SCION {
		return errors.New("shared isolation requires network.policy.scion = false")
	}
	return nil
}
