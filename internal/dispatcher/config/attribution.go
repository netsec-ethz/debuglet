// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"fmt"
	"net/netip"
	"time"
)

// AttributionConfig bounds the attribution history the dispatcher keeps for
// probe verification: the TESLA chains executors announced, their disclosed
// keys and the source addresses and intervals of runs.
type AttributionConfig struct {
	// RetentionDays is how long the history is kept. Older records are pruned
	// periodically, and GET /attribution/candidates reports the resulting
	// retained_from. Omitted or 0 means DefaultAttributionRetentionDays, so
	// a configuration built in code without it keeps the documented default.
	RetentionDays int `toml:"retention_days"`
	// TrustedProxies lists the addresses or CIDR prefixes of reverse proxies
	// in front of the HTTP API that set X-Forwarded-For. The attribution
	// routes are rate-limited per client address; for a request whose TCP
	// peer is one of these, the client address is the right-most
	// X-Forwarded-For entry that is not itself a trusted proxy. Empty, the
	// default, trusts no forwarding header, so every client behind a proxy
	// shares the proxy's allowance.
	TrustedProxies []string `toml:"trusted_proxies"`
	// ReceiptKeyPath is the PEM file holding the Ed25519 private key that
	// signs the receipts of POST /attribution/verify. It is created, owner
	// readable only, when absent. Empty means DefaultReceiptKeyFile in the
	// directory of the database.
	ReceiptKeyPath string `toml:"receipt_key_path"`
}

// DefaultReceiptKeyFile is the receipt key file used when
// attribution.receipt_key_path is empty, beside the database.
const DefaultReceiptKeyFile = "attribution-receipt-key.pem"

// MaxAttributionTrustedProxies bounds attribution.trusted_proxies.
const MaxAttributionTrustedProxies = 64

// Documented default and bound of attribution.retention_days.
const (
	DefaultAttributionRetentionDays = 90
	MaxAttributionRetentionDays     = 3650
)

func DefaultAttributionConfig() AttributionConfig {
	return AttributionConfig{RetentionDays: DefaultAttributionRetentionDays}
}

// Retention is the configured retention as a duration.
func (cfg AttributionConfig) Retention() time.Duration {
	return time.Duration(cfg.retentionDays()) * 24 * time.Hour
}

// retentionDays resolves 0 to the default.
func (cfg AttributionConfig) retentionDays() int {
	if cfg.RetentionDays == 0 {
		return DefaultAttributionRetentionDays
	}
	return cfg.RetentionDays
}

func (cfg AttributionConfig) Validate() error {
	if cfg.RetentionDays < 0 || cfg.RetentionDays > MaxAttributionRetentionDays {
		return fmt.Errorf("attribution.retention_days must be 0 (the default of %d days) or between 1 and %d, got %d",
			DefaultAttributionRetentionDays, MaxAttributionRetentionDays, cfg.RetentionDays)
	}
	_, err := cfg.TrustedProxyPrefixes()
	return err
}

// TrustedProxyPrefixes parses TrustedProxies: each entry is an IP address,
// which stands for itself, or a CIDR prefix. An IPv4-mapped IPv6 entry is
// refused, since peers are compared in their unmapped form.
func (cfg AttributionConfig) TrustedProxyPrefixes() ([]netip.Prefix, error) {
	if len(cfg.TrustedProxies) > MaxAttributionTrustedProxies {
		return nil, fmt.Errorf("attribution.trusted_proxies lists %d entries, at most %d are allowed", len(cfg.TrustedProxies), MaxAttributionTrustedProxies)
	}
	prefixes := make([]netip.Prefix, 0, len(cfg.TrustedProxies))
	for _, entry := range cfg.TrustedProxies {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			addr, addrErr := netip.ParseAddr(entry)
			if addrErr != nil || addr.Zone() != "" {
				return nil, fmt.Errorf("attribution.trusted_proxies: %q is neither an IP address nor a CIDR prefix", entry)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("attribution.trusted_proxies: %q is an IPv4-mapped IPv6 address; list the IPv4 form", entry)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}
