// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestAttributionTrustedProxies(t *testing.T) {
	cfg := DefaultAttributionConfig()
	if prefixes, err := cfg.TrustedProxyPrefixes(); err != nil || len(prefixes) != 0 {
		t.Fatalf("default trusts %v, %v; want no proxy", prefixes, err)
	}
	cfg.TrustedProxies = []string{"10.0.0.1", "192.0.2.0/24", "2001:db8::/48", "192.0.2.77/24"}
	prefixes, err := cfg.TrustedProxyPrefixes()
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/48"), netip.MustParsePrefix("192.0.2.0/24")}
	if err != nil || !slices.Equal(prefixes, want) || cfg.Validate() != nil {
		t.Fatalf("prefixes=%v, %v; want %v", prefixes, err, want)
	}
	for _, bad := range []string{"proxy.example", "10.0.0.1/33", "fe80::1%eth0", "::ffff:10.0.0.1", ""} {
		cfg.TrustedProxies = []string{bad}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "attribution.trusted_proxies") {
			t.Errorf("%q: %v; want a trusted_proxies error", bad, err)
		}
	}
	cfg.TrustedProxies = slices.Repeat([]string{"10.0.0.1"}, MaxAttributionTrustedProxies+1)
	if err := cfg.Validate(); err == nil {
		t.Error("an unbounded proxy list was accepted")
	}
}

func TestAttributionTrustedProxiesDecode(t *testing.T) {
	cfg, _, err := DecodeConfig([]byte(baseSections + "\n[attribution]\ntrusted_proxies = [\"10.0.0.0/8\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil || !slices.Equal(cfg.Attribution.TrustedProxies, []string{"10.0.0.0/8"}) || cfg.Attribution.RetentionDays != DefaultAttributionRetentionDays {
		t.Fatalf("attribution=%+v, %v", cfg.Attribution, err)
	}
}
