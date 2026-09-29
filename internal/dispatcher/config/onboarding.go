// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/configcheck"
)

// ExecutorOnboardingConfig enables account owners to enroll their machines.
// The signing key stays on the dispatcher; executors generate their own keys.
type ExecutorOnboardingConfig struct {
	Enabled       bool   `toml:"enabled"`
	CACert        string `toml:"ca_cert"`
	CAKey         string `toml:"ca_key"`
	DispatcherURL string `toml:"dispatcher_url"`
	GRPCAddress   string `toml:"grpc_address"`
	YamuxAddress  string `toml:"yamux_address"`
}

func (cfg ExecutorOnboardingConfig) Validate(tls TLSConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if tls.Disable || !tls.RequireClientCert {
		return errors.New("executor_onboarding.enabled requires TLS with tls.require_client_cert = true")
	}
	for _, field := range []struct{ name, value string }{
		{"executor_onboarding.ca_cert", cfg.CACert},
		{"executor_onboarding.ca_key", cfg.CAKey},
	} {
		if err := configcheck.Path(field.name, field.value); err != nil {
			return err
		}
	}
	const field = "executor_onboarding.dispatcher_url"
	parsed, err := url.Parse(cfg.DispatcherURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(cfg.DispatcherURL, "#") {
		return fmt.Errorf("%s must be an absolute HTTPS URL without credentials, query or fragment", field)
	}
	if err := configcheck.Host(field, parsed.Hostname()); err != nil {
		return err
	}
	if port := parsed.Port(); port != "" || strings.HasSuffix(parsed.Host, ":") {
		if err := configcheck.Endpoint(field, net.JoinHostPort(parsed.Hostname(), port)); err != nil {
			return err
		}
	}
	if err := configcheck.Endpoint("executor_onboarding.grpc_address", cfg.GRPCAddress); err != nil {
		return err
	}
	return configcheck.Endpoint("executor_onboarding.yamux_address", cfg.YamuxAddress)
}
