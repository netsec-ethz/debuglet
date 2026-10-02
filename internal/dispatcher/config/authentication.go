// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type AuthenticationConfig struct {
	PublicURL             string `toml:"public_url"`
	DeviceVerificationURL string `toml:"device_verification_url"`
}

type CILogonConfig struct {
	Enabled     bool   `toml:"enabled"`
	Issuer      string `toml:"issuer"`
	CallbackURL string `toml:"callback_url"`
	SuccessURL  string `toml:"success_url"`
}

func authenticationURL(field, value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return nil, fmt.Errorf("%s must be an absolute HTTPS URL without credentials, query or fragment", field)
	}
	return parsed, nil
}

func (cfg *DispatcherConfig) validateAuthentication() error {
	for _, provider := range []struct {
		field             string
		enabled           bool
		callback, success string
	}{{"github_oauth", cfg.GitHubOAuth.Enabled, cfg.GitHubOAuth.CallbackURL, cfg.GitHubOAuth.SuccessURL}, {"cilogon_oidc", cfg.CILogonOIDC.Enabled, cfg.CILogonOIDC.CallbackURL, cfg.CILogonOIDC.SuccessURL}} {
		if !provider.enabled {
			continue
		}
		if cfg.TLS.Disable && !cfg.Server.BehindTLSTerminator {
			return fmt.Errorf("%s.enabled requires dispatcher TLS or server.behind_tls_terminator so browser credentials use Secure cookies", provider.field)
		}
		callback, err := authenticationURL(provider.field+".callback_url", provider.callback)
		if err != nil {
			return err
		}
		success, err := authenticationURL(provider.field+".success_url", provider.success)
		if err != nil {
			return err
		}
		if callback.Host != success.Host {
			return fmt.Errorf("%s callback and success URLs must have the same origin", provider.field)
		}
	}
	if cfg.CILogonOIDC.Enabled && cfg.CILogonOIDC.Issuer != "https://cilogon.org" && cfg.CILogonOIDC.Issuer != "https://test.cilogon.org" {
		return errors.New("cilogon_oidc.issuer must be https://cilogon.org or https://test.cilogon.org")
	}
	if cfg.Authentication.PublicURL == "" && cfg.Authentication.DeviceVerificationURL == "" {
		return nil
	}
	public, err := authenticationURL("authentication.public_url", cfg.Authentication.PublicURL)
	if err != nil {
		return err
	}
	verification, err := authenticationURL("authentication.device_verification_url", cfg.Authentication.DeviceVerificationURL)
	if err != nil {
		return err
	}
	if strings.HasSuffix(cfg.Authentication.PublicURL, "/") {
		return errors.New("authentication.public_url must not end with a slash")
	}
	if public.Host != verification.Host {
		return errors.New("authentication.device_verification_url must have the same origin as authentication.public_url")
	}
	if cfg.TLS.Disable && !cfg.Server.BehindTLSTerminator {
		return errors.New("authentication requires Secure cookies through dispatcher TLS or server.behind_tls_terminator")
	}
	for _, provider := range []struct {
		enabled  bool
		callback string
	}{{cfg.GitHubOAuth.Enabled, cfg.GitHubOAuth.CallbackURL}, {cfg.CILogonOIDC.Enabled, cfg.CILogonOIDC.CallbackURL}} {
		if !provider.enabled {
			continue
		}
		callback, _ := url.Parse(provider.callback)
		if callback.Host != public.Host {
			return errors.New("authentication.public_url and enabled provider callbacks must have the same origin")
		}
	}
	return nil
}
