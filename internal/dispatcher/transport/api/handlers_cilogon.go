// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

type CILogonConfig struct {
	Enabled                                                 bool
	Issuer, ClientID, ClientSecret, CallbackURL, SuccessURL string
}

func CILogon(cfg CILogonConfig) Option { return func(h *Handler) { h.cilogonOIDC = cfg } }

type cilogonDiscovery struct {
	sync.Mutex
	provider *oidc.Provider
	expires  time.Time
}

var oidcHTTPClient = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (h *Handler) cilogonReady() bool {
	return h.cilogonOIDC.Enabled && h.cilogonOIDC.ClientID != "" && h.cilogonOIDC.ClientSecret != "" && h.cilogonOIDC.Issuer != ""
}

// A provider caches and refreshes its signing keys. Rediscovery also permits
// endpoint changes without a restart; failures never reuse expired metadata.
func (h *Handler) cilogonProvider(ctx context.Context) (*oidc.Provider, error) {
	h.cilogonDiscovery.Lock()
	defer h.cilogonDiscovery.Unlock()
	if h.cilogonDiscovery.provider != nil && time.Now().Before(h.cilogonDiscovery.expires) {
		return h.cilogonDiscovery.provider, nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, oidcHTTPClient), h.cilogonOIDC.Issuer)
	if err != nil {
		return nil, errors.New("CILogon discovery unavailable")
	}
	h.cilogonDiscovery.provider, h.cilogonDiscovery.expires = provider, time.Now().Add(time.Hour)
	return provider, nil
}

func (h *Handler) cilogonClient(provider *oidc.Provider) oauth2.Config {
	return oauth2.Config{ClientID: h.cilogonOIDC.ClientID, ClientSecret: h.cilogonOIDC.ClientSecret,
		Endpoint: provider.Endpoint(), RedirectURL: h.cilogonOIDC.CallbackURL, Scopes: []string{oidc.ScopeOpenID, "profile"}}
}

func (h *Handler) GetCILogonLogin(c echo.Context) error {
	session := ""
	if caller := requestCaller(c); caller.Authenticated && caller.Cookie && !caller.API {
		session = caller.Session
	}
	return h.startProviderLogin(c, "cilogon", "login", session)
}
func (h *Handler) GetCILogonCallback(c echo.Context) error { return h.providerCallback(c, "cilogon") }

func (h *Handler) cilogonProfile(ctx context.Context, code, verifier, nonce string) (externalProfile, error) {
	provider, err := h.cilogonProvider(ctx)
	if err != nil {
		return externalProfile{}, err
	}
	cfg := h.cilogonClient(provider)
	token, err := cfg.Exchange(oidc.ClientContext(ctx, oidcHTTPClient), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return externalProfile{}, errors.New("CILogon code exchange failed")
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return externalProfile{}, errors.New("CILogon did not return an ID token")
	}
	verified, err := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(oidc.ClientContext(ctx, oidcHTTPClient), rawIDToken)
	if err != nil {
		return externalProfile{}, errors.New("CILogon ID token validation failed")
	}
	if subtle.ConstantTimeCompare([]byte(verified.Nonce), []byte(nonce)) != 1 || verified.Subject == "" || len(verified.Subject) > 512 {
		return externalProfile{}, errors.New("CILogon nonce or subject is invalid")
	}
	if verified.AccessTokenHash != "" && verified.VerifyAccessToken(token.AccessToken) != nil {
		return externalProfile{}, errors.New("CILogon access token hash is invalid")
	}
	var claims struct {
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		AuthorizedParty   string `json:"azp"`
	}
	if verified.Claims(&claims) != nil || (claims.AuthorizedParty != "" && claims.AuthorizedParty != cfg.ClientID) || (len(verified.Audience) > 1 && claims.AuthorizedParty != cfg.ClientID) {
		return externalProfile{}, errors.New("CILogon authorized party is invalid")
	}
	name := strings.TrimSpace(claims.Name)
	if name == "" {
		name = strings.TrimSpace(claims.PreferredUsername)
	}
	if name == "" {
		name = "CILogon account"
	}
	if len(name) > 200 {
		name = "CILogon account"
	}
	return externalProfile{Provider: "cilogon", Issuer: verified.Issuer, Subject: verified.Subject, Login: name, Name: name}, nil
}
