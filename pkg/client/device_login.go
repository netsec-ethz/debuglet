// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// DeviceLogin is a short-lived browser approval request. DeviceCode is a
// secret for polling and cancellation; show only UserCode and VerificationURI.
type DeviceLogin struct {
	DeviceCode      string   `json:"device_code"`
	UserCode        string   `json:"user_code"`
	VerificationURI string   `json:"verification_uri"`
	Audience        string   `json:"audience"`
	Scopes          []string `json:"scopes"`
	ExpiresAt       int64    `json:"expires_at"`
	Interval        int64    `json:"interval"`
}

// APICredential is returned once when a browser has approved a device login.
// Token is usable only at Audience; it belongs in the client's secure store.
type APICredential struct {
	Token        string   `json:"token"`
	CredentialID string   `json:"credential_id"`
	Audience     string   `json:"audience"`
	Scopes       []string `json:"scopes"`
	ExpiresAt    int64    `json:"expires_at"`
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Role         string   `json:"role"`
}

type DeviceLoginPoll struct {
	State      string         `json:"state"`
	Interval   int64          `json:"interval,omitempty"`
	Credential *APICredential `json:"credential,omitempty"`
}

// StartDeviceLogin requests a credential with explicit scopes. It never sends
// a provider token or chooses an audience from a remote response.
func (c *Client) StartDeviceLogin(ctx context.Context, label string, scopes []string) (DeviceLogin, error) {
	const route = "auth/device/start"
	body, err := json.Marshal(struct {
		Audience string   `json:"audience"`
		Scopes   []string `json:"scopes"`
		Label    string   `json:"label"`
	}{c.origin + c.basePath, scopes, label})
	if err != nil {
		return DeviceLogin{}, err
	}
	data, err := c.do(ctx, http.MethodPost, route, nil, body, http.StatusCreated)
	if err != nil {
		return DeviceLogin{}, err
	}
	var login DeviceLogin
	if err = c.decode(http.MethodPost, route, data, &login); err != nil {
		return DeviceLogin{}, err
	}
	verify, parseErr := url.Parse(login.VerificationURI)
	gotScopes, wantScopes := slices.Clone(login.Scopes), slices.Clone(scopes)
	slices.Sort(gotScopes)
	slices.Sort(wantScopes)
	if parseErr != nil || verify.User != nil || verify.RawQuery != "" || verify.Fragment != "" || verify.Scheme+"://"+verify.Host != c.origin || login.Audience != c.origin+c.basePath || !strings.HasPrefix(login.DeviceCode, "dbd_") || len(login.DeviceCode) > 128 || login.UserCode == "" || len(login.UserCode) > 20 || login.Interval < 5 || login.Interval > 60 || login.ExpiresAt <= time.Now().Unix() || login.ExpiresAt > time.Now().Add(15*time.Minute).Unix() || !slices.Equal(slices.Compact(gotScopes), slices.Compact(wantScopes)) {
		return DeviceLogin{}, c.protocolErr(http.MethodPost, route, "invalid browser login request")
	}
	for _, ch := range login.UserCode {
		if !(ch >= 'A' && ch <= 'Z' || ch >= '2' && ch <= '7' || ch == '-') {
			return DeviceLogin{}, c.protocolErr(http.MethodPost, route, "invalid user code")
		}
	}
	return login, nil
}

// PollDeviceLogin must be called no faster than the last returned Interval.
// slow_down increases that interval; denied/expired/consumed end the login.
func (c *Client) PollDeviceLogin(ctx context.Context, login DeviceLogin) (DeviceLoginPoll, error) {
	const route = "auth/device/poll"
	if login.Audience != c.origin+c.basePath {
		return DeviceLoginPoll{}, c.protocolErr(http.MethodPost, route, "login belongs to another dispatcher")
	}
	body, _ := json.Marshal(struct {
		DeviceCode string `json:"device_code"`
		Audience   string `json:"audience"`
	}{login.DeviceCode, login.Audience})
	data, err := c.do(ctx, http.MethodPost, route, nil, body, http.StatusOK, login.DeviceCode)
	if err != nil {
		return DeviceLoginPoll{}, err
	}
	var result DeviceLoginPoll
	if err = c.decode(http.MethodPost, route, data, &result); err != nil {
		return DeviceLoginPoll{}, err
	}
	switch result.State {
	case "authorization_pending", "slow_down":
		if result.Interval < 5 || result.Interval > 60 {
			return DeviceLoginPoll{}, c.protocolErr(http.MethodPost, route, "invalid polling interval")
		}
	case "access_denied", "expired_token", "consumed":
	case "authorized":
		credential := result.Credential
		if credential == nil || credential.Audience != login.Audience || !strings.HasPrefix(credential.Token, "dbt_") || len(credential.Token) > 128 || credential.ExpiresAt <= time.Now().Unix() {
			return DeviceLoginPoll{}, c.protocolErr(http.MethodPost, route, "invalid issued credential")
		}
		got, want := slices.Clone(credential.Scopes), slices.Clone(login.Scopes)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			return DeviceLoginPoll{}, c.protocolErr(http.MethodPost, route, "issued credential scopes differ from approval")
		}
	default:
		return DeviceLoginPoll{}, c.protocolErr(http.MethodPost, route, "invalid login state")
	}
	return result, nil
}

func (c *Client) CancelDeviceLogin(ctx context.Context, login DeviceLogin) error {
	const route = "auth/device/cancel"
	if login.Audience != c.origin+c.basePath {
		return c.protocolErr(http.MethodPost, route, "login belongs to another dispatcher")
	}
	body, _ := json.Marshal(struct {
		DeviceCode string `json:"device_code"`
		Audience   string `json:"audience"`
	}{login.DeviceCode, login.Audience})
	_, err := c.do(ctx, http.MethodPost, route, nil, body, http.StatusNoContent, login.DeviceCode)
	return err
}

// CredentialStatus contains no secret and reflects immediate server-side
// revocation, rather than trusting the local file's expiry alone.
type CredentialStatus struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Audience  string   `json:"audience"`
	Scopes    []string `json:"scopes"`
	CreatedAt int64    `json:"created_at"`
	ExpiresAt int64    `json:"expires_at"`
}

func (c *Client) CredentialStatus(ctx context.Context) (CredentialStatus, error) {
	const route = "auth/credential"
	data, err := c.do(ctx, http.MethodGet, route, nil, nil, http.StatusOK)
	if err != nil {
		return CredentialStatus{}, err
	}
	var result CredentialStatus
	if err = c.decode(http.MethodGet, route, data, &result); err != nil {
		return CredentialStatus{}, err
	}
	encoded, _ := json.Marshal(result)
	if c.credential != "" && strings.Contains(string(encoded), c.credential) {
		return CredentialStatus{}, c.protocolErr(http.MethodGet, route, "credential material in status response")
	}
	return result, nil
}
