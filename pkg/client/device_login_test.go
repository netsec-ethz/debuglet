// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDeviceLoginBindsAudienceAndScopes(t *testing.T) {
	f := newFakeServer(t, "/api")
	c := f.client(t, Options{})
	start := DeviceLogin{DeviceCode: "dbd_selector.verifier", UserCode: "ABCDE-F2345", VerificationURI: f.srv.URL + "/console/device", Audience: f.endpoint(), Scopes: []string{"account:read"}, ExpiresAt: time.Now().Add(10 * time.Minute).Unix(), Interval: 5}
	f.handle("POST /auth/device/start", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Audience string   `json:"audience"`
			Scopes   []string `json:"scopes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.Audience != f.endpoint() || len(req.Scopes) != 1 || req.Scopes[0] != "account:read" {
			t.Error("request changed scope or audience")
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(start)
	})
	login, err := c.StartDeviceLogin(testContext(t), "shell", []string{"account:read"})
	if err != nil {
		t.Fatal(err)
	}
	if login.DeviceCode != start.DeviceCode {
		t.Fatal("missing polling secret")
	}
	start.VerificationURI = "https://unrelated.example/device"
	if _, err := c.StartDeviceLogin(testContext(t), "shell", []string{"account:read"}); err == nil {
		t.Fatal("cross-origin approval page accepted")
	}
	start.VerificationURI = f.srv.URL + "/console/device"
	start.Scopes = []string{"executors:write"}
	if _, err := c.StartDeviceLogin(testContext(t), "shell", []string{"account:read"}); err == nil {
		t.Fatal("unrequested scope accepted")
	}
}

func TestDeviceLoginPollingStatesAndSecretRedaction(t *testing.T) {
	f := newFakeServer(t, "")
	c := f.client(t, Options{})
	login := DeviceLogin{DeviceCode: "dbd_selector.POLLING-SECRET", Audience: f.endpoint(), Scopes: []string{"account:read"}}
	for _, state := range []string{"authorization_pending", "slow_down", "access_denied", "expired_token", "consumed", "authorized"} {
		t.Run(state, func(t *testing.T) {
			result := DeviceLoginPoll{State: state, Interval: 10}
			if state == "authorized" {
				result.Credential = &APICredential{Token: "dbt_selector.CREDENTIAL-SECRET", Audience: f.endpoint(), Scopes: login.Scopes, ExpiresAt: time.Now().Add(time.Hour).Unix()}
			}
			f.handle("POST /auth/device/poll", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(result) })
			got, err := c.PollDeviceLogin(testContext(t), login)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != state {
				t.Fatalf("state %s", got.State)
			}
		})
	}
	f.handle("POST /auth/device/poll", jsonHandler(400, `{"code":"invalid_request","message":"echo `+login.DeviceCode+`"}`))
	if _, err := c.PollDeviceLogin(testContext(t), login); err == nil || strings.Contains(err.Error(), login.DeviceCode) {
		t.Fatalf("poll secret diagnostic: %v", err)
	}
	f.handle("POST /auth/device/cancel", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	if err := c.CancelDeviceLogin(testContext(t), login); err != nil {
		t.Fatal(err)
	}
	other := login
	other.Audience = "https://other.example"
	if _, err := c.PollDeviceLogin(testContext(t), other); err == nil {
		t.Fatal("wrong audience poll sent")
	}
	if err := c.CancelDeviceLogin(testContext(t), other); err == nil {
		t.Fatal("wrong audience cancellation sent")
	}
}
