// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func remoteLoginEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err != nil || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback()
}

func browserLoginCommand(ctx context.Context, c *client.Client, profile connections.Profile, options globalOptions, scopes []string, noBrowser bool, stdout, stderr io.Writer) int {
	for i := range scopes {
		scopes[i] = strings.TrimSpace(scopes[i])
	}
	host, _ := os.Hostname()
	label := "dbl on " + host
	if len(label) > 80 {
		label = label[:80]
	}
	login, err := c.StartDeviceLogin(ctx, label, scopes)
	if err != nil {
		return reportFailure(ctx, "dbl login: start browser approval", stderr, err)
	}
	complete := false
	defer func() {
		if !complete {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = c.CancelDeviceLogin(cleanup, login)
		}
	}()
	notice := stdout
	if options.Output == outputJSON {
		notice = stderr
	}
	if _, err = fmt.Fprintf(notice, "Open %s\nEnter code: %s\nDispatcher: %s\nRequested access: %s\nApprove only if the device and code match this request.\n", login.VerificationURI, login.UserCode, login.Audience, strings.Join(login.Scopes, ", ")); err != nil {
		return reportFailure(ctx, "dbl login", stderr, err)
	}
	if !noBrowser {
		if err = openLoginBrowser(login.VerificationURI); err != nil {
			fmt.Fprintln(stderr, "A browser could not be opened. Use the URL and code above on any device.")
		}
	}
	waiting, cancel := context.WithDeadline(ctx, time.Unix(login.ExpiresAt, 0))
	defer cancel()
	interval := time.Duration(login.Interval) * time.Second
	for {
		timer := time.NewTimer(interval)
		select {
		case <-waiting.Done():
			timer.Stop()
			return reportFailure(ctx, "dbl login", stderr, errors.New("browser login cancelled or expired; run dbl login again"))
		case <-timer.C:
		}
		poll, err := c.PollDeviceLogin(waiting, login)
		if err != nil {
			var httpErr *client.HTTPError
			if errors.As(err, &httpErr) && (httpErr.StatusCode == 429 || httpErr.StatusCode == 503) {
				interval = max(interval+5*time.Second, httpErr.RetryAfter)
				continue
			}
			return reportFailure(ctx, "dbl login: check browser approval", stderr, err)
		}
		switch poll.State {
		case "authorization_pending", "slow_down":
			interval = time.Duration(poll.Interval) * time.Second
		case "authorized":
			credential := poll.Credential
			authenticated, err := c.WithCredential(credential.Token)
			if err != nil {
				return reportFailure(ctx, "dbl login", stderr, err)
			}
			if waiting.Err() != nil {
				cleanup, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cleanupCancel()
				_ = authenticated.Logout(cleanup)
				return reportFailure(ctx, "dbl login", stderr, errors.New("browser login cancelled; run dbl login again"))
			}
			if err = connections.SaveCredential(options.ConfigPath, profile.Name, connections.Credential{Endpoint: profile.Endpoint, Token: credential.Token, ExpiresAt: credential.ExpiresAt, AccountID: credential.ID}); err != nil {
				cleanup, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cleanupCancel()
				_ = authenticated.Logout(cleanup)
				return reportFailure(ctx, "dbl login: store credential", stderr, err)
			}
			complete = true
			return emitReported(ctx, "dbl login", options.Output, stdout, stderr, map[string]any{"dispatcher": profile.Name, "endpoint": profile.Endpoint, "account_id": credential.ID, "expires_at": credential.ExpiresAt, "scopes": credential.Scopes, "credential_store": "owner-only file"}, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "Logged in to %s. Credential saved in the owner-only local credential file; expires %s.\n", profile.Name, time.Unix(credential.ExpiresAt, 0).UTC().Format(time.RFC3339))
				return err
			})
		case "access_denied":
			return reportFailure(ctx, "dbl login", stderr, errors.New("browser login denied or cancelled"))
		default:
			return reportFailure(ctx, "dbl login", stderr, errors.New("browser login expired or already used; run dbl login again"))
		}
	}
}

func openLoginBrowser(address string) error {
	var name string
	switch runtime.GOOS {
	case "darwin":
		name = "open"
	case "linux":
		name = "xdg-open"
	default:
		return errors.New("browser opening unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, address)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}
