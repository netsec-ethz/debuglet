// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func importTokenCommand(ctx context.Context, c *client.Client, profile connections.Profile, options globalOptions, path, storage string, stdout, stderr io.Writer) int {
	token, err := readAPIToken(path)
	if err != nil {
		return reportFailure(ctx, "dbl login: read API credential", stderr, err)
	}
	authenticated, err := c.WithCredential(token)
	if err != nil {
		return reportFailure(ctx, "dbl login", stderr, err)
	}
	status, err := authenticated.CredentialStatus(ctx)
	if err != nil {
		var apiError *client.HTTPError
		if errors.As(err, &apiError) && apiError.StatusCode == http.StatusForbidden {
			err = fmt.Errorf("%w; token import requires the account:read scope", err)
		}
		return reportFailure(ctx, "dbl login: verify API credential (check its dispatcher, expiry and revocation)", stderr, err)
	}
	if status.Kind != "api" || status.ID == "" || len(status.Scopes) == 0 {
		return reportFailure(ctx, "dbl login", stderr, errors.New("--token-file requires a scoped API credential from the console Credentials page"))
	}
	if status.Audience != profile.Endpoint {
		return reportFailure(ctx, "dbl login", stderr, errors.New("API credential belongs to another dispatcher"))
	}
	if status.ExpiresAt <= time.Now().Unix() {
		return reportFailure(ctx, "dbl login", stderr, errors.New("API credential has expired; create a replacement in the console"))
	}
	// This token already exists and may be in use elsewhere. Unlike newly issued
	// login credentials, a local persistence failure must not revoke it.
	result, err := connections.SaveCredentialWithStorage(ctx, options.ConfigPath, profile.Name, connections.Credential{
		Endpoint: profile.Endpoint, Token: token, ExpiresAt: status.ExpiresAt,
	}, storage)
	if err != nil {
		return reportFailure(ctx, "dbl login: store API credential", stderr, err)
	}
	if result.Warning != "" {
		fmt.Fprintln(stderr, result.Warning)
	}
	return emitReported(ctx, "dbl login", options.Output, stdout, stderr, map[string]any{
		"dispatcher": profile.Name, "endpoint": profile.Endpoint, "credential_id": status.ID,
		"expires_at": status.ExpiresAt, "scopes": status.Scopes, "credential_store": storage,
	}, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "Imported API credential for %s. Credential store: %s; expires %s.\n", profile.Name, credentialStorageLabel(storage), time.Unix(status.ExpiresAt, 0).UTC().Format(time.RFC3339))
		return err
	})
}

func readAPIToken(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", errors.New("cannot open API credential file")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxAccountKeyFile {
		return "", errors.New("API credential file must be regular, owner-only (mode 0600) and at most 4 KiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("cannot open API credential file")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 {
		return "", errors.New("API credential file changed while opening it")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxAccountKeyFile+1))
	if err != nil || len(data) > maxAccountKeyFile {
		return "", errors.New("cannot read API credential file (limit 4 KiB)")
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("API credential file is empty")
	}
	return token, nil
}
