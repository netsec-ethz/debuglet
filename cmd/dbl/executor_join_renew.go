// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/netsec-ethz/debuglet/internal/demo/service"
)

func renewExecutorCertificate(ctx context.Context, installer *service.Installer, p service.Profile, client *http.Client, endpoint, token string) (err error) {
	keyPEM, err := os.ReadFile(filepath.Join(p.StateDir, "executor.key"))
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(p.StateDir, "executor.crt"), filepath.Join(p.StateDir, "executor.key"))
	if err != nil {
		return err
	}
	key, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("retained executor key cannot sign a certificate request")
	}
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w; keep the service stopped. If enrollment was sent, obtain a fresh Set up again token and repeat the same --renew command; do not delete or re-enroll the state directory", err)
		}
	}()
	result, err := requestExecutorCertificate(ctx, client, endpoint, p.ExecutorID, token, key, keyPEM)
	if err != nil {
		return err
	}
	if result.GRPCAddress != p.DispatcherGRPC || result.YamuxAddress != p.DispatcherHTTP {
		return errors.New("renewal returned different native endpoints; ask the service operator for recovery instructions")
	}
	if err := installer.RenewCertificate(ctx, p.Name, []byte(result.CertificatePEM)); err != nil {
		return fmt.Errorf("publish renewed certificate under retained native trust: %w", err)
	}
	return nil
}
