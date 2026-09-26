// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package tlsfiles loads the configured TLS identity and trust roots of a
// daemon, and refuses at startup what would fail every handshake later. Each
// error names the configuration key an operator has to correct.
package tlsfiles

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// KeyPair loads a certificate and its key, and refuses a certificate outside
// its validity window: an expired or not yet valid identity fails every
// handshake, so it is reported once here instead of as an unexplained
// rejection per connection. certField and keyField are the configuration keys
// that name the two files.
func KeyPair(certField, certFile, keyField, keyFile string, now time.Time) (tls.Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%s %q with %s %q: %w", certField, certFile, keyField, keyFile, err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%s %q: %w", certField, certFile, err)
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return tls.Certificate{}, fmt.Errorf("%s %q: certificate is valid from %s to %s, which does not include %s; renew it before starting",
			certField, certFile, leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	certificate.Leaf = leaf
	return certificate, nil
}

// TrustRoots reads an authority file and refuses one that cannot verify
// anything: a file holding no certificate, a certificate that does not parse,
// and a root outside its validity window, which would fail every chain built on
// it. A file may hold several roots, which is what an authority rotation needs
// while old and new leaves are both in use.
func TrustRoots(field, path string, now time.Time) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	pool := x509.NewCertPool()
	roots := 0
	for rest := pemBytes; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		root, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", field, path, err)
		}
		if now.Before(root.NotBefore) || now.After(root.NotAfter) {
			return nil, fmt.Errorf("%s %q: authority %q is valid from %s to %s, which does not include %s; renew it before starting",
				field, path, root.Subject.CommonName, root.NotBefore.UTC().Format(time.RFC3339), root.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		}
		pool.AddCert(root)
		roots++
	}
	if roots == 0 {
		return nil, fmt.Errorf("%s %q holds no PEM certificate", field, path)
	}
	return pool, nil
}
