// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package enrollment

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/tlsfiles"
)

const maxCSRBytes = 16 << 10

// Signer issues client identities whose keys were generated on executor hosts.
// The authority must be trusted by the dispatcher's executor TLS listeners.
type Signer struct {
	issuer        *x509.Certificate
	key           crypto.Signer
	intermediates *x509.CertPool
	roots         *x509.CertPool
	issuerPEM     []byte
	caPEM         string
}

func NewSigner(caCertPath, caKeyPath, trustCAPath string) (*Signer, error) {
	now := time.Now()
	identity, err := tlsfiles.KeyPair("executor_onboarding.ca_cert", caCertPath, "executor_onboarding.ca_key", caKeyPath, now)
	if err != nil {
		return nil, err
	}
	issuer := identity.Leaf
	if !issuer.BasicConstraintsValid || !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("executor_onboarding.ca_cert must be a certificate-signing authority")
	}
	roots, err := tlsfiles.TrustRoots("tls.ca_file", trustCAPath, now)
	if err != nil {
		return nil, err
	}
	key, ok := identity.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("executor_onboarding.ca_key cannot sign certificates")
	}
	s := &Signer{issuer: issuer, key: key, roots: roots, intermediates: x509.NewCertPool()}
	for i, der := range identity.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("executor_onboarding.ca_cert: %w", err)
		}
		if i > 0 {
			s.intermediates.AddCert(cert)
		}
		s.issuerPEM = append(s.issuerPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if _, err := s.validUntil(now); err != nil {
		return nil, err
	}
	trustPEM, err := os.ReadFile(trustCAPath)
	if err != nil {
		return nil, fmt.Errorf("tls.ca_file: %w", err)
	}
	// Return public certificates only, even if the configured trust file also
	// contains unrelated PEM material.
	for len(trustPEM) > 0 {
		block, rest := pem.Decode(trustPEM)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			s.caPEM += string(pem.EncodeToMemory(block))
		}
		trustPEM = rest
	}
	return s, nil
}

// CAPEM returns the public authorities trusted for executor client identities.
func (s *Signer) CAPEM() string { return s.caPEM }

// Sign accepts only proof of key possession from a CSR. Its requested names
// and extensions are ignored: the result is a client-only, non-CA identity.
func (s *Signer) Sign(executorID, csrPEM string) (string, string, error) {
	if strings.TrimSpace(executorID) == "" || len(executorID) > 128 {
		return "", "", errors.New("executor certificate needs an executor ID")
	}
	if len(csrPEM) > maxCSRBytes {
		return "", "", errors.New("executor certificate request exceeds 16 KiB")
	}
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return "", "", errors.New("executor certificate request must contain one PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("parse executor certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", "", fmt.Errorf("verify executor certificate request: %w", err)
	}
	now := time.Now()
	expires, err := s.validUntil(now)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("executor certificate serial: %w", err)
	}
	cert := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: executorID},
		NotBefore:             now,
		NotAfter:              expires,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, s.issuer, csr.PublicKey, s.key)
	if err != nil {
		return "", "", fmt.Errorf("sign executor certificate: %w", err)
	}
	fingerprint := sha256.Sum256(der)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), s.issuerPEM...)
	return string(chain), hex.EncodeToString(fingerprint[:]), nil
}

func (s *Signer) validUntil(now time.Time) (time.Time, error) {
	chains, err := s.issuer.Verify(x509.VerifyOptions{
		Roots: s.roots, Intermediates: s.intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("executor_onboarding.ca_cert must be trusted by tls.ca_file for client certificates: %w", err)
	}
	expires := now.Add(90 * 24 * time.Hour)
	for _, cert := range chains[0] {
		if cert.NotAfter.Before(expires) {
			expires = cert.NotAfter
		}
	}
	return expires, nil
}
