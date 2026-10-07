// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package enrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

// MaxCertificateBytes bounds a certificate file read for binding: a leaf and
// a few intermediates fit many times over.
const MaxCertificateBytes = 64 << 10

// Binding reports what one administrator binding did.
type Binding struct {
	// Fingerprint is the lowercase hex SHA-256 of the leaf's DER bytes, the
	// value the transport reports for a verified client certificate.
	Fingerprint string
	// Previous is the fingerprint the executor ID was bound to before, empty
	// when it had none.
	Previous string
	// Changed reports that the recorded binding was created or replaced. A
	// binding to the same certificate is left as it is.
	Changed bool
}

// CertificateFingerprint verifies a PEM certificate file an administrator
// issued for executorID and returns the fingerprint the transport would
// report for it. The first certificate is the leaf; any further ones are
// intermediates. The leaf has to chain to roots for client authentication at
// now, must not be an authority, and must carry executorID as its common
// name, which is how deploy/scripts/generate-certs.sh and the enrollment
// signer both issue executor certificates. A file holding anything but
// certificates, a private key in particular, is refused: binding needs public
// material only.
func CertificateFingerprint(executorID string, certPEM []byte, roots *x509.CertPool, now time.Time) (string, error) {
	if strings.TrimSpace(executorID) == "" || len(executorID) > 128 {
		return "", errors.New("binding needs an executor ID")
	}
	if roots == nil {
		return "", errors.New("binding needs the authority client certificates are verified against")
	}
	if len(certPEM) > MaxCertificateBytes {
		return "", fmt.Errorf("certificate file exceeds %d bytes", MaxCertificateBytes)
	}
	var certs []*x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return "", fmt.Errorf("certificate file holds a %q block; give the public certificate only", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("certificate file holds data that is not PEM")
	}
	if len(certs) == 0 {
		return "", errors.New("certificate file holds no PEM certificate")
	}
	leaf := certs[0]
	if leaf.IsCA {
		return "", errors.New("the certificate is an authority, not an executor's client certificate")
	}
	if leaf.Subject.CommonName != executorID {
		return "", fmt.Errorf("the certificate was issued for %q, not for executor %q", leaf.Subject.CommonName, executorID)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return "", fmt.Errorf("the certificate is not a client certificate of the configured authority: %w", err)
	}
	sum := sha256.Sum256(leaf.Raw)
	return hex.EncodeToString(sum[:]), nil
}

// Bind records fingerprint as the node credential of executorID without a
// token: the administrator who controls the database vouches for a
// certificate they issued. It replaces only executorID's own binding, leaves
// any unused token alone, and changes nothing when the same certificate is
// already bound, so running it again is harmless.
func (s *Store) Bind(ctx context.Context, executorID, fingerprint string) (Binding, error) {
	if executorID == "" {
		return Binding{}, errors.New("binding needs an executor ID")
	}
	if len(fingerprint) != 2*sha256.Size || strings.ToLower(fingerprint) != fingerprint {
		return Binding{}, errors.New("binding needs a lowercase hex SHA-256 certificate fingerprint")
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		return Binding{}, errors.New("binding needs a lowercase hex SHA-256 certificate fingerprint")
	}
	result := Binding{Fingerprint: fingerprint}
	err := s.write(ctx, func(q *database.Queries) error {
		previous, err := q.GetExecutorEnrollment(ctx, executorID)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return fmt.Errorf("read executor enrollment: %w", err)
		default:
			result.Previous = previous
		}
		if result.Previous == fingerprint {
			return nil
		}
		if err := q.SetExecutorEnrollment(ctx, database.SetExecutorEnrollmentParams{
			ExecutorID: executorID, Fingerprint: fingerprint, EnrolledAt: models.NewUTCTime(s.now()),
		}); err != nil {
			return fmt.Errorf("record executor enrollment: %w", err)
		}
		result.Changed = true
		return nil
	})
	if err != nil {
		return Binding{}, err
	}
	return result, nil
}
