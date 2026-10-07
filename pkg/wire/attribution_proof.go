// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// AttributionScheduleProof authenticates schedule parameters under an
// executor's enrolled TLS key. The certificate is evidence of a signature,
// not a trust root: consumers must independently pin its fingerprint.
type AttributionScheduleProof struct {
	Certificate []byte `json:"certificate"`
	Signature   []byte `json:"signature"`
}

// AttributionCertificateID is the SHA-256 fingerprint of a DER certificate,
// matching the identity pinned by executor enrollment.
func AttributionCertificateID(certificate []byte) string {
	sum := sha256.Sum256(certificate)
	return hex.EncodeToString(sum[:])
}

func schedulePayload(executor string, schedule AttributionSchedule) ([]byte, error) {
	schedule.OperatorProof = nil
	return json.Marshal(struct {
		Format     string              `json:"format"`
		ExecutorID string              `json:"executor_id"`
		Schedule   AttributionSchedule `json:"schedule"`
	}{"debuglet-tesla-schedule-v1", executor, schedule})
}

func scheduleSignatureAlgorithm(key any) (x509.SignatureAlgorithm, error) {
	switch key.(type) {
	case ed25519.PublicKey:
		return x509.PureEd25519, nil
	case *rsa.PublicKey:
		return x509.SHA256WithRSA, nil
	case *ecdsa.PublicKey:
		return x509.ECDSAWithSHA256, nil
	default:
		return x509.UnknownSignatureAlgorithm, errors.New("unsupported executor signing key")
	}
}

// SignAttributionSchedule uses the existing enrolled TLS identity; no new
// signing key or private material is included in the proof.
func SignAttributionSchedule(executor string, schedule AttributionSchedule, identity tls.Certificate) (*AttributionScheduleProof, error) {
	signer, ok := identity.PrivateKey.(crypto.Signer)
	if !ok || len(identity.Certificate) == 0 {
		return nil, errors.New("executor identity cannot sign")
	}
	payload, err := schedulePayload(executor, schedule)
	if err != nil {
		return nil, err
	}
	algorithm, err := scheduleSignatureAlgorithm(signer.Public())
	if err != nil {
		return nil, err
	}
	input, opts := payload, crypto.SignerOpts(crypto.Hash(0))
	if algorithm != x509.PureEd25519 {
		digest := sha256.Sum256(payload)
		input, opts = digest[:], crypto.SHA256
	}
	signature, err := signer.Sign(rand.Reader, input, opts)
	if err != nil {
		return nil, err
	}
	proof := &AttributionScheduleProof{Certificate: identity.Certificate[0], Signature: signature}
	schedule.OperatorProof = proof
	if err := VerifyAttributionSchedule(executor, schedule, AttributionCertificateID(proof.Certificate)); err != nil {
		return nil, err
	}
	return proof, nil
}

// VerifyAttributionSchedule requires the independently known certificate
// fingerprint of this executor, checks validity at the signed chain origin,
// and verifies every schedule field and the executor ID.
func VerifyAttributionSchedule(executor string, schedule AttributionSchedule, fingerprint string) error {
	proof := schedule.OperatorProof
	if proof == nil || fingerprint == "" || len(proof.Certificate) > 16<<10 || len(proof.Signature) > 1024 || AttributionCertificateID(proof.Certificate) != fingerprint {
		return errors.New("missing or untrusted executor schedule proof")
	}
	certificate, err := x509.ParseCertificate(proof.Certificate)
	if err != nil {
		return fmt.Errorf("executor signing certificate: %w", err)
	}
	origin := time.Unix(0, schedule.T0UnixNs)
	if origin.Before(certificate.NotBefore) || origin.After(certificate.NotAfter) {
		return errors.New("executor signing certificate was not valid at the chain origin")
	}
	algorithm, err := scheduleSignatureAlgorithm(certificate.PublicKey)
	if err != nil {
		return err
	}
	payload, err := schedulePayload(executor, schedule)
	if err != nil {
		return err
	}
	if err := certificate.CheckSignature(algorithm, payload, proof.Signature); err != nil {
		return fmt.Errorf("executor schedule signature: %w", err)
	}
	return nil
}
