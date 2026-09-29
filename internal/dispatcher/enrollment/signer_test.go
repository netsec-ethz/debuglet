// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/testtls"
)

func TestSignerIssuesOnlyExecutorClientIdentity(t *testing.T) {
	ca := signerAuthority(t, nil, nil)
	s, err := NewSigner(ca.CertFile, ca.KeyFile, ca.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	key, request := signerRequest(t)
	before := time.Now()
	certificate, fingerprint, err := s.Sign("node-id", request)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := tls.X509KeyPair([]byte(certificate), key)
	if err != nil {
		t.Fatalf("certificate does not match the machine key: %v", err)
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "node-id" || len(leaf.Subject.Names) != 1 || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) != 0 || leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("unexpected issued identity: %+v", leaf)
	}
	if leaf.NotAfter.After(time.Now().Add(90*24*time.Hour)) || leaf.NotAfter.Before(before.Add(90*24*time.Hour-time.Second)) {
		t.Fatalf("certificate expiry = %s, want 90 days", leaf.NotAfter)
	}
	wantFingerprint := sha256.Sum256(leaf.Raw)
	if fingerprint != hex.EncodeToString(wantFingerprint[:]) {
		t.Fatalf("fingerprint = %s", fingerprint)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(s.CAPEM()))
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("client verification: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("executor identity accepted as a server")
	}
}

func TestSignerRejectsUnusableRequests(t *testing.T) {
	ca := signerAuthority(t, nil, nil)
	s, err := NewSigner(ca.CertFile, ca.KeyFile, ca.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	_, request := signerRequest(t)
	block, _ := pem.Decode([]byte(request))
	block.Bytes[len(block.Bytes)-1] ^= 1
	badSignature := string(pem.EncodeToMemory(block))
	for name, input := range map[string]string{
		"empty": "", "wrong type": string(ca.CertPEM), "oversized": strings.Repeat("x", maxCSRBytes+1),
		"second request": request + request, "trailing data": request + "unparsed", "signature": badSignature,
	} {
		t.Run(name, func(t *testing.T) {
			cert, fingerprint, err := s.Sign("node-id", input)
			if err == nil || cert != "" || fingerprint != "" {
				t.Fatalf("accepted unusable request: %q %q %v", cert, fingerprint, err)
			}
		})
	}
	if _, _, err := s.Sign("", request); err == nil {
		t.Fatal("accepted an empty executor ID")
	}
}

func TestSignerAuthorityAndExpiry(t *testing.T) {
	root := signerAuthority(t, nil, nil)
	shortExpiry := time.Now().Add(time.Hour).Truncate(time.Second)
	intermediate := signerAuthority(t, root, func(cert *x509.Certificate) { cert.NotAfter = shortExpiry })
	s, err := NewSigner(intermediate.CertFile, intermediate.KeyFile, root.CertFile)
	if err != nil {
		t.Fatalf("trusted intermediate: %v", err)
	}
	_, request := signerRequest(t)
	certificate, _, err := s.Sign("node-id", request)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(certificate))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.NotAfter.Equal(shortExpiry) {
		t.Fatalf("leaf expiry %s exceeds issuer expiry %s", leaf.NotAfter, shortExpiry)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(intermediate.CertPEM)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: s.roots, Intermediates: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("issued chain: %v", err)
	}
	if _, err := s.validUntil(shortExpiry.Add(time.Second)); err == nil {
		t.Fatal("expired authority still issues certificates")
	}
	other := signerAuthority(t, nil, nil)
	for name, pair := range map[string]*testtls.Identity{
		"not a CA":         signerAuthority(t, nil, func(cert *x509.Certificate) { cert.IsCA = false }),
		"no signing usage": signerAuthority(t, nil, func(cert *x509.Certificate) { cert.KeyUsage = x509.KeyUsageDigitalSignature }),
		"expired":          signerAuthority(t, nil, func(cert *x509.Certificate) { cert.NotAfter = time.Now().Add(-time.Minute) }),
		"future":           signerAuthority(t, nil, func(cert *x509.Certificate) { cert.NotBefore = time.Now().Add(time.Hour) }),
		"server only":      signerAuthority(t, root, func(cert *x509.Certificate) { cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSigner(pair.CertFile, pair.KeyFile, pair.CertFile); err == nil {
				t.Fatal("accepted unusable signing authority")
			}
		})
	}
	if _, err := NewSigner(root.CertFile, other.KeyFile, root.CertFile); err == nil {
		t.Fatal("accepted mismatched signing key")
	}
	if _, err := NewSigner(root.CertFile, root.KeyFile, other.CertFile); err == nil {
		t.Fatal("accepted untrusted authority")
	}
	trust := filepath.Join(t.TempDir(), "trust.pem")
	if err := os.WriteFile(trust, append(append([]byte{}, root.CertPEM...), root.KeyPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = NewSigner(root.CertFile, root.KeyFile, trust)
	if err != nil || s.CAPEM() != string(root.CertPEM) {
		t.Fatalf("trust response must contain public certificates only: %v", err)
	}
}

func signerRequest(t *testing.T) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "requested-name", Organization: []string{"requested-organization"}},
		DNSNames:        []string{"requested.example"},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func signerAuthority(t *testing.T, parent *testtls.Identity, change func(*x509.Certificate)) *testtls.Identity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "signer authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	if change != nil {
		change(cert)
	}
	issuer, signer := cert, key
	if parent != nil {
		issuer, err = x509.ParseCertificate(parent.Certificate.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		signer = parent.Certificate.PrivateKey.(*ecdsa.PrivateKey)
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	identity := &testtls.Identity{CertFile: filepath.Join(dir, "ca.crt"), KeyFile: filepath.Join(dir, "ca.key"),
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})}
	if parent != nil {
		identity.CertPEM = append(identity.CertPEM, parent.CertPEM...)
	}
	for path, contents := range map[string][]byte{identity.CertFile: identity.CertPEM, identity.KeyFile: identity.KeyPEM} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	identity.Certificate, err = tls.X509KeyPair(identity.CertPEM, identity.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
