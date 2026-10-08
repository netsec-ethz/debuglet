// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package enrollment_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/enrollment"
	"github.com/netsec-ethz/debuglet/internal/testtls"
)

const boundExecutor = "5fe02882-0410-416c-9935-235090bcba0d"

// TestBindRecordsAnAdministratorIssuedCertificate covers the deployment path:
// an executor whose certificate the administrator issued is bound without a
// token, binding the same certificate again changes nothing, and a reissued
// certificate replaces the binding of that executor ID only.
func TestBindRecordsAnAdministratorIssuedCertificate(t *testing.T) {
	ctx, store, _ := openStore(t)
	first, err := store.Bind(ctx, boundExecutor, nodeA)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if !first.Changed || first.Previous != "" || first.Fingerprint != nodeA {
		t.Fatalf("first binding = %+v", first)
	}
	if err := store.Bound(ctx, boundExecutor, nodeA); err != nil {
		t.Fatalf("bound certificate refused: %v", err)
	}
	again, err := store.Bind(ctx, boundExecutor, nodeA)
	if err != nil {
		t.Fatalf("bind again: %v", err)
	}
	if again.Changed || again.Previous != nodeA {
		t.Fatalf("repeated binding = %+v, want unchanged", again)
	}
	if _, err := store.Bind(ctx, "other-executor", nodeA); err != nil {
		t.Fatalf("bind another executor: %v", err)
	}
	rotated, err := store.Bind(ctx, boundExecutor, nodeB)
	if err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if !rotated.Changed || rotated.Previous != nodeA {
		t.Fatalf("rebinding = %+v", rotated)
	}
	if err := store.Bound(ctx, boundExecutor, nodeA); !errors.Is(err, enrollment.ErrWrongNode) {
		t.Fatalf("the replaced certificate: %v", err)
	}
	if err := store.Bound(ctx, boundExecutor, nodeB); err != nil {
		t.Fatalf("the new certificate: %v", err)
	}
	if err := store.Bound(ctx, "other-executor", nodeA); err != nil {
		t.Fatalf("another executor's binding changed: %v", err)
	}
}

// TestBindLeavesOutstandingTokensAlone keeps a token an operator issued
// usable: binding is not a revocation.
func TestBindLeavesOutstandingTokensAlone(t *testing.T) {
	ctx, store, _ := openStore(t)
	token := mint(ctx, t, store, boundExecutor)
	if _, err := store.Bind(ctx, boundExecutor, nodeA); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := store.Admit(ctx, boundExecutor, nodeB, token); err != nil {
		t.Fatalf("token after binding: %v", err)
	}
}

func TestBindRefusesMalformedInput(t *testing.T) {
	ctx, store, _ := openStore(t)
	for name, fingerprint := range map[string]string{
		"empty":     "",
		"short":     nodeA[:10],
		"uppercase": strings.ToUpper(nodeA),
		"not hex":   strings.Repeat("z", 64),
	} {
		if _, err := store.Bind(ctx, boundExecutor, fingerprint); err == nil {
			t.Errorf("%s fingerprint was bound", name)
		}
	}
	if _, err := store.Bind(ctx, "", nodeA); err == nil {
		t.Error("an empty executor ID was bound")
	}
	if err := store.Bound(ctx, boundExecutor, nodeA); !errors.Is(err, enrollment.ErrNotEnrolled) {
		t.Fatalf("a refused binding was recorded: %v", err)
	}
}

func TestCertificateFingerprint(t *testing.T) {
	dir := t.TempDir()
	authority, err := testtls.NewAuthority(dir, "deployment-ca")
	if err != nil {
		t.Fatal(err)
	}
	client, err := authority.Issue(boundExecutor, testtls.Options{Client: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	fingerprint, err := enrollment.CertificateFingerprint(boundExecutor, client.CertPEM, authority.Pool(), now)
	if err != nil {
		t.Fatalf("a client certificate of the authority was refused: %v", err)
	}
	// The value the transport reports for this certificate once verified.
	sum := sha256.Sum256(client.Certificate.Certificate[0])
	if fingerprint != hex.EncodeToString(sum[:]) {
		t.Fatalf("fingerprint = %s, want the SHA-256 of the leaf DER", fingerprint)
	}
	// A chain file with the authority appended names the same leaf.
	chain := append(append([]byte{}, client.CertPEM...), authority.CertPEM...)
	if got, err := enrollment.CertificateFingerprint(boundExecutor, chain, authority.Pool(), now); err != nil || got != fingerprint {
		t.Fatalf("chain file: %s, %v", got, err)
	}

	other, err := testtls.NewAuthority(t.TempDir(), "other-ca")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := other.Issue(boundExecutor, testtls.Options{Client: true})
	if err != nil {
		t.Fatal(err)
	}
	server, err := authority.Issue(boundExecutor+"-server", testtls.Options{Server: true})
	if err != nil {
		t.Fatal(err)
	}
	serverForID, err := authority.Issue(boundExecutor, testtls.Options{Server: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, id, want string
		pem            []byte
		at             time.Time
	}{
		{"another authority", boundExecutor, "not a client certificate of the configured authority", foreign.CertPEM, now},
		{"server-only usage", boundExecutor, "not a client certificate", serverForID.CertPEM, now},
		{"another executor's name", "1144ad6e-2c14-4e5c-ab72-c05a8e8770f2", "was issued for", client.CertPEM, now},
		{"a different common name", boundExecutor, "was issued for", server.CertPEM, now},
		{"expired", boundExecutor, "not a client certificate", client.CertPEM, now.Add(48 * time.Hour)},
		{"the authority itself", "deployment-ca", "is an authority", authority.CertPEM, now},
		{"a private key", boundExecutor, "public certificate only", append(append([]byte{}, client.CertPEM...), client.KeyPEM...), now},
		{"no certificate", boundExecutor, "no PEM certificate", []byte("\n"), now},
		{"trailing garbage", boundExecutor, "not PEM", append(append([]byte{}, client.CertPEM...), "garbage"...), now},
		{"empty ID", "", "executor ID", client.CertPEM, now},
	} {
		if _, err := enrollment.CertificateFingerprint(tc.id, tc.pem, authority.Pool(), tc.at); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.want)
		}
	}
	if _, err := enrollment.CertificateFingerprint(boundExecutor, client.CertPEM, nil, now); err == nil {
		t.Error("a certificate was accepted with no authority")
	}
}
