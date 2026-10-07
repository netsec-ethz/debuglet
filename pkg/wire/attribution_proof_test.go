// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestAttributionScheduleProofBindsExecutorAndEveryParameter(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]crypto.Signer{"ed25519": edKey, "ecdsa": ec, "rsa": rsaKey} {
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
			der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
			if err != nil {
				t.Fatal(err)
			}
			schedule := AttributionSchedule{ChainID: "chain", K0: []byte("anchor"), T0UnixNs: now.UnixNano(), EpochSeconds: 10, DisclosureDelayEpochs: 90, ChainLength: 600, TagSpec: 1}
			schedule.OperatorProof, err = SignAttributionSchedule("executor", schedule, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key})
			if err != nil {
				t.Fatal(err)
			}
			pin := AttributionCertificateID(der)
			if err := VerifyAttributionSchedule("executor", schedule, pin); err != nil {
				t.Fatal(err)
			}
			if err := VerifyAttributionSchedule("other", schedule, pin); err == nil {
				t.Fatal("proof accepted for another executor")
			}
			if err := VerifyAttributionSchedule("executor", schedule, "different"); err == nil {
				t.Fatal("untrusted certificate accepted")
			}
			for field, change := range map[string]func(*AttributionSchedule){
				"chain":     func(s *AttributionSchedule) { s.ChainID = "different" },
				"anchor":    func(s *AttributionSchedule) { s.K0 = []byte("another") },
				"origin":    func(s *AttributionSchedule) { s.T0UnixNs++ },
				"interval":  func(s *AttributionSchedule) { s.EpochSeconds++ },
				"delay":     func(s *AttributionSchedule) { s.DisclosureDelayEpochs++ },
				"length":    func(s *AttributionSchedule) { s.ChainLength++ },
				"algorithm": func(s *AttributionSchedule) { s.TagSpec++ },
			} {
				altered := schedule
				change(&altered)
				if err := VerifyAttributionSchedule("executor", altered, pin); err == nil {
					t.Errorf("%s alteration accepted", field)
				}
			}
		})
	}
}
