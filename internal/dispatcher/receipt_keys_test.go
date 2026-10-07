// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
)

// TestReceiptKeyIsCreatedOnceAndRecorded creates the key file owner-only,
// reads the same key back on the next start, and records it once.
func TestReceiptKeyIsCreatedOnceAndRecorded(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	dir := t.TempDir()
	if _, err := d.OpenReceiptSigner(t.Context(), ""); !errors.Is(err, ErrNoReceiptKey) {
		t.Fatalf("without a place for the key: %v", err)
	}
	signer, err := d.OpenReceiptSigner(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, config.DefaultReceiptKeyFile))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("key file %v, %v; want mode 0600", info, err)
	}
	again, err := d.OpenReceiptSigner(t.Context(), dir)
	if err != nil || again.KeyID() != signer.KeyID() || ReceiptKeyID(signer.PublicKey()) != signer.KeyID() || len(signer.KeyID()) != 32 {
		t.Fatalf("reopened key %v, %v; want %s", again, err, signer.KeyID())
	}
	payload := []byte(`{"api_version":"1.15"}`)
	if !ed25519.Verify(signer.PublicKey(), payload, again.Sign(payload)) {
		t.Fatal("the reopened key signs with another key")
	}
	keys, err := d.ReceiptKeys(t.Context())
	if err != nil || len(keys) != 1 || keys[0].KeyID != signer.KeyID() || keys[0].ValidTo != nil {
		t.Fatalf("recorded keys %+v, %v", keys, err)
	}
}

// TestReceiptKeyFileMustHoldAnEd25519Key refuses a file it cannot use instead
// of replacing it.
func TestReceiptKeyFileMustHoldAnEd25519Key(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultReceiptKeyFile)
	if err := os.WriteFile(path, []byte("not a key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.OpenReceiptSigner(t.Context(), dir); err == nil {
		t.Fatal("a file without a key was accepted")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "not a key\n" {
		t.Fatalf("the file was changed: %q, %v", data, err)
	}
}
