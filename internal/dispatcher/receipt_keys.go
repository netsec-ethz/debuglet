// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/fsutil"
)

// Verification receipts (docs/verification.md#http-api) are signed with one
// Ed25519 key, read from attribution.receipt_key_path and created there when
// absent. Every key that was ever current is recorded with its validity, so a
// receipt stays checkable after the key is replaced.

// ErrNoReceiptKey reports a dispatcher that has no place for its receipt key:
// neither attribution.receipt_key_path nor a database directory is known.
var ErrNoReceiptKey = errors.New("no receipt key: attribution.receipt_key_path is not set and the database directory is unknown")

// ReceiptSigner signs verification receipts. It never exposes the private key.
type ReceiptSigner struct {
	keyID string
	key   ed25519.PrivateKey
}

// KeyID names the signing key: the hex of the first 16 bytes of the SHA-256
// of its public key.
func (s *ReceiptSigner) KeyID() string { return s.keyID }

// PublicKey is the key that verifies the signatures.
func (s *ReceiptSigner) PublicKey() ed25519.PublicKey {
	return s.key.Public().(ed25519.PublicKey)
}

// Sign returns the detached signature of payload.
func (s *ReceiptSigner) Sign(payload []byte) []byte { return ed25519.Sign(s.key, payload) }

// ReceiptKeyID is the key ID of an Ed25519 public key.
func ReceiptKeyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:16])
}

// ReceiptKey is one recorded receipt key; ValidTo is nil while it is current.
type ReceiptKey struct {
	KeyID     string
	PublicKey ed25519.PublicKey
	ValidFrom time.Time
	ValidTo   *time.Time
}

// OpenReceiptSigner loads the receipt key, creating it when the file is
// absent, and records it as the current key: a key seen for the first time
// becomes valid now, and every other recorded key stops being valid now.
// stateDirectory is the database directory, where the key is kept when
// attribution.receipt_key_path is empty.
func (d *Dispatcher) OpenReceiptSigner(ctx context.Context, stateDirectory string) (*ReceiptSigner, error) {
	d.mu.RLock()
	path := d.attribution.ReceiptKeyPath
	d.mu.RUnlock()
	if path == "" {
		if stateDirectory == "" {
			return nil, ErrNoReceiptKey
		}
		path = filepath.Join(stateDirectory, config.DefaultReceiptKeyFile)
	}
	key, err := loadReceiptKey(path)
	if err != nil {
		return nil, fmt.Errorf("attribution.receipt_key_path %q: %w", path, err)
	}
	signer := &ReceiptSigner{key: key}
	signer.keyID = ReceiptKeyID(signer.PublicKey())
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	q := database.New(tx)
	now := d.now().UnixNano()
	if err := q.InsertAttributionReceiptKey(ctx, database.InsertAttributionReceiptKeyParams{KeyID: signer.keyID, PublicKey: signer.PublicKey(), ValidFromNs: now}); err != nil {
		return nil, fmt.Errorf("record the receipt key: %w", err)
	}
	if err := q.RetireAttributionReceiptKeys(ctx, database.RetireAttributionReceiptKeysParams{NowNs: now, KeyID: signer.keyID}); err != nil {
		return nil, fmt.Errorf("record the receipt key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return signer, nil
}

// ReceiptKeys lists every recorded receipt key, oldest first.
func (d *Dispatcher) ReceiptKeys(ctx context.Context) ([]ReceiptKey, error) {
	rows, err := database.New(d.db).ListAttributionReceiptKeys(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([]ReceiptKey, 0, len(rows))
	for _, row := range rows {
		key := ReceiptKey{KeyID: row.KeyID, PublicKey: ed25519.PublicKey(row.PublicKey), ValidFrom: time.Unix(0, row.ValidFromNs).UTC()}
		if row.ValidToNs.Valid {
			to := time.Unix(0, row.ValidToNs.Int64).UTC()
			key.ValidTo = &to
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// receiptKeyPEM is the PEM block type of the key file: PKCS #8.
const receiptKeyPEM = "PRIVATE KEY"

// loadReceiptKey reads the Ed25519 key at path, or creates it there, mode
// 0600, when no file exists. A file that exists but holds no Ed25519 key is
// an error, never replaced.
func loadReceiptKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return createReceiptKey(path)
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != receiptKeyPEM {
		return nil, errors.New("holds no PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("holds no PKCS #8 private key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("holds a private key that is not Ed25519")
	}
	return key, nil
}

// createReceiptKey writes a new key to an absent path. A concurrent creation
// wins over this one, whose key is then read back.
func createReceiptKey(path string) (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, fs.ErrExist) {
		return loadReceiptKey(path)
	}
	if err != nil {
		return nil, err
	}
	_, writeErr := file.Write(pem.EncodeToMemory(&pem.Block{Type: receiptKeyPEM, Bytes: der}))
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		os.Remove(path)
		return nil, err
	}
	if err := fsutil.SyncDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return key, nil
}
