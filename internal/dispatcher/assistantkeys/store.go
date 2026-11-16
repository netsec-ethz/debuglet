// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package assistantkeys stores account-owned provider credentials encrypted at rest.
package assistantkeys

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
)

// Store has one deployment key. It never caches decrypted account credentials.
type Store struct {
	db   *sql.DB
	aead cipher.AEAD
}

func New(db *sql.DB, key []byte) (*Store, error) {
	if db == nil || len(key) != 32 {
		return nil, errors.New("assistant key storage requires a database and a 32-byte encryption key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, aead: aead}, nil
}

// ReadKey loads a base64-encoded 32-byte key from an operator-owned private file.
func ReadKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0037 != 0 {
		return nil, errors.New("assistant encryption key must be a private regular file (0600 or 0640)")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("could not open assistant encryption key")
	}
	defer f.Close()
	encoded, err := io.ReadAll(io.LimitReader(f, 129))
	if err != nil || len(encoded) > 128 {
		return nil, errors.New("could not read bounded assistant encryption key")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("assistant encryption key must encode exactly 32 bytes in base64")
	}
	return key, nil
}

func ValidKey(key string) bool {
	return len(key) > 0 && len(key) <= 8192 && !strings.ContainsFunc(key, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

func (s *Store) Configured(ctx context.Context, account uuid.UUID) (bool, error) {
	_, err := database.New(s.db).GetAssistantKey(ctx, account)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) Load(ctx context.Context, account uuid.UUID) (string, bool, error) {
	data, err := database.New(s.db).GetAssistantKey(ctx, account)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if len(data) < 1+s.aead.NonceSize()+s.aead.Overhead() || data[0] != 1 {
		return "", true, errors.New("invalid encrypted assistant credential")
	}
	nonce := data[1 : 1+s.aead.NonceSize()]
	plain, err := s.aead.Open(nil, nonce, data[1+s.aead.NonceSize():], []byte(account.String()))
	if err != nil || !ValidKey(string(plain)) {
		return "", true, errors.New("could not decrypt account assistant credential")
	}
	return string(plain), true, nil
}

// SaveIn participates in the caller's authorization/write transaction.
func (s *Store) SaveIn(ctx context.Context, q *database.Queries, account uuid.UUID, key string) error {
	if !ValidKey(key) {
		return errors.New("invalid assistant credential format")
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	data := append([]byte{1}, nonce...)
	data = s.aead.Seal(data, nonce, []byte(key), []byte(account.String()))
	return q.SetAssistantKey(ctx, database.SetAssistantKeyParams{Uuid: account, EncryptedKey: data})
}
