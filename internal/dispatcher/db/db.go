// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"encoding/hex"
	"crypto/sha256"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type UserDB struct {
	db *sql.DB
}

func NewUserDB(path string) (*UserDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	// Pending wallet auth challenges: one per address, short-lived.
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS challenges (
		address    TEXT    PRIMARY KEY,
		nonce      TEXT    NOT NULL,
		expires_at INTEGER NOT NULL
	)`)
	if err != nil {
		return nil, fmt.Errorf("create challenges table: %w", err)
	}

	// Active sessions: one per address, issued after successful signature verification.
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		address    TEXT    PRIMARY KEY,
		token      TEXT    NOT NULL,
		expires_at INTEGER NOT NULL
	)`)
	if err != nil {
		return nil, fmt.Errorf("create sessions table: %w", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS state (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`)
	if err != nil {
		return nil, fmt.Errorf("create state table: %w", err)
	}
	return &UserDB{db: db}, nil
}

func (u *UserDB) Close() error {
	return u.db.Close()
}


// UpdateBalance credits delta to a user's balance, creating the row if it does not exist.
func (u *UserDB) UpdateBalance(userID string, delta int64) error {
	userID = strings.ToLower(userID)
	_, err := u.db.Exec(
		`INSERT INTO users (user_id, auth_key_hash, balance) VALUES (?, '', ?)
		 ON CONFLICT(user_id) DO UPDATE SET balance = balance + excluded.balance`,
		userID, delta,
	)
	if err != nil {
		return fmt.Errorf("update balance: %w", err)
	}
	return nil
}

func (u *UserDB) GetBalance(userID string) (int, error) {
	userID = strings.ToLower(userID)
	var value int
	err := u.db.QueryRow(`SELECT balance FROM users WHERE user_id = ?`, userID).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("get balance for %q: %w", userID, err)
	}
	return value, nil
}

// StoreChallenge saves a nonce for address with the given TTL. Overwrites any existing challenge.
func (u *UserDB) StoreChallenge(address, nonce string, ttl time.Duration) error {
	address = strings.ToLower(address)
	expiresAt := time.Now().Add(ttl).Unix()
	_, err := u.db.Exec(
		`INSERT INTO challenges (address, nonce, expires_at) VALUES (?, ?, ?)
		 ON CONFLICT(address) DO UPDATE SET nonce = excluded.nonce, expires_at = excluded.expires_at`,
		address, nonce, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("store challenge: %w", err)
	}
	return nil
}

// GetAndDeleteChallenge atomically reads and removes the nonce for address.
// Returns an error if no valid (non-expired) challenge exists.
func (u *UserDB) GetAndDeleteChallenge(address string) (string, error) {
	address = strings.ToLower(address)
	tx, err := u.db.Begin()
	if err != nil {
		return "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var nonce string
	var expiresAt int64
	err = tx.QueryRow(`SELECT nonce, expires_at FROM challenges WHERE address = ?`, address).Scan(&nonce, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("no pending challenge for address")
	}
	if err != nil {
		return "", fmt.Errorf("query challenge: %w", err)
	}
	if time.Now().Unix() > expiresAt {
		tx.Exec(`DELETE FROM challenges WHERE address = ?`, address)
		tx.Commit()
		return "", fmt.Errorf("challenge expired")
	}

	if _, err := tx.Exec(`DELETE FROM challenges WHERE address = ?`, address); err != nil {
		return "", fmt.Errorf("delete challenge: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit: %w", err)
	}
	return nonce, nil
}

// StoreSession saves a session token for address with the given TTL. Overwrites any existing session.
func (u *UserDB) StoreSession(address, token string, ttl time.Duration) error {
	address = strings.ToLower(address)
	expiresAt := time.Now().Add(ttl).Unix()
	_, err := u.db.Exec(
		`INSERT INTO sessions (address, token, expires_at) VALUES (?, ?, ?)
		 ON CONFLICT(address) DO UPDATE SET token = excluded.token, expires_at = excluded.expires_at`,
		address, tokenHash(token), expiresAt,
	)
	if err != nil {
		return fmt.Errorf("store session: %w", err)
	}
	return nil
}

// Authenticate returns true if address has a valid (non-expired) session matching token.
func (u *UserDB) Authenticate(address, token string) (bool, error) {
	address = strings.ToLower(address)
	var storedToken string
	var expiresAt int64
	err := u.db.QueryRow(
		`SELECT token, expires_at FROM sessions WHERE address = ?`, address,
	).Scan(&storedToken, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query session: %w", err)
	}
	if time.Now().Unix() > expiresAt {
		u.db.Exec(`DELETE FROM sessions WHERE address = ?`, address)
		return false, nil
	}
	return storedToken == tokenHash(token), nil
}

// GetState returns the value for key, or "" if the key does not exist.
func (u *UserDB) GetState(key string) (string, error) {
	var value string
	err := u.db.QueryRow(`SELECT value FROM state WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get state %q: %w", key, err)
	}
	return value, nil
}

// SetState upserts a key-value pair in the state table.
func (u *UserDB) SetState(key, value string) error {
	_, err := u.db.Exec(
		`INSERT INTO state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("set state %q: %w", key, err)
	}
	return nil
}

func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}