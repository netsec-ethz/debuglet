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
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		user_id       TEXT    PRIMARY KEY,
		auth_key_hash TEXT    NOT NULL,
		balance       INTEGER NOT NULL DEFAULT 0
	)`)
	if err != nil {
		return nil, fmt.Errorf("create users table: %w", err)
	}
	return &UserDB{db: db}, nil
}

func (u *UserDB) Close() error {
	return u.db.Close()
}

// CreateUser stores a new user with a bcrypt-hashed auth key.
func (u *UserDB) CreateUser(userID, authKey string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(authKey), 12)
	if err != nil {
		return fmt.Errorf("hash auth key: %w", err)
	}
	_, err = u.db.Exec(`INSERT INTO users (user_id, auth_key_hash) VALUES (?, ?)`, userID, string(hash))
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

// Authenticate returns true if userID exists and authKey matches the stored hash.
func (u *UserDB) Authenticate(userID, authKey string) (bool, error) {
	var hash string
	err := u.db.QueryRow(`SELECT auth_key_hash FROM users WHERE user_id = ?`, userID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query user: %w", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(authKey)); err != nil {
		return false, nil
	}
	return true, nil
}
