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

	_ "modernc.org/sqlite"
)

type TransactionDB struct {
	db *sql.DB
}

type Transaction struct {
	Id        string
	AuthKey   string
	Price     int64
	Method    string
	ExpiresAt int64
	Payed     bool
	Hash      string
}

func NewTransactionDB(path string) (*TransactionDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS transactions (
		transaction_id 	TEXT	PRIMARY KEY NOT NULL,
		auth_key		TEXT	NOT NULL,
		price			INTEGER NOT NULL,
		method			TEXT	NOT NULL,
		expires_at		INTEGER	NOT NULL,
		payed			BOOLEAN	NOT NULL,
		hash			TEXT	NOT NULL
		)`)

	if err != nil {
		return nil, fmt.Errorf("create transactions table: %w", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS state (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`)

	if err != nil {
		return nil, fmt.Errorf("create state table: %w", err)
	}
	return &TransactionDB{db: db}, nil
}

func (t *TransactionDB) Close() error {
	return t.db.Close()
}

func (t *TransactionDB) GetState(key string) (string, error) {
	var value string
	err := t.db.QueryRow(`SELECT value FROM state WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get state %q: %w", key, err)
	}
	return value, nil
}

func (t *TransactionDB) SetState(key, value string) error {
	_, err := t.db.Exec(
		`INSERT INTO state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("set state %q: %w", key, err)
	}
	return nil
}

func (t *TransactionDB) StoreTransaction(transaction Transaction) error {

	_, err := t.db.Exec(
		`INSERT INTO transactions (transaction_id, auth_key, price, method, expires_at, payed, hash) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		transaction.Id, transaction.AuthKey, transaction.Price, transaction.Method, transaction.ExpiresAt, transaction.Payed, transaction.Hash,
	)
	if err != nil {
		return fmt.Errorf("store transaction: %w", err)
	}
	return nil
}

func (t *TransactionDB) GetTransaction(transactionId string) (Transaction, error) {
	var transaction Transaction
	transaction.Id = transactionId
	err := t.db.QueryRow(`SELECT auth_key, price, payed, method, hash, expires_at FROM transactions WHERE transaction_id = ?`, transactionId).Scan(&transaction.AuthKey, &transaction.Price, &transaction.Payed, &transaction.Method, &transaction.Hash, &transaction.ExpiresAt)
	if err != nil {
		return transaction, fmt.Errorf("get transaction %q: %w", transactionId, err)
	}
	return transaction, nil
}

func (t *TransactionDB) SetPayed(transactionId string) error {
	_, err := t.db.Exec(`UPDATE transactions SET payed = TRUE WHERE transaction_id = ?`, transactionId)
	return err
}

func (t *TransactionDB) IsPayed(transactionId string) (bool, error) {
	transaction, err := t.GetTransaction(transactionId)
	if err != nil {
		return false, err
	}
	return transaction.Payed, nil
}
