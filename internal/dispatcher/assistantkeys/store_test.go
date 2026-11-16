// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package assistantkeys

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func TestEncryptedKeysSurviveRestartAndRemainAccountBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.sqlite")
	db, err := sqlitedb.Open(path, sqlitedb.Create())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	store, err := New(db, key)
	if err != nil {
		t.Fatal(err)
	}
	q := database.New(db)
	a, b := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{a, b} {
		if _, err := q.CreateUser(t.Context(), database.CreateUserParams{Uuid: id, Name: "key test"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SaveIn(t.Context(), q, a, "sk-test-first"); err != nil {
		t.Fatal(err)
	}
	first, err := q.GetAssistantKey(t.Context(), a)
	if err != nil || bytes.Contains(first, []byte("sk-test-first")) {
		t.Fatal("plaintext persisted", err)
	}
	if err := store.SaveIn(t.Context(), q, a, "sk-test-replaced"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err = New(db, key)
	if err != nil {
		t.Fatal(err)
	}
	q = database.New(db)
	value, found, err := store.Load(t.Context(), a)
	if err != nil || !found || value != "sk-test-replaced" {
		t.Fatal("restart lost saved key", err)
	}
	if value, found, err := store.Load(t.Context(), b); err != nil || found || value != "" {
		t.Fatal("other account received key")
	}
	ciphertext, err := q.GetAssistantKey(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.SetAssistantKey(t.Context(), database.SetAssistantKeyParams{Uuid: b, EncryptedKey: ciphertext}); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.Load(t.Context(), b); err == nil || !found {
		t.Fatal("ciphertext copied between accounts was accepted")
	}
	wrong, err := New(db, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := wrong.Load(t.Context(), a); err == nil || !found {
		t.Fatal("wrong deployment key silently accepted")
	}
	if err := q.DeleteAssistantKey(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.Load(t.Context(), a); err != nil || found {
		t.Fatal("deleted key retained")
	}
}

func TestEncryptionKeyFileAndCredentialBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	key := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadKey(path); err != nil || !bytes.Equal(got, key) {
		t.Fatal("private key file", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKey(path); err == nil {
		t.Fatal("public key file accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKey(link); err == nil {
		t.Fatal("symlink accepted")
	}
	for _, invalid := range []string{"", "secret\n", "secret key", string(bytes.Repeat([]byte{'x'}, 8193))} {
		if ValidKey(invalid) {
			t.Fatal("malformed credential accepted")
		}
	}
}
