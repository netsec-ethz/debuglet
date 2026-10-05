// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

func TestAdministratorRecoveryUsesExistingAccountAndConsumesOnce(t *testing.T) {
	f := ccNewFixtureWith(t)
	account, oldSession, _ := authAccount(t, f, "historical researcher")
	other, _, _ := authAccount(t, f, "historical researcher")
	user, err := database.New(f.db).GetUserByUUID(t.Context(), uuid.MustParse(account.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec("INSERT INTO owned_executors(executor_id,user_id,name,created_at) VALUES ('retained-node',?,'node',CURRENT_TIMESTAMP)", user.ID); err != nil {
		t.Fatal(err)
	}
	code, selector, digest, err := NewRecoveryCredential()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec("DELETE FROM user_credentials WHERE user_id=?", user.ID); err != nil {
		t.Fatal(err)
	}
	q := database.New(f.db)
	if err := q.UpsertUserCredential(t.Context(), database.UpsertUserCredentialParams{UserID: user.ID, Kind: credentialRecovery, Selector: selector, SecretHash: digest, CreatedAt: models.NewUTCTime(time.Now())}); err != nil {
		t.Fatal(err)
	}
	if err := q.RecordAdminAccountRecovery(t.Context(), database.RecordAdminAccountRecoveryParams{Selector: selector, UserID: user.ID, CaseReference: "verified-support-case", IssuedByUid: 1000, IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	if s, _ := authAs(t, f, code, http.MethodGet, "/me", nil); s != 401 {
		t.Fatalf("recovery code used as session: %d", s)
	}
	status, _, body, _ := authRequest(t, f, http.MethodPost, "/auth/recover", credentialJSON(t, RecoverRequest{RecoveryCode: code}), nil)
	if status != http.StatusOK {
		t.Fatalf("recovery status=%d", status)
	}
	var recovered AccountResponse
	if err := json.Unmarshal(body, &recovered); err != nil {
		t.Fatal(err)
	}
	if recovered.ID != account.ID || recovered.Name != account.Name || recovered.Role != account.Role || recovered.AccountKey == "" || recovered.RecoveryCode == "" {
		t.Fatal("recovery changed canonical account or issued no credentials")
	}
	if s, _ := authAs(t, f, oldSession, http.MethodGet, "/me", nil); s != 401 {
		t.Fatalf("old session remains valid: %d", s)
	}
	if s, _ := authStatus(t, f, http.MethodPost, "/auth/recover", credentialJSON(t, RecoverRequest{RecoveryCode: code}), nil); s != 401 {
		t.Fatalf("replayed code accepted: %d", s)
	}
	var owner, consumed int64
	if err := f.db.QueryRow("SELECT user_id FROM owned_executors WHERE executor_id='retained-node'").Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow("SELECT consumed_at FROM account_recovery_audit WHERE selector=?", selector).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if owner != user.ID || consumed == 0 {
		t.Fatalf("ownership/audit owner=%d consumed=%d", owner, consumed)
	}
	if other.ID == recovered.ID {
		t.Fatal("display-name match joined accounts")
	}
	newSession := authLogin(t, f, recovered.AccountKey)
	if s, _ := authAs(t, f, newSession, http.MethodGet, "/me", nil); s != 200 {
		t.Fatalf("new credential unavailable: %d", s)
	}
}

func TestAdministratorRecoveryRejectsExpiredAndRevokedCodes(t *testing.T) {
	for _, state := range []string{"expired", "revoked"} {
		t.Run(state, func(t *testing.T) {
			f := ccNewFixtureWith(t)
			account, _, _ := authAccount(t, f, "account")
			selector, _, ok := parseCredential(recoveryPrefix, account.RecoveryCode)
			if !ok {
				t.Fatal("fixture recovery code malformed")
			}
			user, err := database.New(f.db).GetUserByUUID(t.Context(), uuid.MustParse(account.ID))
			if err != nil {
				t.Fatal(err)
			}
			expires, revoked := time.Now().Add(time.Hour).Unix(), int64(0)
			if state == "expired" {
				expires = 1
			} else {
				revoked = time.Now().Unix()
			}
			if _, err := f.db.Exec("INSERT INTO account_recovery_audit(selector,user_id,case_reference,issued_by_uid,issued_at,expires_at,revoked_at) VALUES (?,?,'case',1000,1,?,?)", selector, user.ID, expires, revoked); err != nil {
				t.Fatal(err)
			}
			if s, _ := authStatus(t, f, http.MethodPost, "/auth/recover", credentialJSON(t, RecoverRequest{RecoveryCode: account.RecoveryCode}), nil); s != 401 {
				t.Fatalf("%s code accepted: %d", state, s)
			}
			var consumed int64
			if err := f.db.QueryRow("SELECT consumed_at FROM account_recovery_audit WHERE selector=?", selector).Scan(&consumed); err != nil || consumed != 0 {
				t.Fatalf("refused code audit=%d err=%v", consumed, err)
			}
		})
	}
}
