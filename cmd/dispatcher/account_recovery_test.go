// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"database/sql"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

func recoveryFixture(t *testing.T) (*config.DispatcherConfig, *sql.DB, database.User, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "dispatcher.sqlite")
	if err := storagecheck.BootstrapFresh(t.Context(), storagecheck.Dispatcher, path); err != nil {
		t.Fatal(err)
	}
	db, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	user, err := database.New(db).CreateUser(t.Context(), database.CreateUserParams{Uuid: uuid.New(), Name: "historical researcher"})
	if err != nil {
		t.Fatal(err)
	}
	return dispatcherConfig(path), db, user, filepath.Join(dir, "recovery.txt")
}

func TestAdminRecoveryPreservesIdentityAndRevokesSessions(t *testing.T) {
	cfg, db, user, output := recoveryFixture(t)
	for _, query := range []string{
		"INSERT INTO owned_executors(executor_id,user_id,name,created_at) VALUES ('node',?,'historical node',CURRENT_TIMESTAMP)",
		"INSERT INTO sessions(selector,verifier_hash,csrf_hash,user_id,created_at,expires_at) VALUES ('old',X'01',X'02',?,CURRENT_TIMESTAMP,'2999-01-01')",
	} {
		if _, err := db.Exec(query, user.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := administerAccountRecovery(t.Context(), cfg, user.Uuid.String(), "support-17", output, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private output: %v, %v", info, err)
	}
	code, err := os.ReadFile(output)
	if err != nil || !strings.HasPrefix(string(code), "dbr_") {
		t.Fatalf("recovery file unavailable: %v", err)
	}
	var owner, revoked, lifetime, issuer int64
	var reference string
	if err := db.QueryRow("SELECT user_id FROM owned_executors WHERE executor_id='node'").Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT revoked FROM sessions WHERE selector='old'").Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT case_reference,expires_at-issued_at,issued_by_uid FROM account_recovery_audit").Scan(&reference, &lifetime, &issuer); err != nil {
		t.Fatal(err)
	}
	got, err := database.New(db).GetUserByUUID(t.Context(), user.Uuid)
	if err != nil || got != user || owner != user.ID || revoked != 1 || reference != "support-17" || lifetime != 86400 || issuer != int64(os.Geteuid()) {
		t.Fatalf("identity/revocation/audit mismatch: user=%+v owner=%d revoked=%d reference=%q lifetime=%d uid=%d err=%v", got, owner, revoked, reference, lifetime, issuer, err)
	}
	if err := administerAccountRecovery(t.Context(), cfg, user.Uuid.String(), "support-18", output+".second", false); err == nil {
		t.Fatal("duplicate recovery accepted")
	}
	if err := administerAccountRecovery(t.Context(), cfg, user.Uuid.String(), "lost-delivery", "", true); err != nil {
		t.Fatal(err)
	}
	var credentials int
	if err := db.QueryRow("SELECT COUNT(*) FROM user_credentials").Scan(&credentials); err != nil || credentials != 0 {
		t.Fatalf("revoked recovery still usable: %d %v", credentials, err)
	}
	if err := administerAccountRecovery(t.Context(), cfg, user.Uuid.String(), "support-17", output+".reuse", false); err == nil {
		t.Fatal("reused audit case accepted")
	}
	if err := administerAccountRecovery(t.Context(), cfg, user.Uuid.String(), "support-19", output+".retry", false); err != nil {
		t.Fatal(err)
	}
}

func TestAdminRecoveryRefusesMappedAndUnknownAccounts(t *testing.T) {
	for _, kind := range []string{"credential", "provider", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			cfg, db, user, output := recoveryFixture(t)
			var err error
			switch kind {
			case "credential":
				_, err = db.Exec("INSERT INTO user_credentials VALUES (?,'account','existing',X'01',CURRENT_TIMESTAMP)", user.ID)
			case "provider":
				_, err = db.Exec("INSERT INTO oauth_identities VALUES ('github','https://github.com','subject',?,'login',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)", user.ID)
			case "unknown":
				user.Uuid = uuid.New()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := administerAccountRecovery(t.Context(), cfg, user.Uuid.String(), "support", output, false); err == nil {
				t.Fatal("mapped/unknown account accepted")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("refused recovery created an output")
			}
		})
	}
}

func TestAdminRecoveryOutputFailureRollsBack(t *testing.T) {
	for _, kind := range []string{"existing", "symlink", "public-parent", "commit"} {
		t.Run(kind, func(t *testing.T) {
			cfg, db, user, output := recoveryFixture(t)
			switch kind {
			case "existing":
				if err := os.WriteFile(output, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("absent", output); err != nil {
					t.Fatal(err)
				}
			case "public-parent":
				if err := os.Chmod(filepath.Dir(output), 0755); err != nil {
					t.Fatal(err)
				}
			case "commit":
				// A deferred SQLite constraint fails at commit after file publication.
				_, err := db.Exec("CREATE TABLE recovery_commit_failure(user_id INTEGER REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER recovery_fail AFTER INSERT ON account_recovery_audit BEGIN INSERT INTO recovery_commit_failure VALUES (-1); END")
				if err != nil {
					t.Fatal(err)
				}
			}
			err := administerAccountRecovery(t.Context(), cfg, user.Uuid.String(), "support", output, false)
			if err == nil {
				t.Fatal("output/commit failure accepted")
			}
			var count int
			if err := db.QueryRow("SELECT (SELECT COUNT(*) FROM user_credentials)+(SELECT COUNT(*) FROM account_recovery_audit)").Scan(&count); err != nil || count != 0 {
				t.Fatalf("failed issuance persisted: %d %v", count, err)
			}
			if kind == "existing" {
				b, _ := os.ReadFile(output)
				if string(b) != "keep" {
					t.Fatal("existing output overwritten")
				}
			}
			if kind == "commit" && !strings.Contains(err.Error(), "private output retained") {
				t.Fatalf("uncertain commit lacks recovery instruction: %v", err)
			}
		})
	}
}

func TestAdminRecoveryConcurrentIssueAppliesOnce(t *testing.T) {
	cfg, db, user, output := recoveryFixture(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, suffix := range []string{"a", "b"} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results <- administerAccountRecovery(context.Background(), cfg, user.Uuid.String(), "case-"+suffix, output+suffix, false)
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	var records int
	if err := db.QueryRow("SELECT COUNT(*) FROM account_recovery_audit").Scan(&records); err != nil || success != 1 || records != 1 {
		t.Fatalf("success=%d audit=%d err=%v", success, records, err)
	}
}

func TestRecoveryFlagBoundaries(t *testing.T) {
	for _, extra := range []string{"version", "upgrade-database", "grant-operator"} {
		fs := flag.NewFlagSet("dispatcher", flag.ContinueOnError)
		fs.String(extra, "", "")
		if err := fs.Parse([]string{"-" + extra, "x"}); err != nil {
			t.Fatal(err)
		}
		if err := validateRecoveryFlags(fs, "uuid", "", "case", "/private/output"); err == nil {
			t.Fatalf("accepted -%s", extra)
		}
	}
	fs := flag.NewFlagSet("dispatcher", flag.ContinueOnError)
	for _, values := range [][4]string{{"", "", "", ""}, {"uuid", "uuid", "case", "/file"}, {"uuid", "", "case", ""}, {"", "uuid", "case", "/file"}} {
		if err := validateRecoveryFlags(fs, values[0], values[1], values[2], values[3]); err == nil {
			t.Fatalf("invalid flags accepted: %v", values)
		}
	}
}
