package api

import (
	"errors"
	"net/http"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

func TestConcurrentRecoveryConsumesCodeOnce(t *testing.T) {
	f := ccNewFixtureWith(t)
	account, _, oldSession := authAccount(t, f, "concurrent recovery")
	anonymous := f.client(f.root.URL, false)
	ctx, cancel := f.requestCtx()
	defer cancel()

	type result struct {
		account client.Account
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			account, err := anonymous.Recover(ctx, account.RecoveryCode)
			results <- result{account, err}
		}()
	}
	close(start)
	var recovered client.Account
	successes := 0
	for range 2 {
		result := <-results
		if result.err == nil {
			successes++
			recovered = result.account
		} else if !authIsUnauthorized(result.err) {
			t.Fatalf("concurrent recovery: %v", result.err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful recoveries = %d, want exactly one", successes)
	}
	if _, err := anonymous.Login(ctx, recovered.AccountKey); err != nil {
		t.Fatalf("the successful recovery returned an unusable key: %v", err)
	}
	if _, err := oldSession.Whoami(ctx); !authIsUnauthorized(err) {
		t.Fatalf("the previous session survived recovery: %v", err)
	}
	if _, err := anonymous.Recover(ctx, account.RecoveryCode); !authIsUnauthorized(err) {
		t.Fatalf("the consumed recovery code remained usable: %v", err)
	}
}

func TestConcurrentLoginCannotSurviveRecovery(t *testing.T) {
	f := ccNewFixtureWith(t)
	account, _, _ := authAccount(t, f, "concurrent login")
	anonymous := f.client(f.root.URL, false)
	ctx, cancel := f.requestCtx()
	defer cancel()

	// Each login must either finish before recovery and have its session
	// revoked, or verify the old key after recovery and reject it.
	type result struct {
		session client.Session
		err     error
	}
	const logins = 12
	start := make(chan struct{})
	results := make(chan result, logins)
	for range logins {
		go func() {
			<-start
			session, err := anonymous.Login(ctx, account.AccountKey)
			results <- result{session, err}
		}()
	}
	close(start)
	recovered, err := anonymous.Recover(ctx, account.RecoveryCode)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	for range logins {
		result := <-results
		if result.err != nil {
			if !authIsUnauthorized(result.err) {
				t.Fatalf("concurrent login: %v", result.err)
			}
			continue
		}
		authenticated, err := anonymous.WithCredential(result.session.Token)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authenticated.Whoami(ctx); !authIsUnauthorized(err) {
			t.Fatalf("a session issued from the previous key survived recovery: %v", err)
		}
	}
	if _, err := anonymous.Login(ctx, account.AccountKey); !authIsUnauthorized(err) {
		t.Fatalf("the previous account key remained usable: %v", err)
	}
	if _, err := anonymous.Login(ctx, recovered.AccountKey); err != nil {
		t.Fatalf("the replacement account key failed: %v", err)
	}
}

func TestFailedRecoveryPreservesCredentialsAndSessions(t *testing.T) {
	f := ccNewFixtureWith(t)
	account, _, authenticated := authAccount(t, f, "failed recovery")
	anonymous := f.client(f.root.URL, false)
	ctx, cancel := f.requestCtx()
	defer cancel()

	// Fail the last replacement write after session revocation and the new
	// account-key write have run. The entire operation must roll back.
	if _, err := f.db.ExecContext(ctx, `CREATE TRIGGER fail_recovery
		BEFORE INSERT ON user_credentials WHEN NEW.kind = 'recovery'
		BEGIN SELECT RAISE(ABORT, 'recovery write failed'); END`); err != nil {
		t.Fatal(err)
	}
	_, err := anonymous.Recover(ctx, account.RecoveryCode)
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusInternalServerError || httpErr.Code != CodeInternal {
		t.Fatalf("failed recovery = %v, want 500 internal", err)
	}
	if _, err := authenticated.Whoami(ctx); err != nil {
		t.Fatalf("failed recovery revoked the previous session: %v", err)
	}
	if _, err := anonymous.Login(ctx, account.AccountKey); err != nil {
		t.Fatalf("failed recovery replaced the previous account key: %v", err)
	}
	if _, err := f.db.ExecContext(ctx, "DROP TRIGGER fail_recovery"); err != nil {
		t.Fatal(err)
	}
	if _, err := anonymous.Recover(ctx, account.RecoveryCode); err != nil {
		t.Fatalf("failed recovery consumed the previous recovery code: %v", err)
	}
}
