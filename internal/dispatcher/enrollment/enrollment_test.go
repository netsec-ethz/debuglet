package enrollment_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/enrollment"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

// Two node credentials, in the form the transport reports one: the fingerprint
// of a verified client certificate.
const (
	nodeA = "5d9a1c7f0b2e4a6d8c0f13579bdf2468ace0135791bdf2468ace0135791bdf24"
	nodeB = "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f809"
)

// openStore creates a store over a fresh dispatcher database whose clock the
// test moves; a peer never supplies time.
func openStore(t *testing.T) (context.Context, *enrollment.Store, *atomic.Pointer[time.Time]) {
	t.Helper()
	ctx := t.Context()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "dispatcher.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, database.MigrationFS(),
		goose.WithDisableGlobalRegistry(true), goose.WithLogger(goose.NopLogger()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	var clock atomic.Pointer[time.Time]
	start := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	clock.Store(&start)
	return ctx, enrollment.NewStoreWithClock(db, func() time.Time { return *clock.Load() }), &clock
}

func mint(ctx context.Context, t *testing.T, store *enrollment.Store, executorID string) string {
	t.Helper()
	token, err := store.Issue(ctx, executorID, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return token
}

// TestTokenBootstrapsOneBindingOnce covers the credential the acceptance asks
// for: a token bootstraps a node credential instead of remaining its permanent
// transport secret, and it is spent by the peer that used it.
func TestTokenBootstrapsOneBindingOnce(t *testing.T) {
	ctx, store, _ := openStore(t)
	token := mint(ctx, t, store, "executor")
	if err := store.Bound(ctx, "executor", nodeA); !errors.Is(err, enrollment.ErrNotEnrolled) {
		t.Fatalf("before enrollment: %v", err)
	}
	if err := store.Admit(ctx, "executor", nodeA, token); err != nil {
		t.Fatalf("enrol with the token: %v", err)
	}
	if err := store.Bound(ctx, "executor", nodeA); err != nil {
		t.Fatalf("after enrollment: %v", err)
	}
	// The token is spent; the binding is what admits the node from now on. A
	// node keeps presenting the token until an operator removes it from its
	// configuration, so its next session is admitted with a spent one.
	if err := store.Admit(ctx, "executor", nodeA, token); err != nil {
		t.Fatalf("reconnect presenting the spent token: %v", err)
	}
	if err := store.Admit(ctx, "executor", nodeB, token); !errors.Is(err, enrollment.ErrWrongNode) {
		t.Fatalf("another node reusing a spent token: %v", err)
	}
	if err := store.Bound(ctx, "executor", nodeA); err != nil {
		t.Fatalf("a reused token changed the binding: %v", err)
	}
	// A token never rescues a peer holding no verified certificate: there is
	// nothing to bind the ID to.
	if err := store.Admit(ctx, "stranger", "", mint(ctx, t, store, "stranger")); !errors.Is(err, enrollment.ErrNotEnrolled) {
		t.Fatalf("token from a peer without a certificate: %v", err)
	}
}

// TestTokenIsBoundedAndTargeted refuses a token outside its expiry, one issued
// for another executor ID, and one that is not a token at all.
func TestTokenIsBoundedAndTargeted(t *testing.T) {
	ctx, store, clock := openStore(t)
	token := mint(ctx, t, store, "executor")
	// A token that buys nothing leaves the recorded binding to decide, and
	// here there is none for either ID.
	if err := store.Admit(ctx, "other", nodeA, token); !errors.Is(err, enrollment.ErrNotEnrolled) {
		t.Fatalf("token used for another executor ID: %v", err)
	}
	for _, presented := range []string{"dbx_", "dbx_selector", "not-a-token", token + "x"} {
		if err := store.Admit(ctx, "executor", nodeA, presented); err == nil {
			t.Fatalf("token %q was accepted", presented)
		}
	}
	expired := clock.Load().Add(time.Hour + time.Second)
	clock.Store(&expired)
	if err := store.Admit(ctx, "executor", nodeA, token); !errors.Is(err, enrollment.ErrNotEnrolled) {
		t.Fatalf("expired token: %v", err)
	}
	if err := store.Bound(ctx, "executor", nodeA); !errors.Is(err, enrollment.ErrNotEnrolled) {
		t.Fatalf("an expired token enrolled a node: %v", err)
	}
}

// TestRotationRevocationAndRecovery covers the credential lifecycle: a new
// token replaces the fingerprint and the old certificate is refused from then
// on, revocation leaves nothing bound, and recovery is a new token.
func TestRotationRevocationAndRecovery(t *testing.T) {
	ctx, store, _ := openStore(t)
	if err := store.Admit(ctx, "executor", nodeA, mint(ctx, t, store, "executor")); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if err := store.Admit(ctx, "executor", nodeB, mint(ctx, t, store, "executor")); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := store.Bound(ctx, "executor", nodeA); !errors.Is(err, enrollment.ErrWrongNode) {
		t.Fatalf("the rotated-out certificate is still accepted: %v", err)
	}
	if err := store.Bound(ctx, "executor", nodeB); err != nil {
		t.Fatalf("the rotated-in certificate is refused: %v", err)
	}
	removed, err := store.Revoke(ctx, "executor")
	if err != nil || !removed.Binding {
		t.Fatalf("revoke: removed=%+v err=%v", removed, err)
	}
	if err := store.Bound(ctx, "executor", nodeB); !errors.Is(err, enrollment.ErrNotEnrolled) {
		t.Fatalf("after revocation: %v", err)
	}
	if removed, err := store.Revoke(ctx, "executor"); err != nil || removed.Binding || removed.Tokens != 0 {
		t.Fatalf("revoking an unenrolled ID: removed=%+v err=%v", removed, err)
	}
	// Revoking a node that has not connected yet removes the token it was
	// given and no binding, which the operator has to be told about.
	mint(ctx, t, store, "pending")
	if removed, err := store.Revoke(ctx, "pending"); err != nil || removed.Binding || removed.Tokens != 1 {
		t.Fatalf("revoking a pending enrollment: removed=%+v err=%v", removed, err)
	}
	if err := store.Admit(ctx, "executor", nodeB, mint(ctx, t, store, "executor")); err != nil {
		t.Fatalf("recover with a new token: %v", err)
	}
	if err := store.Bound(ctx, "executor", nodeB); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}
