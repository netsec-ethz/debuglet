// Package enrollment binds an executor ID to the node credential its machine
// holds: the SHA-256 fingerprint of the client certificate the dispatcher's
// configured authority verified on a control connection. An operator creates a
// single-use, expiring token on the dispatcher host; the executor presents it
// once in its first Hello, and the dispatcher records the fingerprint. From
// then on that ID is admitted only over that certificate.
//
// This is a node identity, not a session. It outlives control sessions, their
// generations and their leases, and it fences no message: what it answers is
// which machine may act as an executor ID, and nothing else.
package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

// A token is printed as dbx_<selector>.<verifier>, the form the HTTP
// credentials use: the selector is the lookup key, and only the SHA-256 digest
// of the verifier is stored and compared in constant time.
const (
	tokenPrefix = "dbx"
	// selectorBytes and verifierBytes size the two halves of a token.
	selectorBytes = 16
	verifierBytes = 32
	// maxTokenLength bounds a presented token before it is parsed.
	maxTokenLength = 128
	// DefaultLifetime bounds an issued token. A node that was not installed
	// within it needs a new one; the old token is not a standing credential.
	DefaultLifetime = 24 * time.Hour
)

var (
	// ErrNotEnrolled reports an executor ID no node credential is bound to.
	ErrNotEnrolled = errors.New("executor ID is not enrolled")
	// ErrWrongNode reports a peer holding a certificate other than the one
	// enrolled for the executor ID it claims.
	ErrWrongNode = errors.New("certificate is not the one enrolled for this executor ID")
	// ErrUnusableToken reports a token that is malformed, unknown, expired,
	// already spent, or issued for another executor ID.
	ErrUnusableToken = errors.New("enrollment token is unusable")
)

// Store is the dispatcher's enrollment table.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Revoked reports what one revocation removed.
type Revoked struct {
	// Binding reports that an enrolled certificate was deleted.
	Binding bool
	// Tokens counts the unused tokens deleted with it.
	Tokens int64
}

// NewStore reads and writes enrollments in the dispatcher's database.
func NewStore(db *sql.DB) *Store { return NewStoreWithClock(db, time.Now) }

// NewStoreWithClock fixes the clock that decides token expiry. A peer never
// supplies time.
func NewStoreWithClock(db *sql.DB, now func() time.Time) *Store {
	return &Store{db: db, now: now}
}

// write runs one atomic group of statements. Spending a token and recording
// the binding it bought is one decision, and so is replacing a token: half of
// either leaves an ID that nothing can enrol.
func (s *Store) write(ctx context.Context, fn func(*database.Queries) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin enrollment transaction: %w", err)
	}
	defer tx.Rollback()
	if err := fn(database.New(tx)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit enrollment transaction: %w", err)
	}
	return nil
}

// Issue mints a single-use token for executorID, stores its digest with an
// expiry and returns the printed token. That return is the only time the token
// exists outside the operator's hands. Any token the ID still had is dropped,
// so at most one is outstanding.
func (s *Store) Issue(ctx context.Context, executorID string, lifetime time.Duration) (string, error) {
	if executorID == "" {
		return "", errors.New("enrollment needs an executor ID")
	}
	if lifetime <= 0 {
		lifetime = DefaultLifetime
	}
	selector, err := secret(selectorBytes)
	if err != nil {
		return "", err
	}
	verifier, err := secret(verifierBytes)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(verifier))
	now := s.now()
	err = s.write(ctx, func(q *database.Queries) error {
		if _, err := q.DeleteExecutorEnrollmentTokens(ctx, executorID); err != nil {
			return fmt.Errorf("drop outstanding enrollment tokens: %w", err)
		}
		if err := q.CreateExecutorEnrollmentToken(ctx, database.CreateExecutorEnrollmentTokenParams{
			Selector:   selector,
			ExecutorID: executorID,
			SecretHash: digest[:],
			CreatedAt:  models.NewUTCTime(now),
			ExpiresAt:  models.NewUTCTime(now.Add(lifetime)),
		}); err != nil {
			return fmt.Errorf("store enrollment token: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return tokenPrefix + "_" + selector + "." + verifier, nil
}

// DropTokens deletes every unused token of executorID and leaves its binding
// alone. A caller that could not hand a freshly issued token over uses it, so
// a token nobody received does not stay usable.
func (s *Store) DropTokens(ctx context.Context, executorID string) (int64, error) {
	dropped, err := database.New(s.db).DeleteExecutorEnrollmentTokens(ctx, executorID)
	if err != nil {
		return 0, fmt.Errorf("drop outstanding enrollment tokens: %w", err)
	}
	return dropped, nil
}

// Revoke deletes the binding of executorID together with any token still
// outstanding for it, and reports both, since revoking a node that has not
// connected yet removes a token and no binding. Recovery is a new token.
func (s *Store) Revoke(ctx context.Context, executorID string) (Revoked, error) {
	var removed Revoked
	err := s.write(ctx, func(q *database.Queries) error {
		tokens, err := q.DeleteExecutorEnrollmentTokens(ctx, executorID)
		if err != nil {
			return fmt.Errorf("drop outstanding enrollment tokens: %w", err)
		}
		binding, err := q.DeleteExecutorEnrollment(ctx, executorID)
		if err != nil {
			return fmt.Errorf("delete executor enrollment: %w", err)
		}
		removed = Revoked{Binding: binding != 0, Tokens: tokens}
		return nil
	})
	return removed, err
}

// Admit decides whether the peer holding fingerprint may act as executorID. A
// presented token is consumed first, which is how a node bootstraps and how a
// rotation replaces the fingerprint; otherwise the recorded binding decides.
func (s *Store) Admit(ctx context.Context, executorID, fingerprint, token string) error {
	if executorID == "" || fingerprint == "" {
		return ErrNotEnrolled
	}
	// A node keeps presenting its token until an operator removes it from the
	// configuration, so a spent one is not a refusal: it simply buys nothing,
	// and the recorded binding decides as it does for a node presenting none.
	if token != "" {
		if err := s.enroll(ctx, executorID, fingerprint, token); !errors.Is(err, ErrUnusableToken) {
			return err
		}
	}
	return s.Bound(ctx, executorID, fingerprint)
}

// Bound reports whether fingerprint is still the credential enrolled for
// executorID. A session admitted earlier is re-checked with it, so a rotated
// or revoked node stops renewing its lease.
func (s *Store) Bound(ctx context.Context, executorID, fingerprint string) error {
	if executorID == "" || fingerprint == "" {
		return ErrNotEnrolled
	}
	enrolled, err := database.New(s.db).GetExecutorEnrollment(ctx, executorID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotEnrolled
	}
	if err != nil {
		return fmt.Errorf("read executor enrollment: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(enrolled), []byte(fingerprint)) != 1 {
		return ErrWrongNode
	}
	return nil
}

func (s *Store) enroll(ctx context.Context, executorID, fingerprint, token string) error {
	selector, verifier, ok := parse(token)
	if !ok {
		return ErrUnusableToken
	}
	return s.write(ctx, func(q *database.Queries) error {
		row, err := q.GetExecutorEnrollmentToken(ctx, selector)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnusableToken
		}
		if err != nil {
			return fmt.Errorf("read enrollment token: %w", err)
		}
		digest := sha256.Sum256([]byte(verifier))
		if subtle.ConstantTimeCompare(row.SecretHash, digest[:]) != 1 ||
			row.ExecutorID != executorID || !s.now().Before(row.ExpiresAt.Time) {
			return ErrUnusableToken
		}
		// The delete is the single-use claim: of two peers presenting one
		// token, exactly one removes the row and records a binding.
		claimed, err := q.ConsumeExecutorEnrollmentToken(ctx, selector)
		if err != nil {
			return fmt.Errorf("consume enrollment token: %w", err)
		}
		if claimed == 0 {
			return ErrUnusableToken
		}
		if err := q.SetExecutorEnrollment(ctx, database.SetExecutorEnrollmentParams{
			ExecutorID: executorID, Fingerprint: fingerprint, EnrolledAt: models.NewUTCTime(s.now()),
		}); err != nil {
			return fmt.Errorf("record executor enrollment: %w", err)
		}
		return nil
	})
}

// parse splits a printed token. It bounds the input before inspecting it, so
// an arbitrarily long value is rejected without work.
func parse(token string) (selector, verifier string, ok bool) {
	if len(token) > maxTokenLength || !strings.HasPrefix(token, tokenPrefix+"_") {
		return "", "", false
	}
	selector, verifier, found := strings.Cut(strings.TrimPrefix(token, tokenPrefix+"_"), ".")
	if !found || selector == "" || verifier == "" {
		return "", "", false
	}
	return selector, verifier, true
}

func secret(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("mint enrollment token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
