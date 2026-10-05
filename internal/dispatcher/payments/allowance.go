// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"go.uber.org/zap"
)

// AllowanceCurrency is the currency allowances are granted and counted in.
// Allowances are usage credits in TEST units, not money.
const AllowanceCurrency = "TEST"

var (
	// ErrUnknownAccount is a grant for an account that does not exist.
	ErrUnknownAccount = errors.New("unknown account")
	// ErrGrantConflict is a grant whose idempotency key already names a
	// different grant of the same account.
	ErrGrantConflict = errors.New("the idempotency key names a different grant")
)

// Allowance is an account's usage allowance in TEST units. Granted is the sum
// of its grants. Consumed is the price of its orders that have a settlement,
// credited or refunded alike: a run with a known outcome used its allowance
// whatever its exit code. Reserved is the price of the other orders of its
// paid intents, admitted with an outcome not yet known or not yet admitted.
type Allowance struct {
	Granted, Reserved, Consumed int64
}

// Remaining is what the account may still reserve. It is negative when the
// account used more before its grants than it was granted since.
func (a Allowance) Remaining() int64 {
	return a.Granted - a.Consumed - a.Reserved
}

// AllowanceExceededError refuses an intent whose price the account's
// remaining allowance does not cover.
type AllowanceExceededError struct {
	Remaining, Required int64
}

func (e *AllowanceExceededError) Error() string {
	return fmt.Sprintf("the allowance has %d %s units remaining, the intent requires %d", e.Remaining, AllowanceCurrency, e.Required)
}

// AllowanceGrant is one grant as recorded.
type AllowanceGrant struct {
	ID             int64
	Amount         int64
	Currency       string
	Reason         string
	IdempotencyKey string
	GrantedBy      uuid.UUID
	GrantedAt      time.Time
}

// AllowancesEnabled reports whether TEST intents of accounts are capped by
// their allowance. It is decided by configuration only.
func (p *PaymentHandler) AllowancesEnabled() bool {
	return p.cfg.Allowance.Enabled
}

// DefaultAllowanceGrant is the amount of a grant whose request names none.
func (p *PaymentHandler) DefaultAllowanceGrant() int64 {
	return p.cfg.Allowance.Grant()
}

// Allowance reads an account's allowance. An unknown account is
// sql.ErrNoRows.
func (p *PaymentHandler) Allowance(ctx context.Context, account uuid.UUID) (Allowance, error) {
	return readAllowance(ctx, database.New(p.db), account)
}

func readAllowance(ctx context.Context, q *database.Queries, account uuid.UUID) (Allowance, error) {
	row, err := q.GetAllowance(ctx, database.GetAllowanceParams{PaidStatus: int64(models.Paid), UserUuid: account})
	if err != nil {
		return Allowance{}, err
	}
	return Allowance{Granted: row.Granted, Reserved: row.Reserved, Consumed: row.Consumed}, nil
}

// CreateAllowanceIntentIn creates the paid TEST transaction of an account's
// intent through db only if the account's remaining allowance covers price,
// and otherwise returns an *AllowanceExceededError and writes no transaction.
// First, the account's paid TEST intents past their expiry that admitted no
// run are released to Expired, so their reservation returns to the allowance
// and they can no longer be submitted; that release is written through db
// whether or not the intent is then refused.
func (p *PaymentHandler) CreateAllowanceIntentIn(db database.DBTX, account uuid.UUID, transactionId string, price int64, hash string, ctx context.Context) (PaymentIntent, error) {
	queries := database.New(db)
	now := time.Now()
	released, err := queries.ReleaseExpiredAllowanceIntents(ctx, database.ReleaseExpiredAllowanceIntentsParams{
		ExpiredStatus: int64(models.Expired), PaidStatus: int64(models.Paid),
		Now: models.NewUTCTime(now), UserUuid: account,
	})
	if err != nil {
		return PaymentIntent{}, fmt.Errorf("release expired intents: %w", err)
	}
	if released > 0 {
		p.logger.Info("released expired unadmitted intents", zap.Int64("intents", released))
	}
	created, err := queries.ReserveAllowanceIntent(ctx, database.ReserveAllowanceIntentParams{
		ID: transactionId, Price: price, ExpiresAt: models.NewUTCTime(now.Add(testIntentLifetime)),
		PaidStatus: int64(models.Paid), Hash: hash, UserUuid: account,
	})
	if err != nil {
		return PaymentIntent{}, fmt.Errorf("failed to store transaction: %w", err)
	}
	if created == 0 {
		allowance, err := readAllowance(ctx, queries, account)
		if err != nil {
			return PaymentIntent{}, fmt.Errorf("read the allowance: %w", err)
		}
		return PaymentIntent{}, &AllowanceExceededError{Remaining: allowance.Remaining(), Required: price}
	}
	return PaymentIntent{method: "TEST", Intent: DummyIntent{TransactionId: transactionId}}, nil
}

// AllowanceGrantResult is a grant together with the account's allowance
// after it. Created is false when the idempotency key named the grant already.
type AllowanceGrantResult struct {
	Grant     AllowanceGrant
	Allowance Allowance
	Created   bool
}

// GrantAllowance records a grant of amount TEST units to account by operator.
// The idempotency key makes a repeated request issue the grant once: the same
// key with the same amount and reason returns the recorded grant, with any
// other body ErrGrantConflict. An unknown account is ErrUnknownAccount.
func (p *PaymentHandler) GrantAllowance(ctx context.Context, account, operator uuid.UUID, amount int64, reason, key string) (AllowanceGrantResult, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return AllowanceGrantResult{}, err
	}
	defer tx.Rollback()
	queries := database.New(tx)
	lookup := database.GetAllowanceGrantParams{UserUuid: account, IdempotencyKey: key}
	row, err := queries.GetAllowanceGrant(ctx, lookup)
	created := false
	switch {
	case err == nil:
		if row.Amount != amount || row.Reason != reason {
			return AllowanceGrantResult{}, ErrGrantConflict
		}
	case errors.Is(err, sql.ErrNoRows):
		inserted, err := queries.InsertAllowanceGrant(ctx, database.InsertAllowanceGrantParams{
			Amount: amount, Reason: reason, IdempotencyKey: key,
			GrantedAt: models.NewUTCTime(time.Now()), GrantedBy: operator, UserUuid: account,
		})
		if err != nil {
			return AllowanceGrantResult{}, err
		}
		if inserted == 0 {
			return AllowanceGrantResult{}, ErrUnknownAccount
		}
		if row, err = queries.GetAllowanceGrant(ctx, lookup); err != nil {
			return AllowanceGrantResult{}, err
		}
		created = true
	default:
		return AllowanceGrantResult{}, err
	}
	allowance, err := readAllowance(ctx, queries, account)
	if err != nil {
		return AllowanceGrantResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return AllowanceGrantResult{}, err
	}
	if created {
		p.logger.Info("allowance granted", zap.Int64("grant", row.ID), zap.Int64("amount", row.Amount))
	}
	return AllowanceGrantResult{
		Grant: AllowanceGrant{
			ID: row.ID, Amount: row.Amount, Currency: row.Currency, Reason: row.Reason,
			IdempotencyKey: row.IdempotencyKey, GrantedBy: row.GrantedBy, GrantedAt: row.GrantedAt.Time,
		},
		Allowance: allowance,
		Created:   created,
	}, nil
}
