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
)

// AllowancePolicy is the decision already applied for this UTC day (or the
// account's one public trial). Eligibility changes apply at the next reset.
type AllowancePolicy struct {
	Kind                            string
	Researcher                      bool
	EligibleNodes                   int
	Ceiling, HostingBonus, Credited int64
	NextReset                       *time.Time
}

// AllowanceWithPolicy applies an opt-in refill and reads its balance in the
// same transaction. Automatic issuance reuses immutable TEST ledger grants.
func (p *PaymentHandler) AllowanceWithPolicy(ctx context.Context, account uuid.UUID) (Allowance, *AllowancePolicy, error) {
	if !p.cfg.Allowance.Automatic() {
		a, err := readAllowance(ctx, database.New(p.db), account)
		return a, nil, err
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return Allowance{}, nil, err
	}
	defer tx.Rollback()
	policy, err := p.applyAllowancePolicyIn(ctx, tx, account, time.Now())
	if err != nil {
		return Allowance{}, nil, err
	}
	a, err := readAllowance(ctx, database.New(tx), account)
	if err != nil {
		return Allowance{}, nil, err
	}
	if err = tx.Commit(); err != nil {
		return Allowance{}, nil, err
	}
	return a, policy, nil
}

// applyAllowancePolicyIn must share the caller's transaction with admission.
// A write before reading acquires SQLite's writer lock, preventing concurrent
// connections from deciding a refill from the same stale balance.
func (p *PaymentHandler) applyAllowancePolicyIn(ctx context.Context, db database.DBTX, account uuid.UUID, now time.Time) (*AllowancePolicy, error) {
	cfg := p.cfg.Allowance
	if !cfg.Automatic() {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `UPDATE allowance_eligibility SET updated_at=updated_at WHERE user_id=(SELECT id FROM users WHERE uuid=?)`, account); err != nil {
		return nil, err
	}
	issuer, err := uuid.Parse(cfg.PolicyIssuer)
	if err != nil {
		return nil, err
	}
	user, err := database.New(db).GetUserByUUID(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("allowance policy issuer: %w", err)
	}
	if user.Role != "operator" {
		return nil, errors.New("allowance policy issuer is not an operator")
	}
	var uid int64
	var researcher bool
	err = db.QueryRowContext(ctx, `SELECT u.id,COALESCE(e.researcher,0) FROM users u LEFT JOIN allowance_eligibility e ON e.user_id=u.id WHERE u.uuid=?`, account).Scan(&uid, &researcher)
	if err != nil {
		return nil, err
	}
	period := "trial"
	policy := &AllowancePolicy{Kind: "trial", Ceiling: cfg.PublicTrial, Researcher: researcher}
	if researcher {
		period = now.UTC().Format("2006-01-02")
		policy.Kind = "daily"
		reset := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day()+1, 0, 0, 0, 0, time.UTC)
		policy.NextReset = &reset
	}
	// Once a decision exists, neither spending nor a policy edit can issue again.
	err = db.QueryRowContext(ctx, `SELECT researcher,eligible_nodes,ceiling,hosting_bonus,granted FROM allowance_periods WHERE user_id=? AND period=?`, uid, period).Scan(&policy.Researcher, &policy.EligibleNodes, &policy.Ceiling, &policy.HostingBonus, &policy.Credited)
	if err == nil {
		return policy, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if researcher {
		ids, err := EligibleHostingExecutors(ctx, db, account, now)
		if err != nil {
			return nil, err
		}
		policy.EligibleNodes = min(len(ids), cfg.DailyNodeCap)
		policy.HostingBonus = int64(policy.EligibleNodes) * cfg.DailyPerNode
		policy.Ceiling = cfg.DailyBase + policy.HostingBonus
	}
	a, err := readAllowance(ctx, database.New(db), account)
	if err != nil {
		return nil, err
	}
	// Outstanding reservations remain unconsumed credit. Refilling only available
	// credit would double-issue when those reservations expire or are released.
	unconsumed := a.Granted - a.Consumed
	if unconsumed < 0 {
		return nil, &AllowanceRangeError{Account: account}
	}
	policy.Credited = max(int64(0), policy.Ceiling-unconsumed)
	if policy.Credited > 0 {
		_, err = database.New(db).InsertAllowanceGrant(ctx, database.InsertAllowanceGrantParams{
			UserUuid: account, GrantedBy: issuer, Amount: policy.Credited, Reason: "automatic " + policy.Kind + " allowance",
			IdempotencyKey: "allowance-policy:" + period, GrantedAt: models.NewUTCTime(now),
		})
		if err != nil {
			return nil, err
		}
		if _, err = readAllowance(ctx, database.New(db), account); err != nil {
			return nil, err
		}
	}
	_, err = db.ExecContext(ctx, `INSERT INTO allowance_periods(user_id,period,researcher,eligible_nodes,ceiling,hosting_bonus,granted,decided_at) VALUES(?,?,?,?,?,?,?,?)`, uid, period, researcher, policy.EligibleNodes, policy.Ceiling, policy.HostingBonus, policy.Credited, now.Unix())
	return policy, err
}
