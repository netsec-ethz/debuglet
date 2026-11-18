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
	Kind                                       string
	Researcher                                 bool
	EligibleNodes                              int
	Ceiling, HostingBonus, Credited            int64
	NextReset                                  *time.Time
	DailyGrant, BalanceCap                     int64
	HostingSeconds, HostingRate, HostingEarned int64
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
	if cfg.ManagedCredits() {
		return p.applyManagedDailyIn(ctx, db, account, issuer, uid, researcher, now)
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

// applyManagedDailyIn adds each UTC day's grant to the existing balance. A
// missed day is recovered on the next maintenance pass or account request;
// the first decision starts today, with no historical credit before enrollment.
func (p *PaymentHandler) applyManagedDailyIn(ctx context.Context, db database.DBTX, account, issuer uuid.UUID, uid int64, researcher bool, now time.Time) (*AllowancePolicy, error) {
	cfg := p.cfg.Allowance
	today := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	reset := today.AddDate(0, 0, 1)
	period := "credits:" + today.Format(time.DateOnly)
	policy := &AllowancePolicy{Kind: "credits", Researcher: researcher, DailyGrant: cfg.DailyBase,
		BalanceCap: cfg.BalanceCap, Ceiling: cfg.BalanceCap, HostingRate: cfg.HostingHourlyRate, NextReset: &reset}
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(SUM(observed_seconds),0),COALESCE(SUM(credited),0) FROM allowance_hosting WHERE user_id=?`, uid).Scan(&policy.HostingSeconds, &policy.HostingEarned); err != nil {
		return nil, err
	}
	err := db.QueryRowContext(ctx, `SELECT granted FROM allowance_periods WHERE user_id=? AND period=?`, uid, period).Scan(&policy.Credited)
	if err == nil {
		return policy, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var last sql.NullString
	if err = db.QueryRowContext(ctx, `SELECT MAX(period) FROM allowance_periods WHERE user_id=? AND period LIKE 'credits:%'`, uid).Scan(&last); err != nil {
		return nil, err
	}
	days := int64(1)
	if last.Valid {
		previous, err := time.Parse("credits:"+time.DateOnly, last.String)
		if err != nil {
			return nil, fmt.Errorf("invalid managed credit period: %w", err)
		}
		days = max(int64(0), (today.Unix()-previous.Unix())/86400)
	}
	// Saturate at the balance cap before multiplication, even after a long gap.
	requested := cfg.BalanceCap
	if cfg.DailyBase == 0 || days <= cfg.BalanceCap/cfg.DailyBase {
		requested = days * cfg.DailyBase
	}
	policy.Credited, err = p.grantManagedCreditIn(ctx, db, account, issuer, requested,
		"daily Debuglet credits", "allowance-policy:"+period, now)
	if err != nil {
		return nil, err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO allowance_periods(user_id,period,researcher,eligible_nodes,ceiling,hosting_bonus,granted,decided_at) VALUES(?,?,?,0,?,0,?,?)`, uid, period, researcher, cfg.BalanceCap, policy.Credited, now.Unix())
	return policy, err
}

// grantManagedCreditIn shares a writer transaction with the caller's daily or
// hosting checkpoint. The caller records zero grants too, preventing later
// spending from reopening credit that was discarded at the cap.
func (p *PaymentHandler) grantManagedCreditIn(ctx context.Context, db database.DBTX, account, issuer uuid.UUID, requested int64, reason, key string, now time.Time) (int64, error) {
	if requested < 0 || !p.cfg.Allowance.ManagedCredits() {
		return 0, errors.New("invalid managed credit grant")
	}
	q := database.New(db)
	a, err := readAllowance(ctx, q, account)
	if err != nil {
		return 0, err
	}
	// Reservations remain part of the balance: releasing one cannot manufacture
	// room for another grant. Historical grants are never reduced when caps change.
	unconsumed := a.Granted - a.Consumed
	if unconsumed < 0 {
		return 0, &AllowanceRangeError{Account: account}
	}
	amount := min(requested, max(int64(0), p.cfg.Allowance.BalanceCap-unconsumed))
	if amount == 0 {
		return 0, nil
	}
	if _, err = q.InsertAllowanceGrant(ctx, database.InsertAllowanceGrantParams{
		UserUuid: account, GrantedBy: issuer, Amount: amount, Reason: reason,
		IdempotencyKey: key, GrantedAt: models.NewUTCTime(now),
	}); err != nil {
		return 0, err
	}
	if _, err = readAllowance(ctx, q, account); err != nil {
		return 0, err
	}
	return amount, nil
}
