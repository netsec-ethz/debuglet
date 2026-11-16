// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
)

var ErrTopUpConflict = errors.New("top-up idempotency key was already used with different details")

// PersonalBalance is derived from confirmed deposits and order decisions.
// Refunded orders no longer consume credit; no second mutable balance exists.
func (p *PaymentHandler) PersonalBalance(ctx context.Context, db database.DBTX, owner uuid.UUID, currency string) (CommunityBudget, error) {
	if currency != "SUI" {
		return CommunityBudget{}, ErrUnsupportedPaymentMethod
	}
	if err := p.requireChain(currency, "read prepaid wallet"); err != nil {
		return CommunityBudget{}, err
	}
	var b CommunityBudget
	err := db.QueryRowContext(ctx, `SELECT
 COALESCE((SELECT SUM(t.price) FROM prepaid_topups d JOIN transactions t ON t.id=d.transaction_id WHERE d.user_id=u.id AND d.purpose='personal' AND d.network=? AND d.coin_type=? AND t.status=?),0),
 COALESCE((SELECT SUM(o.price) FROM personal_funding f JOIN transactions t ON t.id=f.transaction_id JOIN debuglet_order o ON o.transaction_id=t.id WHERE f.user_id=u.id AND f.network=? AND f.currency=? AND t.status=? AND o.state=?),0),
 COALESCE((SELECT SUM(o.price) FROM personal_funding f JOIN debuglet_order o ON o.transaction_id=f.transaction_id WHERE f.user_id=u.id AND f.network=? AND f.currency=? AND o.state=?),0)
 FROM users u WHERE u.uuid=?`, p.cfg.Sui.Network, sui.GetCoinType(currency, p.cfg.Sui.Network), models.Paid,
		p.cfg.Sui.Network, currency, models.Paid, models.Outstanding, p.cfg.Sui.Network, currency, models.Credited, owner).Scan(&b.Funded, &b.Reserved, &b.Spent)
	if err != nil {
		return b, err
	}
	if b.Funded < 0 || b.Reserved < 0 || b.Spent < 0 || b.Reserved > math.MaxInt64-b.Spent {
		return b, errors.New("prepaid history exceeds supported range")
	}
	b.Available = b.Funded - b.Reserved - b.Spent
	if b.Available < 0 {
		return b, errors.New("prepaid history has more obligations than funding")
	}
	return b, nil
}

// CreatePrepaidTopUpIn is atomic with its caller's transaction. Repeating the
// same key returns the original signed intent, including its original expiry.
func (p *PaymentHandler) CreatePrepaidTopUpIn(ctx context.Context, db database.DBTX, owner uuid.UUID, id, key, purpose string, amount int64, refund string) (PaymentIntent, error) {
	if err := p.requireChain("SUI", "fund prepaid credit"); err != nil {
		return PaymentIntent{}, err
	}
	if (purpose != "personal" && purpose != "hosting") || len(key) < 1 || len(key) > 128 || amount <= 0 || amount > 1<<53-1 {
		return PaymentIntent{}, errors.New("invalid top-up purpose, key or amount")
	}
	if err := sui.ValidAddress(refund); err != nil {
		return PaymentIntent{}, err
	}
	if _, err := db.ExecContext(ctx, `UPDATE users SET name=name WHERE uuid=?`, owner); err != nil {
		return PaymentIntent{}, err
	}
	var saved, savedRefund, network string
	var savedAmount int64
	err := db.QueryRowContext(ctx, `SELECT d.intent_json,d.refund_address,d.network,t.price FROM prepaid_topups d JOIN users u ON u.id=d.user_id JOIN transactions t ON t.id=d.transaction_id WHERE u.uuid=? AND d.purpose=? AND d.idempotency_key=?`, owner, purpose, key).Scan(&saved, &savedRefund, &network, &savedAmount)
	if err == nil {
		if savedAmount != amount || savedRefund != refund || network != p.cfg.Sui.Network {
			return PaymentIntent{}, ErrTopUpConflict
		}
		var intent sui.SuiPaymentIntent
		if err := json.Unmarshal([]byte(saved), &intent); err != nil {
			return PaymentIntent{}, err
		}
		return PaymentIntent{method: "SUI", Intent: intent}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return PaymentIntent{}, err
	}
	intent, err := p.CreatePaymentIntentIn(db, id, amount, "SUI", "prepaid-deposit:"+purpose, ctx)
	if err != nil {
		return PaymentIntent{}, err
	}
	encoded, err := json.Marshal(intent.Intent)
	if err != nil {
		return PaymentIntent{}, err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO prepaid_topups(transaction_id,user_id,purpose,idempotency_key,refund_address,network,coin_type,intent_json) SELECT ?,id,?,?,?,?,?,? FROM users WHERE uuid=?`, id, purpose, key, refund, p.cfg.Sui.Network, sui.GetCoinType("SUI", p.cfg.Sui.Network), string(encoded), owner)
	if err != nil {
		return PaymentIntent{}, err
	}
	err = database.New(db).SetTransactionOwner(ctx, database.SetTransactionOwnerParams{TransactionID: id, Uuid: owner})
	return intent, err
}

func (p *PaymentHandler) CreatePersonalIntentIn(db database.DBTX, owner uuid.UUID, id string, price int64, currency, hash string, ctx context.Context) (PaymentIntent, error) {
	if price < 0 || currency != "SUI" {
		return PaymentIntent{}, ErrUnsupportedPaymentMethod
	}
	if _, err := db.ExecContext(ctx, `UPDATE users SET name=name WHERE uuid=?`, owner); err != nil {
		return PaymentIntent{}, err
	}
	// Unused expired reservations are released, but admitted uncertain work is retained.
	if _, err := db.ExecContext(ctx, `UPDATE transactions SET status=? WHERE status=? AND expires_at<? AND id IN(SELECT f.transaction_id FROM personal_funding f JOIN users u ON u.id=f.user_id WHERE u.uuid=?) AND NOT EXISTS(SELECT 1 FROM debuglet_order o WHERE o.transaction_id=transactions.id AND o.debuglet_id IS NOT NULL)`, models.Expired, models.Paid, models.NewUTCTime(time.Now()), owner); err != nil {
		return PaymentIntent{}, err
	}
	b, err := p.PersonalBalance(ctx, db, owner, currency)
	if err != nil {
		return PaymentIntent{}, err
	}
	if b.Available < price {
		return PaymentIntent{}, &CommunityFundsError{b.Available, price}
	}
	_, err = database.New(db).CreateTransaction(ctx, database.CreateTransactionParams{ID: id, Price: price, Currency: currency, Method: "CREDITS", ExpiresAt: models.NewUTCTime(time.Now().Add(testIntentLifetime)), Hash: hash, Status: int64(models.Paid)})
	if err != nil {
		return PaymentIntent{}, err
	}
	result, err := db.ExecContext(ctx, `INSERT INTO personal_funding(transaction_id,user_id,currency,network) SELECT ?,id,?,? FROM users WHERE uuid=?`, id, currency, p.cfg.Sui.Network, owner)
	if err != nil {
		return PaymentIntent{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return PaymentIntent{}, err
	}
	if n != 1 {
		return PaymentIntent{}, fmt.Errorf("prepaid owner not found")
	}
	return PaymentIntent{method: "CREDITS", Intent: DummyIntent{TransactionId: id}}, nil
}
