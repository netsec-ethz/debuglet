// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
)

var (
	ErrCommunityNotFound          = errors.New("community or project not found")
	ErrCommunityOwner             = errors.New("only the community owner may add funds")
	ErrCommunityAllowanceDisabled = errors.New("community TEST spending requires the creator's configured usage allowance")
	ErrCommunityDeposit           = errors.New("a community deposit cannot be submitted as a measurement")
	ErrCommunityNetwork           = errors.New("community funds belong to a different Sui network")
)

type CommunityFundsError struct{ Available, Required int64 }

func (e *CommunityFundsError) Error() string {
	return fmt.Sprintf("community has %d units available; this measurement requires %d", e.Available, e.Required)
}

// CommunityBudget derives funds from receipts and existing order decisions;
// there is no second balance that can drift away from the payment records.
type CommunityBudget struct{ Funded, Reserved, Spent, Available int64 }

func (p *PaymentHandler) CommunityCurrency() (string, string) {
	if p.chainDisabled() {
		return "TEST", ""
	}
	return "USDC", p.cfg.Sui.Network
}

// CommunityBalance includes only the configured chain and asset. TEST reports
// the creator's allowance, including their individual and sponsored spending.
func (p *PaymentHandler) CommunityBalance(ctx context.Context, db database.DBTX, communityID, currency string) (CommunityBudget, error) {
	if currency == "TEST" {
		var owner uuid.UUID
		err := db.QueryRowContext(ctx, `SELECT u.uuid FROM communities c JOIN users u ON u.id=c.created_by WHERE c.id=?`, communityID).Scan(&owner)
		if errors.Is(err, sql.ErrNoRows) {
			return CommunityBudget{}, ErrCommunityNotFound
		}
		if err != nil {
			return CommunityBudget{}, err
		}
		if !p.AllowancesEnabled() {
			return CommunityBudget{}, ErrCommunityAllowanceDisabled
		}
		a, err := readAllowance(ctx, database.New(db), owner)
		return CommunityBudget{a.Granted, a.Reserved, a.Consumed, a.Remaining()}, err
	}
	if currency != "USDC" {
		return CommunityBudget{}, ErrUnsupportedPaymentMethod
	}
	var b CommunityBudget
	err := db.QueryRowContext(ctx, `SELECT
		COALESCE((SELECT SUM(t.price) FROM community_topups d JOIN transactions t ON t.id=d.transaction_id
			WHERE d.community_id=c.id AND d.network=? AND d.coin_type=? AND t.status=?),0),
		COALESCE((SELECT SUM(o.price) FROM community_funding f JOIN transactions t ON t.id=f.transaction_id
			JOIN debuglet_order o ON o.transaction_id=t.id
			WHERE f.community_id=c.id AND f.currency='USDC' AND f.network=? AND t.status=? AND o.state=?),0),
		COALESCE((SELECT SUM(o.price) FROM community_funding f JOIN debuglet_order o ON o.transaction_id=f.transaction_id
			WHERE f.community_id=c.id AND f.currency='USDC' AND f.network=? AND o.state=?),0)
		FROM communities c WHERE c.id=?`,
		p.cfg.Sui.Network, sui.GetCoinType("USDC", p.cfg.Sui.Network), models.Paid,
		p.cfg.Sui.Network, models.Paid, models.Outstanding,
		p.cfg.Sui.Network, models.Credited, communityID).Scan(&b.Funded, &b.Reserved, &b.Spent)
	if errors.Is(err, sql.ErrNoRows) {
		return b, ErrCommunityNotFound
	}
	if err != nil {
		return b, err
	}
	if b.Funded < 0 || b.Reserved < 0 || b.Spent < 0 || b.Reserved > math.MaxInt64-b.Spent {
		return b, errors.New("community payment history exceeds the supported range")
	}
	b.Available = b.Funded - b.Reserved - b.Spent
	return b, nil
}

// CreateCommunityTopUpIn creates the ordinary owner-signed USDC intent and
// classifies it as a deposit in the same caller-owned SQL transaction.
func (p *PaymentHandler) CreateCommunityTopUpIn(db database.DBTX, actor uuid.UUID, communityID, transactionID string, amount int64, refundAddress string, ctx context.Context) (PaymentIntent, error) {
	if err := p.requireChain("USDC", "fund community"); err != nil {
		return PaymentIntent{}, err
	}
	if amount <= 0 || amount > 1<<53-1 {
		return PaymentIntent{}, errors.New("top-up must be between 1 and 9007199254740991 micro-USDC")
	}
	if err := sui.ValidAddress(refundAddress); err != nil {
		return PaymentIntent{}, err
	}
	var ownerID int64
	var owner uuid.UUID
	err := db.QueryRowContext(ctx, `SELECT c.created_by,u.uuid FROM communities c JOIN users u ON u.id=c.created_by
		WHERE c.id=? AND EXISTS(SELECT 1 FROM community_members m JOIN users a ON a.id=m.user_id WHERE m.community_id=c.id AND a.uuid=?)`,
		communityID, actor).Scan(&ownerID, &owner)
	if errors.Is(err, sql.ErrNoRows) {
		return PaymentIntent{}, ErrCommunityNotFound
	}
	if err != nil {
		return PaymentIntent{}, err
	}
	if actor != owner {
		return PaymentIntent{}, ErrCommunityOwner
	}
	intent, err := p.CreatePaymentIntentIn(db, transactionID, amount, "USDC", "community-deposit:"+communityID, ctx)
	if err != nil {
		return PaymentIntent{}, err
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO community_topups(transaction_id,community_id,created_by,refund_address,network,coin_type) VALUES(?,?,?,?,?,?)`,
		transactionID, communityID, ownerID, refundAddress, p.cfg.Sui.Network, sui.GetCoinType("USDC", p.cfg.Sui.Network)); err != nil {
		return PaymentIntent{}, err
	}
	if err := database.New(db).SetTransactionOwner(ctx, database.SetTransactionOwnerParams{TransactionID: transactionID, Uuid: actor}); err != nil {
		return PaymentIntent{}, err
	}
	return intent, nil
}

// CreateCommunityIntentIn reserves the whole quoted batch before its caller
// writes the order rows. The caller must hold one SQL transaction for all of
// these writes. The first UPDATE acquires SQLite's write lock before the
// balance and current membership are read.
func (p *PaymentHandler) CreateCommunityIntentIn(db database.DBTX, actor uuid.UUID, projectID, transactionID string, price int64, currency, hash string, ctx context.Context) (PaymentIntent, error) {
	if price < 0 {
		return PaymentIntent{}, errors.New("community price must not be negative")
	}
	if err := p.CheckPaymentMethod(currency); err != nil {
		return PaymentIntent{}, err
	}
	if currency != "TEST" && currency != "USDC" {
		return PaymentIntent{}, ErrUnsupportedPaymentMethod
	}
	if _, err := db.ExecContext(ctx, `UPDATE communities SET name=name WHERE id=(SELECT community_id FROM community_projects WHERE id=?)`, projectID); err != nil {
		return PaymentIntent{}, err
	}
	var communityID string
	var ownerID, actorID int64
	var owner uuid.UUID
	err := db.QueryRowContext(ctx, `SELECT c.id,c.created_by,a.id,o.uuid FROM community_projects p
		JOIN communities c ON c.id=p.community_id JOIN users o ON o.id=c.created_by
		JOIN community_members m ON m.community_id=c.id JOIN users a ON a.id=m.user_id
		WHERE p.id=? AND a.uuid=?`, projectID, actor).Scan(&communityID, &ownerID, &actorID, &owner)
	if errors.Is(err, sql.ErrNoRows) {
		return PaymentIntent{}, ErrCommunityNotFound
	}
	if err != nil {
		return PaymentIntent{}, err
	}
	if _, err := db.ExecContext(ctx, `UPDATE transactions SET status=?
		WHERE status=? AND expires_at<? AND id IN(SELECT transaction_id FROM community_funding WHERE community_id=? AND currency=?)
		AND NOT EXISTS(SELECT 1 FROM debuglet_order o WHERE o.transaction_id=transactions.id AND o.debuglet_id IS NOT NULL)`,
		models.Expired, models.Paid, models.NewUTCTime(time.Now()), communityID, currency); err != nil {
		return PaymentIntent{}, err
	}
	var intent PaymentIntent
	if currency == "TEST" {
		if !p.AllowancesEnabled() {
			return PaymentIntent{}, ErrCommunityAllowanceDisabled
		}
		intent, err = p.CreateAllowanceIntentIn(db, owner, transactionID, price, hash, ctx)
	} else {
		var budget CommunityBudget
		budget, err = p.CommunityBalance(ctx, db, communityID, currency)
		if err == nil && budget.Available < price {
			return PaymentIntent{}, &CommunityFundsError{budget.Available, price}
		}
		if err == nil {
			_, err = database.New(db).CreateTransaction(ctx, database.CreateTransactionParams{
				ID: transactionID, Price: price, Currency: "USDC", Method: "COMMUNITY",
				ExpiresAt: models.NewUTCTime(time.Now().Add(testIntentLifetime)), Hash: hash, Status: int64(models.Paid),
			})
			intent = PaymentIntent{method: "COMMUNITY", Intent: DummyIntent{TransactionId: transactionID}}
		}
	}
	if err != nil {
		return PaymentIntent{}, err
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO community_funding(transaction_id,community_id,project_id,sponsor_user_id,actor_user_id,currency,network) VALUES(?,?,?,?,?,?,?)`,
		transactionID, communityID, projectID, ownerID, actorID, currency, p.cfg.Sui.Network); err != nil {
		return PaymentIntent{}, err
	}
	return intent, nil
}

// CheckCommunitySubmission refuses deposit intents and rechecks membership for
// sponsored work. It does not grant access to another actor's payment intent.
func (p *PaymentHandler) CheckCommunitySubmission(ctx context.Context, db database.DBTX, transactionID string, actor uuid.UUID) error {
	var deposit bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM community_topups WHERE transaction_id=?)`, transactionID).Scan(&deposit); err != nil {
		return err
	}
	if deposit {
		return ErrCommunityDeposit
	}
	var member bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM community_members m JOIN users u ON u.id=m.user_id
		WHERE m.community_id=f.community_id AND u.uuid=? AND m.user_id=f.actor_user_id)
		FROM community_funding f WHERE f.transaction_id=?`, actor, transactionID).Scan(&member)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !member {
		return ErrCommunityNotFound
	}
	return p.checkCommunityCurrency(ctx, db, transactionID)
}

func (p *PaymentHandler) checkCommunityCurrency(ctx context.Context, db database.DBTX, transactionID string) error {
	var currency, network string
	err := db.QueryRowContext(ctx, `SELECT currency,network FROM community_funding WHERE transaction_id=?`, transactionID).Scan(&currency, &network)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if currency == "USDC" && network != p.cfg.Sui.Network {
		return ErrCommunityNetwork
	}
	return nil
}

func communityFunded(ctx context.Context, db database.DBTX, transactionID string) (bool, error) {
	var funded bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM community_funding WHERE transaction_id=?)`, transactionID).Scan(&funded)
	return funded, err
}

// refundCommunityIn makes the existing order settlement the budget credit.
// It never sends a second on-chain payment to the member who submitted a run.
func refundCommunityIn(ctx context.Context, q *database.Queries, orders []database.DebugletOrder) error {
	for _, order := range orders {
		if _, err := recordSettlement(ctx, q, order, order.ExecutorID, settlementRefund); err != nil {
			return err
		}
	}
	return nil
}
