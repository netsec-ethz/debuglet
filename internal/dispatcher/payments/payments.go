// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"crypto/rand"
	"database/sql"
	"debuglet/internal/dispatcher/config"
	"debuglet/internal/dispatcher/database"
	"debuglet/internal/dispatcher/models"
	"debuglet/internal/dispatcher/payments/sui"
	"encoding/hex"
	"fmt"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type PaymentHandler struct {
	db     *sql.DB
	sui    *sui.SuiPaymentHandler
	logger *zap.Logger
	cfg    *config.DispatcherConfig
	pt     *PayoutTicker
}

type PaymentIntent struct {
	method string
	Intent any // method specific intent fields
}

type DummyIntent struct {
	TransactionId string
	AuthKey       string
}

func NewPaymentHandler(db *sql.DB, cfg *config.DispatcherConfig, logger *zap.Logger) *PaymentHandler {
	handler := &PaymentHandler{db: db, logger: logger, cfg: cfg}
	handler.sui = sui.NewSuiPaymentHandler(cfg, db, logger, handler)
	handler.pt = NewPayoutTicker(db, handler, logger)
	return handler
}

func (p *PaymentHandler) Start(ctx context.Context) error {
	g, subCtx := errgroup.WithContext(ctx)
	g.Go(func() error { return p.pt.StartPayoutLoop(subCtx) })
	g.Go(func() error { return p.sui.Start(subCtx) })
	return g.Wait()
}

func (p *PaymentHandler) CreatePaymentIntent(transactionId string, price int64, method string, hash string, ctx context.Context) (PaymentIntent, error) {
	switch method {
	case "USDC":
		fallthrough
	case "SUI":
		suiIntent, err := p.sui.CreatePaymentIntent(transactionId, price, method, hash, ctx)
		if err != nil {
			return PaymentIntent{}, fmt.Errorf("Failed to get Intent: %w", err)
		}
		return PaymentIntent{method: method, Intent: suiIntent}, nil
	case "TEST":
		err := p.CreateDummyIntent(transactionId, price, hash, ctx)
		return PaymentIntent{method: "TEST", Intent: DummyIntent{TransactionId: transactionId, AuthKey: ""}}, err
	default:
		return PaymentIntent{}, fmt.Errorf("Unsupported payment method: %s", method)
	}
}

func (p *PaymentHandler) IsPaid(ctx context.Context, transactionID string) (bool, error) {
	if t, err := p.GetTransaction(ctx, transactionID); err != nil {
		return false, err
	} else {
		return models.TransactionState(t.Status) == models.Paid, nil
	}
}

func (p *PaymentHandler) GetTransaction(ctx context.Context, transactionID string) (database.Transaction, error) {
	queries := database.New(p.db)
	return queries.GetTransactionByID(ctx, transactionID)
}

func (p *PaymentHandler) NewTransactionID() (string, error) {
	b_transactionId := make([]byte, 16)
	_, err := rand.Read(b_transactionId)
	if err != nil {
		return "", fmt.Errorf("Failed to create TransactionId")
	}
	return hex.EncodeToString(b_transactionId), nil
}

// This is for testing only. Creates a transaction and immediately sets it to paid
func (p *PaymentHandler) CreateDummyIntent(transactionId string, price int64, hash string, ctx context.Context) error {
	//TODO check if we can fetch a timestamp from chain to avoid drift
	expiresAt := time.Now().Add(time.Minute * 5)

	queries := database.New(p.db)
	if t, err := queries.CreateTransaction(ctx, database.CreateTransactionParams{
		ID:        transactionId,
		Method:    "TEST",
		ExpiresAt: models.NewUTCTime(expiresAt),
		Hash:      hash,
		Status:    int64(models.Paid),
	}); err != nil {
		return fmt.Errorf("failed to store transaction: %w", err)
	} else {
		p.logger.Info("created intent: ", zap.String("id", transactionId), zap.Int64("paid", t.Status))
		return nil
	}
}

func (p *PaymentHandler) CompleteTransaction(transactionId string, ctx context.Context) {
	p.logger.Info("settling transaction", zap.String("id", transactionId))
	queries := database.New(p.db)
	queries.UpdateTransactionStatus(ctx, database.UpdateTransactionStatusParams{
		Status: int64(models.Paid),
		ID:     transactionId,
	})
}

func (p *PaymentHandler) SetDebugletOrderComplete(debuglet *database.Debuglet, ctx context.Context) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	queries := database.New(p.db).WithTx(tx)
	p.logger.Debug("Update", zap.String("transactionId", debuglet.TransactionID), zap.Int64("orderId", debuglet.OrderID))
	order, err := queries.UpdateDebugletOrderState(ctx, database.UpdateDebugletOrderStateParams{
		State:         int64(models.Credited),
		TransactionID: debuglet.TransactionID,
		OrderID:       debuglet.OrderID,
	})
	if err != nil {
		return fmt.Errorf("Failed to update state of %s: %s", debuglet.Uuid.String(), err.Error())
	}
	p.CreateEarningsIfNotExists(debuglet.ExecutorID, order.Currency, "", queries, ctx)
	err = queries.AddEarnings(ctx, database.AddEarningsParams{
		Amount:     order.Price,
		ExecutorID: debuglet.ExecutorID,
		Currency:   order.Currency,
	})
	p.logger.Debug("Credited Executor", zap.String("ID", debuglet.ExecutorID), zap.String("currency", order.Currency), zap.Int64("amount", order.Price))
	return tx.Commit()
}

func (p *PaymentHandler) RefundDebugletOrder(debuglet *database.Debuglet, refundAddress string, ctx context.Context) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	queries := database.New(p.db).WithTx(tx)
	order, err := queries.GetDebugletOrder(ctx, database.GetDebugletOrderParams{
		TransactionID: debuglet.TransactionID,
		OrderID:       debuglet.OrderID,
	})
	if err != nil {
		return fmt.Errorf("Failed to find debuglet order")
	}
	if order.State == int64(models.Refunded) {
		return fmt.Errorf("Debuglet has already been refunded")
	}

	order, err = queries.UpdateDebugletOrderState(ctx, database.UpdateDebugletOrderStateParams{
		TransactionID: debuglet.TransactionID,
		OrderID:       debuglet.OrderID,
		State:         int64(models.Refunded),
	})

	if err != nil {
		return err
	}
	switch order.Currency {
	case "USDC":
		err = p.sui.RefundDebuglet(&order, refundAddress, ctx)
	default:
		err = fmt.Errorf("Refunds not supported for currency %s", order.Currency)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (p *PaymentHandler) RefundTransaction(transactionId string, ctx context.Context) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("Failed to begin transaction: %s", err.Error())
	}
	defer tx.Rollback()
	queries := database.New(p.db).WithTx(tx)
	transaction, err := queries.GetTransactionByID(ctx, transactionId)
	if err != nil {
		return err
	}
	if transaction.Status != int64(models.Paid) {
		return fmt.Errorf("Tried to refund transaction that has not been payed: %s", transactionId)
	}
	orders, err := queries.GetTransactionOrders(ctx, transactionId)
	if err != nil {
		return err
	}
	currency := orders[0].Currency
	refundAddress := orders[0].RefundAddress
	totalRefundValue := int64(0)
	for _, order := range orders {
		if order.Currency != currency || order.RefundAddress != refundAddress {
			// should never happen because these values are always set together but let's guard anyway
			return fmt.Errorf("Inconsistent orders in transaction %s", transactionId)
		}
		if order.State == int64(models.Refunded) {
			p.logger.Warn("Order has already been refunded", zap.String("transactionID", transactionId), zap.Int64("orderID", order.OrderID))
			continue
		}
		totalRefundValue += order.Price
		queries.UpdateDebugletOrderState(ctx, database.UpdateDebugletOrderStateParams{
			State:         int64(models.Refunded),
			TransactionID: transactionId,
			OrderID:       order.OrderID,
		})
	}

	switch currency {
	case "USDC":
		err = p.sui.TransferCoins(uint64(totalRefundValue), sui.GetCoinType("USDC", p.cfg.Sui.Network), refundAddress, ctx)
	default:
		err = fmt.Errorf("Refunds are not supported for currency %s", orders[0].Currency)
	}

	if err != nil {
		return fmt.Errorf("Failed to execute refund transaction: %s", err.Error())
	}

	return tx.Commit()
}

func (p *PaymentHandler) CreateEarningsIfNotExists(execID string, currency string, wallet string, queries *database.Queries, ctx context.Context) {
	_, err := queries.GetEarningsIn(ctx, database.GetEarningsInParams{
		ExecutorID: execID,
		Currency:   currency,
	})
	if err == sql.ErrNoRows {
		queries.CreateEarnings(ctx, database.CreateEarningsParams{
			ExecutorID:       execID,
			Currency:         currency,
			SuiWalletAddress: wallet,
		})
	}
}

func (p *PaymentHandler) TransferUSDC(amount uint64, receiver string, ctx context.Context) error {
	return p.sui.TransferCoins(amount, receiver, sui.GetCoinType("USDC", p.cfg.Sui.Network), ctx)
}

func (p *PaymentHandler) PayoutExecutor(earning database.Earning, ctx context.Context) error {
	switch earning.Currency {
	case "USDC":
		return p.sui.TransferCoins(uint64(earning.CurrentBalance), sui.GetCoinType("USDC", p.cfg.Sui.Network), earning.SuiWalletAddress, ctx)
	default:
		return fmt.Errorf("Unknown/unallowed currency %s", earning.Currency)
	}
}
