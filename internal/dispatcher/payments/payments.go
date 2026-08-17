package payments

import (
	"context"
	"crypto/rand"
	"database/sql"
	"debuglet/internal/dispatcher/config"
	"debuglet/internal/dispatcher/database/ddb"
	"debuglet/internal/dispatcher/models"
	"debuglet/internal/dispatcher/payments/sui"
	"encoding/hex"
	"fmt"
	"time"

	"go.uber.org/zap"
)

type PaymentHandler struct {
	db     *sql.DB
	sui    *sui.SuiPaymentHandler
	logger *zap.Logger
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
	handler := &PaymentHandler{db: db, logger: logger}
	handler.sui = sui.NewSuiPaymentHandler(cfg, db, logger, handler)
	return handler
}

func (p *PaymentHandler) Start(ctx context.Context) error {
	return p.sui.Start(ctx)
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

func (p *PaymentHandler) GetTransaction(ctx context.Context, transactionID string) (ddb.Transaction, error) {
	queries := ddb.New(p.db)
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

	queries := ddb.New(p.db)
	if t, err := queries.CreateTransaction(ctx, ddb.CreateTransactionParams{
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
	queries := ddb.New(p.db)
	queries.UpdateTransactionStatus(ctx, ddb.UpdateTransactionStatusParams{
		Status: int64(models.Paid),
		ID:     transactionId,
	})
	orders, err := queries.GetTransactionOrders(ctx, transactionId)
	if err != nil {
		p.logger.Warn("failed to load orders of transaction")
		//TODO refund order
		return
	}
	for _, order := range orders {
		p.logger.Info("Crediting", zap.String("id", order.ExecutorID), zap.Int64("amount", order.Price), zap.String("currency", order.Currency))
		p.CreateEarningsIfNotExists(order.ExecutorID, order.Currency, queries, ctx)
		i, err := queries.AddEarnings(ctx, ddb.AddEarningsParams{
			Amount:     order.Price,
			ExecutorID: order.ExecutorID,
			Currency:   order.Currency,
		})
		if err != nil {
			p.logger.Error("Failed to credit executor", zap.String("error", err.Error()))
		} else {
			p.logger.Info("new balance: ", zap.Int64("total", i.TotalIncome), zap.Int64("current", i.CurrentBalance))
		}
	}
}

func (p *PaymentHandler) CreateEarningsIfNotExists(execID string, currency string, queries *ddb.Queries, ctx context.Context) {
	_, err := queries.GetEarningsIn(ctx, ddb.GetEarningsInParams{
		ExecutorID: execID,
		Currency:   currency,
	})
	if err == sql.ErrNoRows {
		queries.CreateEarnings(ctx, ddb.CreateEarningsParams{
			ExecutorID: execID,
			Currency:   currency,
		})
	}
}
