package payments

import (
	"context"
	"crypto/rand"
	"database/sql"
	"debuglet/internal/dispatcher/config"
	"debuglet/internal/dispatcher/database/ddb"
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
	Intent any //method specific intent fields
}

type DummyIntent struct {
	TransactionId string
	AuthKey       string
}

func NewPaymentHandler(db *sql.DB, cfg *config.DispatcherConfig, logger *zap.Logger) *PaymentHandler {
	return &PaymentHandler{
		db:     db,
		sui:    sui.NewSuiPaymentHandler(cfg, db, logger),
		logger: logger,
	}
}

func (p *PaymentHandler) Start() error {
	return p.sui.Start()
}

func (p *PaymentHandler) CreatePaymentIntent(ctx context.Context, price int64, method string, hash string) (PaymentIntent, error) {
	switch method {
	case "SUI":
		suiIntent, err := p.sui.CreatePaymentIntent(ctx, price, hash)
		if err != nil {
			return PaymentIntent{}, fmt.Errorf("Failed to get Intent: %w", err)
		}
		return PaymentIntent{method: method, Intent: suiIntent}, nil
	case "TEST":
		transactionId, err := p.CreateDummyIntent(ctx, hash)
		return PaymentIntent{method: "TEST", Intent: DummyIntent{TransactionId: transactionId, AuthKey: ""}}, err
	default:
		return PaymentIntent{}, fmt.Errorf("Unsupported payment method: %s", method)
	}
}

func (p *PaymentHandler) IsPaid(ctx context.Context, transactionID string) (bool, error) {
	if t, err := p.GetTransaction(ctx, transactionID); err != nil {
		return false, err
	} else {
		return t.Paid, nil
	}
}

func (p *PaymentHandler) GetTransaction(ctx context.Context, transactionID string) (ddb.Transaction, error) {
	queries := ddb.New(p.db)
	return queries.GetTransactionByID(ctx, transactionID)
}

// This is for testing only. Creates a transaction and immediately sets it to paid
func (p *PaymentHandler) CreateDummyIntent(ctx context.Context, hash string) (string, error) {
	b_transactionId := make([]byte, 16)
	_, err := rand.Read(b_transactionId)
	if err != nil {
		return "", fmt.Errorf("Failed to create Intent")
	}
	expiresAt := time.Now().Add(time.Minute * 5)
	transactionId := hex.EncodeToString(b_transactionId)

	queries := ddb.New(p.db)
	if t, err := queries.CreateTransaction(ctx, ddb.CreateTransactionParams{
		ID:        transactionId,
		Method:    "TEST",
		ExpiresAt: expiresAt,
		Hash:      hash,
		Paid:      true,
	}); err != nil {
		return "", fmt.Errorf("failed to store transaction: %w", err)
	} else {
		p.logger.Info("created intent: ", zap.String("id", transactionId), zap.Bool("paid", t.Paid))
		return transactionId, err
	}

}
