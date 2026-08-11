package sui

import (
	"context"
	"crypto/rand"
	"database/sql"
	"debuglet/internal/dispatcher/config"
	"debuglet/internal/dispatcher/database/ddb"
	"encoding/hex"
	"fmt"
	"time"

	"go.uber.org/zap"
)

type SuiPaymentHandler struct {
	lis *Listener
	db  *sql.DB
}

type SuiPaymentIntent struct {
	TransactionId   string
	Price           int64
	AuthKey         string
	ExpiresAt       time.Time
	RegistryAddress string
	ReceiverAddress string
}

func NewSuiPaymentHandler(cfg *config.DispatcherConfig, db *sql.DB, logger *zap.Logger) *SuiPaymentHandler {
	listener := NewListener(cfg, db, logger)
	return &SuiPaymentHandler{lis: listener, db: db}
}

func (h *SuiPaymentHandler) Start(ctx context.Context) error {
	return h.lis.Start(ctx)
}

func (h *SuiPaymentHandler) CreatePaymentIntent(ctx context.Context, price int64, hash string) (SuiPaymentIntent, error) {
	b_transactionId := make([]byte, 16)
	b_authKey := make([]byte, 16)
	_, err := rand.Read(b_transactionId)
	_, err2 := rand.Read(b_authKey)
	if err != nil || err2 != nil {
		return SuiPaymentIntent{}, fmt.Errorf("Failed to create Intent")
	}
	expiresAt := time.Now().Add(time.Minute * 5)
	transactionId := hex.EncodeToString(b_transactionId)
	authKey := hex.EncodeToString(b_authKey)
	queries := ddb.New(h.db)
	if _, err := queries.CreateTransaction(ctx, ddb.CreateTransactionParams{
		ID:        transactionId,
		AuthKey:   authKey,
		Price:     price,
		Method:    "SUI",
		ExpiresAt: expiresAt,
		Hash:      hash,
		Paid:      false,
	}); err != nil {
		return SuiPaymentIntent{}, fmt.Errorf("failed to store transaction: %w", err)
	}

	return SuiPaymentIntent{
		TransactionId:   transactionId,
		Price:           price,
		AuthKey:         authKey,
		RegistryAddress: h.lis.paymentRegistryId,
		ReceiverAddress: h.lis.receiverAddress,
		ExpiresAt:       expiresAt,
	}, nil
}
