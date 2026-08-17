package sui

import (
	"context"
	"crypto/rand"
	"database/sql"
	"debuglet/internal/dispatcher/config"
	"debuglet/internal/dispatcher/database/ddb"
	"debuglet/internal/dispatcher/models"
	"encoding/hex"
	"fmt"
	"time"

	"go.uber.org/zap"
)

type SuiPaymentHandler struct {
	lis *Listener
	db  *sql.DB
	cfg *config.DispatcherConfig
}

type SuiPaymentIntent struct {
	TransactionId   string
	Price           int64
	CoinType        string
	AuthKey         string
	ExpiresAt       time.Time
	RegistryAddress string
	ReceiverAddress string
}

func GetCoinType(currency string, network string) string {
	switch currency {
	case "SUI":
		return "0x2::sui::SUI"
	case "USDC":
		switch network {
		case "testnet":
			return "0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC"
		case "mainnet":
			return "0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC"
		}
	default:
		return ""
	}
	return ""
}

func NewSuiPaymentHandler(cfg *config.DispatcherConfig, db *sql.DB, logger *zap.Logger, tf TransactionFulfiller) *SuiPaymentHandler {
	listener := NewListener(cfg, db, logger, tf)
	return &SuiPaymentHandler{lis: listener, db: db, cfg: cfg}
}

func (h *SuiPaymentHandler) Start(ctx context.Context) error {
	return h.lis.Start(ctx)
}

func (h *SuiPaymentHandler) CreatePaymentIntent(transactionId string, price int64, currency string, hash string, ctx context.Context) (SuiPaymentIntent, error) {
	b_authKey := make([]byte, 16)
	_, err := rand.Read(b_authKey)
	if err != nil {
		return SuiPaymentIntent{}, fmt.Errorf("Failed to create Intent")
	}

	coinType := GetCoinType(currency, h.cfg.Sui.Network)
	if coinType == "" {
		return SuiPaymentIntent{}, fmt.Errorf("No coin type found for currency %s on %s", currency, h.cfg.Sui.Network)
	}

	expiresAt := time.Now().Add(time.Minute * 5)
	authKey := hex.EncodeToString(b_authKey)
	queries := ddb.New(h.db)
	if _, err := queries.CreateTransaction(ctx, ddb.CreateTransactionParams{
		ID:        transactionId,
		AuthKey:   authKey,
		Price:     price,
		Currency:  currency,
		Method:    "SUI",
		ExpiresAt: models.NewUTCTime(expiresAt),
		Hash:      hash,
		Status:    int64(models.Outstanding),
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
		CoinType:        coinType,
	}, nil
}
