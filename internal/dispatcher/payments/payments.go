package payments

import (
	"crypto/rand"
	"debuglet/internal/dispatcher/config"
	"debuglet/internal/dispatcher/db"
	"debuglet/internal/dispatcher/payments/sui"
	"encoding/hex"
	"fmt"
	"time"

	"go.uber.org/zap"
)

type PaymentHandler struct {
	db     *db.TransactionDB
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

func NewPaymentHandler(db *db.TransactionDB, userDB *db.UserDB, cfg *config.DispatcherConfig, logger *zap.Logger) *PaymentHandler {
	return &PaymentHandler{
		db:     db,
		sui:    sui.NewSuiPaymentHandler(cfg, userDB, db, logger),
		logger: logger,
	}
}

func (p *PaymentHandler) Start() error {
	return p.sui.Start()
}

func (p *PaymentHandler) CreatePaymentIntent(price int64, method string) (string, PaymentIntent, error) {
	switch method {
	case "SUI":
		transactionId, suiIntent, err := p.sui.CreatePaymentIntent(price)
		if err != nil {
			return "", PaymentIntent{}, fmt.Errorf("Failed to get Intent: %w", err)
		}
		return transactionId, PaymentIntent{method: method, Intent: suiIntent}, nil
	case "TEST":
		transactionId, err := p.CreateDummyIntent()
		return transactionId, PaymentIntent{method: "TEST", Intent: DummyIntent{TransactionId: transactionId, AuthKey: ""}}, err
	default:
		return "", PaymentIntent{}, fmt.Errorf("Unsupported payment method: %s", method)
	}
}

func (p *PaymentHandler) IsPayed(transactionID string) (bool, error) {
	payed, err := p.db.IsPayed(transactionID)
	if err != nil {
		return false, err
	}
	return payed, nil
}

func (p *PaymentHandler) GetTransaction(transactionID string) (db.Transaction, error) {
	transaction, err := p.db.GetTransaction(transactionID)
	return transaction, err
}

// This is for testing only. Creates a transaction and immediately sets it to payed
func (p *PaymentHandler) CreateDummyIntent() (string, error) {
	b_transactionId := make([]byte, 16)
	_, err := rand.Read(b_transactionId)
	if err != nil {
		return "", fmt.Errorf("Failed to create Intent")
	}
	expiresAt := time.Now().Add(time.Minute * 5).Unix()
	transactionId := hex.EncodeToString(b_transactionId)
	err = p.db.StoreTransaction(transactionId, "", 0, "TEST", expiresAt)
	if err != nil {
		return "", err
	}
	err = p.db.SetPayed(transactionId)
	payed, _ := p.db.IsPayed(transactionId)
	p.logger.Info("created intent: ", zap.String("id", transactionId), zap.Bool("payed", payed))
	return transactionId, err
}
