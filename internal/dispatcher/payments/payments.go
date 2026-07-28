package payments

import (
	"debuglet/internal/dispatcher/config"
	"debuglet/internal/dispatcher/db"
	"debuglet/internal/dispatcher/payments/sui"
	"fmt"

	"go.uber.org/zap"
)

type PaymentHandler struct {
	db  *db.TransactionDB
	sui *sui.SuiPaymentHandler
}

type PaymentIntent struct {
	method string
	intent any //method specific intent fields
}

func NewPaymentHandler(db *db.TransactionDB, userDB *db.UserDB, cfg *config.DispatcherConfig, logger *zap.Logger) *PaymentHandler {
	return &PaymentHandler{
		db:  db,
		sui: sui.NewSuiPaymentHandler(cfg.Sui.RPCURL, cfg.Sui.GRPCEndpoint, cfg.Sui.Address, userDB, db, logger),
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
		return transactionId, PaymentIntent{method: method, intent: suiIntent}, nil
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
