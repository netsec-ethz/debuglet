package sui

import (
	"context"
	"crypto/rand"
	"debuglet/internal/dispatcher/db"
	"encoding/hex"
	"fmt"
	"time"

	"go.uber.org/zap"
)

type SuiPaymentHandler struct {
	Listener *Listener
	Database *db.TransactionDB
}

type SuiPaymentIntent struct {
	TransactionId   string
	Price           int64
	AuthKey         string
	ExpiresAt       int64
	RegistryAddress string
	ReceiverAddress string
}

func NewSuiPaymentHandler(grpcEndpoint, graphqlURL, receiverAddress string, userDB *db.UserDB, transactionDB *db.TransactionDB, logger *zap.Logger) *SuiPaymentHandler {
	listener := NewListener(grpcEndpoint, graphqlURL, receiverAddress, userDB, transactionDB, logger)
	return &SuiPaymentHandler{Listener: listener, Database: transactionDB}
}

func (h *SuiPaymentHandler) Start() error {
	return h.Listener.Start(context.Background())
}

func (h *SuiPaymentHandler) CreatePaymentIntent(price int64) (string, SuiPaymentIntent, error) {
	b_transactionId := make([]byte, 16)
	b_authKey := make([]byte, 16)
	_, err := rand.Read(b_transactionId)
	_, err2 := rand.Read(b_authKey)
	if err != nil || err2 != nil {
		return "", SuiPaymentIntent{}, fmt.Errorf("Failed to create Intent")
	}
	expiresAt := time.Now().Add(time.Minute * 5).Unix()
	transactionId := hex.EncodeToString(b_transactionId)
	authKey := hex.EncodeToString(b_authKey)
	if err := h.Database.StoreTransaction(transactionId, authKey, price, "SUI", expiresAt); err != nil {
		return "", SuiPaymentIntent{}, fmt.Errorf("failed to store transaction: %w", err)
	}

	return transactionId, SuiPaymentIntent{TransactionId: transactionId, Price: price, AuthKey: authKey, RegistryAddress: debugletRegistryTestnet, ReceiverAddress: h.Listener.receiverAddress, ExpiresAt: expiresAt}, nil
}
