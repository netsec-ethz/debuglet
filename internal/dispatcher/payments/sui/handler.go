// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sui

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"strconv"
	"time"

	"github.com/block-vision/sui-go-sdk/common/grpcconn"
	"github.com/block-vision/sui-go-sdk/constant"
	sdkmodels "github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/signer"
	"github.com/block-vision/sui-go-sdk/sui/v2/grpc_client"
	"github.com/block-vision/sui-go-sdk/sui/v2/types"
	"github.com/block-vision/sui-go-sdk/transaction"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type SuiPaymentHandler struct {
	lis    *Listener
	db     *sql.DB
	cfg    *config.DispatcherConfig
	signer *signer.Signer
	client *grpc_client.Client
	logger *zap.Logger
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
	client, _ := grpc_client.NewClient(
		grpc_client.ClientOptions{
			GrpcClient: grpcconn.NewSuiGrpcClient(
				cfg.Sui.GRPCEndpoint,
				grpcconn.WithDialOptions(grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, ""))),
			),
		},
	)
	listener := NewListener(cfg, db, logger, tf)
	signer, err := LoadKeypair(cfg.Sui.KeystorePath, cfg.Sui.Address, logger)
	if err != nil {
		logger.Warn(fmt.Errorf("Failed to load keypair: %s. USDC refunds and payouts can not be completed ", err.Error()).Error())
	}
	return &SuiPaymentHandler{lis: listener, db: db, cfg: cfg, signer: signer, client: client, logger: logger}
}

func (h *SuiPaymentHandler) Start(ctx context.Context) error {
	return h.lis.Start(ctx)
}

// CreatePaymentIntent stores the transaction row of a new intent through db,
// which may be the caller's SQL transaction.
func (h *SuiPaymentHandler) CreatePaymentIntent(db database.DBTX, transactionId string, price int64, currency string, hash string, ctx context.Context) (SuiPaymentIntent, error) {
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
	queries := database.New(db)
	if _, err := queries.CreateTransaction(ctx, database.CreateTransactionParams{
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

func coinArg(tx *transaction.Transaction, coin types.Coin) (transaction.Argument, error) {
	ref, err := transaction.NewSuiObjectRef(
		sdkmodels.SuiAddress(coin.ObjectId),
		coin.Version,
		sdkmodels.ObjectDigest(coin.Digest),
	)
	if err != nil {
		return transaction.Argument{}, fmt.Errorf("invalid coin ref %s: %s", coin.ObjectId, err.Error())
	}

	return tx.Object(transaction.CallArg{
		Object: &transaction.ObjectArg{
			ImmOrOwnedObject: ref,
		},
	}), nil
}

func (h *SuiPaymentHandler) GetTransactionCoin(tx *transaction.Transaction, amount uint64, cointype string, ctx context.Context) (transaction.Argument, error) {
	balance, err := h.client.GetBalance(ctx, types.GetBalanceOptions{
		Owner:    h.signer.Address,
		CoinType: &cointype,
	})
	if err != nil {
		return transaction.Argument{}, fmt.Errorf("Failed to fetch balance: %s", err.Error())
	}

	totalBalance, err := strconv.ParseUint(balance.Balance.CoinBalance, 10, 64)
	if err != nil {
		return transaction.Argument{}, fmt.Errorf("Invalid address balance %s", balance.Balance.CoinBalance)
	}
	if totalBalance < amount {
		return transaction.Argument{}, fmt.Errorf("Insuficient Balance %s", balance.Balance.CoinBalance)
	}

	OwnCoins, err := h.client.ListCoins(ctx, types.ListCoinsOptions{
		Owner:    h.signer.Address,
		CoinType: &cointype,
	})

	if err != nil {
		return transaction.Argument{}, fmt.Errorf("Failed to fetch coins: %s", err.Error())
	}
	coins := OwnCoins.Objects
	if len(coins) == 0 {
		return transaction.Argument{}, fmt.Errorf("No coins found")
	}
	//TODO paginate if there are many coins
	destination, err := coinArg(tx, coins[0])
	if err != nil {
		return transaction.Argument{}, err
	}
	runningTotal, err := strconv.ParseUint(coins[0].Balance, 10, 64)
	sources := []transaction.Argument{}
	for _, coin := range coins[1:] {
		if runningTotal >= amount {
			break
		}

		balance, err := strconv.ParseUint(coin.Balance, 10, 64)
		if err != nil {
			return transaction.Argument{}, fmt.Errorf("Invalid balance %s of coin %s", coin.Balance, coin.ObjectId)
		}
		runningTotal += balance
		source, err := coinArg(tx, coin)
		if err != nil {
			return transaction.Argument{}, err
		}
		sources = append(sources, source)
	}
	if len(sources) > 0 {
		tx.MergeCoins(destination, sources)
	}
	if runningTotal > amount {
		splitCoin := tx.SplitCoins(destination, []transaction.Argument{tx.Pure(runningTotal - amount)})
		tx.TransferObjects([]transaction.Argument{splitCoin}, tx.Pure(h.signer.Address))
	}

	return destination, nil
}

func (h *SuiPaymentHandler) GetGasCoinRefs(gasPrice uint64, ctx context.Context) ([]transaction.SuiObjectRef, error) {
	coins, err := h.client.ListCoins(ctx, types.ListCoinsOptions{
		Owner: h.signer.Address,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch coins: %s", err.Error())
	}
	var (
		refs  []transaction.SuiObjectRef
		total uint64
	)
	for _, coin := range coins.Objects {
		balance, err := strconv.ParseUint(coin.Balance, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("Invalid coin:%s", err.Error())
		}

		ref, err := transaction.NewSuiObjectRef(
			sdkmodels.SuiAddress(coin.ObjectId),
			coin.Version,
			sdkmodels.ObjectDigest(coin.Digest),
		)
		if err != nil {
			return nil, fmt.Errorf("invalid coin: %s", err.Error())
		}

		refs = append(refs, *ref)
		total += balance
		if total >= gasPrice {
			return refs, nil
		}
	}
	return nil, fmt.Errorf("insufficient balance %d < %d", total, gasPrice)
}

func (h *SuiPaymentHandler) TransferCoins(amount uint64, cointype string, refundAddress string, ctx context.Context) error {
	if refundAddress == "" {
		return fmt.Errorf("No wallet address set")
	}
	if h.signer == nil {
		return fmt.Errorf("No keypair set for sui transactions.")
	}
	tx := transaction.NewTransaction()
	coin, err := h.GetTransactionCoin(tx, amount, cointype, ctx)
	if err != nil {
		return err
	}

	tx.TransferObjects([]transaction.Argument{coin}, tx.Pure(refundAddress))

	tx.SetSigner(h.signer)
	gp, err := h.client.GetReferenceGasPrice(ctx)
	if err != nil {
		return err
	}
	price, _ := strconv.ParseUint(gp.ReferenceGasPrice, 10, 64)
	tx.SetGasPrice(price)
	gasCoinRefs, err := h.GetGasCoinRefs(amount, ctx)
	if err != nil {
		return err
	}
	tx.SetGasPayment(gasCoinRefs)

	txBytes, err := tx.BuildBCSBytes(ctx)
	if err != nil {
		return fmt.Errorf("Failed to build transaction bytes: %s", err.Error())
	}

	sig, err := h.signer.SignMessage(base64.StdEncoding.EncodeToString(txBytes), constant.TransactionDataIntentScope)
	if err != nil {
		return fmt.Errorf("Failed to sign transaction: %s", err.Error())
	}
	result, err := h.client.ExecuteTransaction(ctx, types.ExecuteTransactionOptions{
		Transaction: txBytes,
		Signatures:  []string{sig.Signature},
		Include: types.TransactionInclude{
			BalanceChanges: true,
		},
	})

	if err != nil {
		return fmt.Errorf("Failed to execute transaction: %s", err.Error())
	}
	if result.Transaction == nil {
		return fmt.Errorf("Empty transaction")
	}

	if !result.Transaction.Status.Success {
		return fmt.Errorf("failure: %s", result.Transaction.Status.Error.Message)
	}

	h.logger.Info("Transferred coins", zap.String("digest", result.Transaction.Digest))
	return nil
}

func (h *SuiPaymentHandler) RefundDebuglet(debugletOrder *database.DebugletOrder, refundAddress string, ctx context.Context) error {

	err := h.TransferCoins(uint64(debugletOrder.Price), GetCoinType("USDC", h.cfg.Sui.Network), debugletOrder.RefundAddress, ctx)
	if err != nil {
		return err
	}
	h.logger.Debug("Executed Refund", zap.Int64("Amount", debugletOrder.Price), zap.String("receiver", refundAddress))
	return nil
}
