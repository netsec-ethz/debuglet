// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sui

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/block-vision/sui-go-sdk/common/grpcconn"
	"github.com/block-vision/sui-go-sdk/constant"
	sdkmodels "github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/signer"
	"github.com/block-vision/sui-go-sdk/sui/v2/grpc_client"
	"github.com/block-vision/sui-go-sdk/sui/v2/types"
	"github.com/block-vision/sui-go-sdk/transaction"
	"github.com/block-vision/sui-go-sdk/utils"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
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

// NewSuiPaymentHandler validates the [sui] configuration and loads the
// configured key before it builds the chain client and the receipt listener,
// so a misconfigured dispatcher fails at startup instead of running with a
// backend that cannot pay out or refund. The SDK clients dial lazily on their
// first call; nothing is connected here and nothing needs releasing when
// construction fails.
func NewSuiPaymentHandler(cfg *config.DispatcherConfig, db *sql.DB, logger *zap.Logger, tf TransactionFulfiller) (*SuiPaymentHandler, error) {
	if err := validateConfig(cfg.Sui); err != nil {
		return nil, err
	}
	signer, err := LoadKeypair(cfg.Sui.KeystorePath, cfg.Sui.Address, logger)
	if err != nil {
		return nil, fmt.Errorf("sui.keystore_path: %w", err)
	}
	client, err := grpc_client.NewClient(
		grpc_client.ClientOptions{
			GrpcClient: grpcconn.NewSuiGrpcClient(
				cfg.Sui.GRPCEndpoint,
				grpcconn.WithDialOptions(grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, ""))),
			),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create sui client: %w", err)
	}
	listener := NewListener(cfg, db, logger, tf)
	return &SuiPaymentHandler{lis: listener, db: db, cfg: cfg, signer: signer, client: client, logger: logger}, nil
}

// validateConfig checks every [sui] field that chain mode depends on. It
// reads no file and opens no connection.
func validateConfig(c config.SuiConfig) error {
	if GetCoinType("USDC", c.Network) == "" {
		return fmt.Errorf("sui.network %q is not supported; use testnet or mainnet", c.Network)
	}
	host, port, err := net.SplitHostPort(c.GRPCEndpoint)
	if err != nil || host == "" {
		return fmt.Errorf("sui.grpc_endpoint %q must be host:port", c.GRPCEndpoint)
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return fmt.Errorf("sui.grpc_endpoint %q has an invalid port", c.GRPCEndpoint)
	}
	u, err := url.Parse(c.GraphQLURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("sui.graphql_url %q must be an absolute http(s) URL", c.GraphQLURL)
	}
	for _, field := range []struct{ name, value string }{
		{"sui.address", c.Address},
		{"sui.payment_registry_id", c.PaymentRegistryId},
		{"sui.payment_kit_package", c.PaymentKitPackage},
	} {
		if err := ValidAddress(field.value); err != nil {
			return fmt.Errorf("%s: %w", field.name, err)
		}
	}
	if c.KeystorePath == "" {
		return errors.New("sui.keystore_path is empty")
	}
	return nil
}

// ValidAddress reports whether s is a Sui address or object id: 0x followed
// by one to 64 hexadecimal digits. The SDK accepts the short form and pads it.
func ValidAddress(s string) error {
	digits, ok := strings.CutPrefix(s, "0x")
	// The length bound comes first: the SDK's normalisation panics on longer input.
	if !ok || len(digits) == 0 || len(digits) > 64 {
		return fmt.Errorf("%q is not a Sui address", s)
	}
	if _, err := transaction.ConvertSuiAddressStringToBytes(sdkmodels.SuiAddress(s)); err != nil {
		return fmt.Errorf("%q is not a Sui address", s)
	}
	return nil
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

// Errors of the transfer methods. A transfer error wraps ErrNotBroadcast,
// wraps ErrTransferFailed, or wraps neither: then the transaction may have
// been submitted and its outcome is unknown until LookupTransfer resolves it.
var (
	// ErrNotBroadcast marks a failure before the transaction was submitted;
	// nothing was sent.
	ErrNotBroadcast = errors.New("transfer not broadcast")
	// ErrTransferFailed marks a transaction the chain executed with a failure
	// status; no coins moved.
	ErrTransferFailed = errors.New("transfer executed with failure status")
)

// TransferOutcome is what the chain reports for a transfer digest.
type TransferOutcome string

const (
	TransferConfirmed TransferOutcome = "confirmed" // executed successfully
	TransferFailed    TransferOutcome = "failed"    // executed with failure status
	TransferNotFound  TransferOutcome = "not_found" // unknown to the node
)

// PreparedTransfer is a built and signed transfer that has not been
// submitted. Digest identifies the transaction on chain, so a caller can
// record it before ExecuteTransfer and look the transfer up afterwards.
type PreparedTransfer struct {
	Digest    string
	txBytes   []byte
	signature string
}

// Bounds of coin selection. Coins are read in pages of coinPageSize, at most
// maxCoinPages pages per selection. A gas payment holds at most maxGasCoins
// objects, the chain's limit.
const (
	coinPageSize = 50
	maxCoinPages = 20
	maxGasCoins  = 256
)

// transferGasUnits sets the gas budget: budget = reference gas price x
// transferGasUnits. 50,000 units is the SDK's default budget of 50,000,000
// MIST at a reference price of 1,000 MIST, so the budget keeps that headroom
// when the price changes. The budget is an upper bound; only the gas the
// transfer uses is charged.
const transferGasUnits = 50_000

// coinLister is the SDK call that coin selection pages through;
// (*grpc_client.Client).ListCoins satisfies it.
type coinLister func(ctx context.Context, options types.ListCoinsOptions) (*types.ListCoinsResponse, error)

// selectCoins pages through owner's coins of coinType, skipping the object
// ids in exclude, and returns the coins read until their balances cover
// amount, with their total. It selects at most maxCoins coins and reads at
// most maxCoinPages pages.
func selectCoins(ctx context.Context, list coinLister, owner string, coinType string, amount uint64, maxCoins int, exclude map[string]bool) ([]types.Coin, uint64, error) {
	if amount == 0 {
		return nil, 0, errors.New("amount must be positive")
	}
	limit := uint32(coinPageSize)
	var (
		selected []types.Coin
		total    uint64
		cursor   *string
	)
	seen := map[string]bool{}
	for page := 0; ; page++ {
		if page == maxCoinPages {
			return nil, 0, fmt.Errorf("%s coins: more than %d pages without covering %d (selected %d)", coinType, maxCoinPages, amount, total)
		}
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		resp, err := list(ctx, types.ListCoinsOptions{Owner: owner, CoinType: &coinType, Limit: &limit, Cursor: cursor})
		if err != nil {
			return nil, 0, fmt.Errorf("list %s coins: %w", coinType, err)
		}
		more := resp.HasNextPage && resp.Cursor != nil
		if len(resp.Objects) == 0 && more {
			return nil, 0, fmt.Errorf("%s coins: empty page %d before the end of the listing", coinType, page+1)
		}
		for _, coin := range resp.Objects {
			if exclude[coin.ObjectId] {
				continue
			}
			balance, err := strconv.ParseUint(coin.Balance, 10, 64)
			if err != nil {
				return nil, 0, fmt.Errorf("coin %s: invalid balance %q", coin.ObjectId, coin.Balance)
			}
			if balance == 0 {
				continue
			}
			if balance > math.MaxUint64-total {
				return nil, 0, fmt.Errorf("%s coins: balance total overflows", coinType)
			}
			selected = append(selected, coin)
			total += balance
			if total >= amount {
				return selected, total, nil
			}
			if len(selected) == maxCoins {
				return nil, 0, fmt.Errorf("insufficient %s balance in %d coins: %d of %d", coinType, maxCoins, total, amount)
			}
		}
		if !more {
			return nil, 0, fmt.Errorf("insufficient %s balance: %d of %d", coinType, total, amount)
		}
		if seen[*resp.Cursor] {
			return nil, 0, fmt.Errorf("%s coins: listing repeated a cursor", coinType)
		}
		seen[*resp.Cursor] = true
		cursor = resp.Cursor
	}
}

// objectRef converts a listed coin into the reference a transaction input
// or gas payment needs.
func objectRef(coin types.Coin) (*transaction.SuiObjectRef, error) {
	if err := ValidAddress(coin.ObjectId); err != nil {
		return nil, fmt.Errorf("coin: %w", err)
	}
	ref, err := transaction.NewSuiObjectRef(sdkmodels.SuiAddress(coin.ObjectId), coin.Version, sdkmodels.ObjectDigest(coin.Digest))
	if err != nil {
		return nil, fmt.Errorf("coin %s: invalid reference: %w", coin.ObjectId, err)
	}
	return ref, nil
}

// buildTransfer builds the transaction that sends exactly amount from coins
// (holding total) to receiver: the coins are merged into the first one and,
// when total exceeds amount, amount is split off and sent, so the change
// stays in the merged coin at the sender's address.
func buildTransfer(s *signer.Signer, coins []types.Coin, total uint64, amount uint64, receiver string, gas []types.Coin, price uint64, budget uint64) (*transaction.Transaction, error) {
	tx := transaction.NewTransaction()
	inputs := make([]transaction.Argument, 0, len(coins))
	for _, coin := range coins {
		ref, err := objectRef(coin)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, tx.Object(transaction.CallArg{Object: &transaction.ObjectArg{ImmOrOwnedObject: ref}}))
	}
	payment := make([]transaction.SuiObjectRef, 0, len(gas))
	for _, coin := range gas {
		ref, err := objectRef(coin)
		if err != nil {
			return nil, err
		}
		payment = append(payment, *ref)
	}
	sent := inputs[0]
	if len(inputs) > 1 {
		tx.MergeCoins(sent, inputs[1:])
	}
	if total > amount {
		sent = tx.SplitCoins(sent, []transaction.Argument{tx.Pure(amount)})
	}
	tx.TransferObjects([]transaction.Argument{sent}, tx.Pure(receiver))
	tx.SetSigner(s)
	tx.SetGasPrice(price)
	tx.SetGasBudget(budget)
	tx.SetGasPayment(payment)
	return tx, nil
}

// PrepareTransfer selects coins and gas, builds and signs a transfer of
// amount coinType to receiver, and returns it with its digest. It submits
// nothing; every error wraps ErrNotBroadcast.
func (h *SuiPaymentHandler) PrepareTransfer(ctx context.Context, amount uint64, coinType string, receiver string) (*PreparedTransfer, error) {
	prepared, err := h.prepareTransfer(ctx, amount, coinType, receiver)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotBroadcast, err)
	}
	return prepared, nil
}

func (h *SuiPaymentHandler) prepareTransfer(ctx context.Context, amount uint64, coinType string, receiver string) (*PreparedTransfer, error) {
	if err := ValidAddress(receiver); err != nil {
		return nil, fmt.Errorf("receiver: %w", err)
	}
	if coinType == "" {
		return nil, errors.New("no coin type for this network")
	}
	if h.signer == nil {
		return nil, errors.New("no keypair loaded")
	}
	owner := h.signer.Address
	coins, total, err := selectCoins(ctx, h.client.ListCoins, owner, coinType, amount, maxCoinPages*coinPageSize, nil)
	if err != nil {
		return nil, err
	}

	gp, err := h.client.GetReferenceGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("reference gas price: %w", err)
	}
	price, err := strconv.ParseUint(gp.ReferenceGasPrice, 10, 64)
	if err != nil || price == 0 {
		return nil, fmt.Errorf("invalid reference gas price %q", gp.ReferenceGasPrice)
	}
	if price > math.MaxUint64/transferGasUnits {
		return nil, fmt.Errorf("reference gas price %d overflows the gas budget", price)
	}
	budget := price * transferGasUnits

	// A coin is either transferred or pays gas, never both.
	var exclude map[string]bool
	if coinType == types.SUI_TYPE_ARG {
		exclude = make(map[string]bool, len(coins))
		for _, coin := range coins {
			exclude[coin.ObjectId] = true
		}
	}
	gas, _, err := selectCoins(ctx, h.client.ListCoins, owner, types.SUI_TYPE_ARG, budget, maxGasCoins, exclude)
	if err != nil {
		return nil, fmt.Errorf("gas: %w", err)
	}

	tx, err := buildTransfer(h.signer, coins, total, amount, receiver, gas, price, budget)
	if err != nil {
		return nil, err
	}
	txBytes, err := tx.BuildBCSBytes(ctx)
	if err != nil {
		return nil, fmt.Errorf("build transaction bytes: %w", err)
	}
	sig, err := h.signer.SignMessage(base64.StdEncoding.EncodeToString(txBytes), constant.TransactionDataIntentScope)
	if err != nil {
		return nil, fmt.Errorf("sign transaction: %w", err)
	}
	// The Sui digest of the transaction data, known before submission.
	digest, err := utils.GetTxDigestFromBytes(txBytes)
	if err != nil {
		return nil, fmt.Errorf("transaction digest: %w", err)
	}
	return &PreparedTransfer{Digest: digest, txBytes: txBytes, signature: sig.Signature}, nil
}

// ExecuteTransfer submits a prepared transfer. An error wrapping
// ErrTransferFailed means the chain executed it with a failure status; any
// other error from the submission leaves the outcome unknown.
func (h *SuiPaymentHandler) ExecuteTransfer(ctx context.Context, prepared *PreparedTransfer) error {
	if prepared == nil || len(prepared.txBytes) == 0 {
		return fmt.Errorf("%w: no prepared transaction", ErrNotBroadcast)
	}
	result, err := h.client.ExecuteTransaction(ctx, types.ExecuteTransactionOptions{
		Transaction: prepared.txBytes,
		Signatures:  []string{prepared.signature},
	})
	if err != nil {
		return fmt.Errorf("execute transfer %s: %w", prepared.Digest, err)
	}
	if result.Transaction == nil {
		return fmt.Errorf("execute transfer %s: empty response", prepared.Digest)
	}
	if d := result.Transaction.Digest; d != "" && d != prepared.Digest {
		h.logger.Error("executed transfer digest differs from the computed digest",
			zap.String("computed", prepared.Digest), zap.String("executed", d))
		prepared.Digest = d
	}
	switch st := result.Transaction.Status; {
	case st.Success:
		h.logger.Info("Transferred coins", zap.String("digest", prepared.Digest))
		return nil
	case st.Error != nil:
		return fmt.Errorf("%w: %s: %s", ErrTransferFailed, prepared.Digest, st.Error.Message)
	default:
		return fmt.Errorf("execute transfer %s: response carries no execution status", prepared.Digest)
	}
}

// TransferCoins prepares and executes a transfer of amount cointype to
// receiver. It returns the transfer's digest whenever one was computed, also
// with an error, so that an unknown outcome can be looked up.
func (h *SuiPaymentHandler) TransferCoins(amount uint64, cointype string, receiver string, ctx context.Context) (string, error) {
	prepared, err := h.PrepareTransfer(ctx, amount, cointype, receiver)
	if err != nil {
		return "", err
	}
	err = h.ExecuteTransfer(ctx, prepared)
	return prepared.Digest, err
}

// LookupTransfer reports what the chain knows about the transfer with the
// given digest. An error means the lookup itself failed.
func (h *SuiPaymentHandler) LookupTransfer(ctx context.Context, digest string) (TransferOutcome, error) {
	if digest == "" {
		return "", errors.New("look up transfer: empty digest")
	}
	result, err := h.client.GetTransaction(ctx, types.GetTransactionOptions{Digest: digest})
	if err != nil {
		if status.Code(err) == codes.NotFound || errors.Is(err, types.ErrTransactionNotFound) {
			return TransferNotFound, nil
		}
		return "", fmt.Errorf("look up transfer %s: %w", digest, err)
	}
	switch tx := result.Transaction; {
	case tx == nil:
		return "", fmt.Errorf("look up transfer %s: empty response", digest)
	case tx.Status.Success:
		return TransferConfirmed, nil
	case tx.Status.Error != nil:
		return TransferFailed, nil
	default:
		return "", fmt.Errorf("look up transfer %s: response carries no execution status", digest)
	}
}

func (h *SuiPaymentHandler) RefundDebuglet(debugletOrder *database.DebugletOrder, refundAddress string, ctx context.Context) error {

	_, err := h.TransferCoins(uint64(debugletOrder.Price), GetCoinType("USDC", h.cfg.Sui.Network), debugletOrder.RefundAddress, ctx)
	if err != nil {
		return err
	}
	h.logger.Debug("Executed Refund", zap.Int64("Amount", debugletOrder.Price), zap.String("receiver", refundAddress))
	return nil
}
