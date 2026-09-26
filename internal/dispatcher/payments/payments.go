// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

var (
	// ErrPaymentsDisabled is returned (possibly wrapped) by every chain payment
	// action while cfg.Sui.Disabled is set. TEST payments are unaffected.
	ErrPaymentsDisabled = errors.New("blockchain payments are disabled")
	// ErrUnsupportedPaymentMethod is wrapped by CheckPaymentMethod for methods
	// other than TEST, USDC and SUI.
	ErrUnsupportedPaymentMethod = errors.New("unsupported payment method")
)

// chainBackend is the subset of *sui.SuiPaymentHandler that PaymentHandler
// uses. It exists so construction tests can script the chain side without a
// network or key file; *sui.SuiPaymentHandler satisfies it unchanged.
type chainBackend interface {
	Start(ctx context.Context) error
	CreatePaymentIntent(transactionId string, price int64, currency string, hash string, ctx context.Context) (sui.SuiPaymentIntent, error)
	RefundDebuglet(debugletOrder *database.DebugletOrder, refundAddress string, ctx context.Context) error
	TransferCoins(amount uint64, cointype string, refundAddress string, ctx context.Context) error
}

// payoutLoop is the subset of *PayoutTicker that PaymentHandler uses.
type payoutLoop interface {
	StartPayoutLoop(ctx context.Context) error
}

// paymentDeps carries the constructors of the two chain-mode services. The
// production set is defined by productionDeps; tests substitute scripted ones.
type paymentDeps struct {
	newChain  func(cfg *config.DispatcherConfig, db *sql.DB, logger *zap.Logger, tf sui.TransactionFulfiller) chainBackend
	newPayout func(db *sql.DB, h Handler, logger *zap.Logger) payoutLoop
}

func productionDeps() paymentDeps {
	return paymentDeps{
		newChain: func(cfg *config.DispatcherConfig, db *sql.DB, logger *zap.Logger, tf sui.TransactionFulfiller) chainBackend {
			return sui.NewSuiPaymentHandler(cfg, db, logger, tf)
		},
		newPayout: func(db *sql.DB, h Handler, logger *zap.Logger) payoutLoop {
			return NewPayoutTicker(db, h, logger)
		},
	}
}

type PaymentHandler struct {
	db     *sql.DB
	sui    chainBackend // nil while cfg.Sui.Disabled
	logger *zap.Logger
	cfg    *config.DispatcherConfig
	pt     payoutLoop // nil while cfg.Sui.Disabled
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
	return newPaymentHandler(db, cfg, logger, productionDeps())
}

// newPaymentHandler is the single construction path. In disabled mode neither
// factory is invoked, so no chain client, event listener, keystore read or
// payout ticker exists; the handler then serves database-backed TEST payments
// only. In enabled mode both factories are invoked exactly once.
func newPaymentHandler(db *sql.DB, cfg *config.DispatcherConfig, logger *zap.Logger, deps paymentDeps) *PaymentHandler {
	handler := &PaymentHandler{db: db, logger: logger, cfg: cfg}
	if cfg.Sui.Disabled {
		logger.Info("blockchain payments are disabled; only TEST payments are available")
		return handler
	}
	handler.sui = deps.newChain(cfg, db, logger, handler)
	handler.pt = deps.newPayout(db, handler, logger)
	return handler
}

// chainDisabled reports whether chain payment actions are switched off. It is
// decided by configuration only, never inferred from other fields.
func (p *PaymentHandler) chainDisabled() bool {
	return p.cfg.Sui.Disabled
}

// isChainCurrency reports whether a payment method/order currency is settled
// on chain. Only the literal strings "USDC" and "SUI" are chain currencies.
func isChainCurrency(currency string) bool {
	return currency == "USDC" || currency == "SUI"
}

// requireChain returns an error wrapping ErrPaymentsDisabled when the given
// action would need the chain backend but blockchain payments are disabled.
// Every path that reaches p.sui must pass this check first, so a disabled
// handler returns the sentinel instead of dereferencing a nil backend.
func (p *PaymentHandler) requireChain(currency string, action string) error {
	if isChainCurrency(currency) && p.chainDisabled() {
		return fmt.Errorf("%s (%s): %w", action, currency, ErrPaymentsDisabled)
	}
	return nil
}

// CheckPaymentMethod is the mode preflight for a payment method. TEST is
// accepted in both modes; USDC and SUI return ErrPaymentsDisabled while
// blockchain payments are disabled; any other method returns an error wrapping
// ErrUnsupportedPaymentMethod.
func (p *PaymentHandler) CheckPaymentMethod(method string) error {
	switch method {
	case "TEST":
		return nil
	case "USDC", "SUI":
		if p.chainDisabled() {
			return ErrPaymentsDisabled
		}
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedPaymentMethod, method)
	}
}

// Start runs the chain listener and the payout loop until ctx is cancelled or
// the listener fails. Disabled mode returns nil immediately without spawning
// anything; repeated calls remain no-ops.
func (p *PaymentHandler) Start(ctx context.Context) error {
	if p.chainDisabled() {
		return nil
	}
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
		if err := p.requireChain(method, "create payment intent"); err != nil {
			return PaymentIntent{}, err
		}
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
		Price:     price,
		Currency:  "TEST",
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

// CompleteTransaction marks a transaction as paid. It is the
// sui.TransactionFulfiller callback of the chain listener, so it keeps its
// void signature: a failed lookup, or a chain transaction while blockchain
// payments are disabled, is logged and leaves the row untouched.
func (p *PaymentHandler) CompleteTransaction(transactionId string, ctx context.Context) {
	queries := database.New(p.db)
	transaction, err := queries.GetTransactionByID(ctx, transactionId)
	if err != nil {
		p.logger.Error("failed to look up transaction to settle", zap.String("id", transactionId), zap.Error(err))
		return
	}
	if err := p.requireChain(transaction.Method, "settle transaction"); err != nil {
		p.logger.Warn("not settling transaction", zap.String("id", transactionId), zap.String("method", transaction.Method), zap.Error(err))
		return
	}
	p.logger.Info("settling transaction", zap.String("id", transactionId))
	if err := queries.UpdateTransactionStatus(ctx, database.UpdateTransactionStatusParams{
		Status: int64(models.Paid),
		ID:     transactionId,
	}); err != nil {
		p.logger.Error("failed to settle transaction", zap.String("id", transactionId), zap.Error(err))
	}
}

func (p *PaymentHandler) SetDebugletOrderComplete(debuglet *database.Debuglet, ctx context.Context) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	queries := database.New(p.db).WithTx(tx)
	p.logger.Debug("Update", zap.String("transactionId", debuglet.TransactionID), zap.Int64("orderId", debuglet.OrderID))
	// Read the order first: its currency decides whether crediting is allowed
	// before any state is changed.
	current, err := queries.GetDebugletOrder(ctx, database.GetDebugletOrderParams{
		TransactionID: debuglet.TransactionID,
		OrderID:       debuglet.OrderID,
	})
	if err != nil {
		return fmt.Errorf("Failed to find debuglet order of %s: %w", debuglet.Uuid.String(), err)
	}
	if err := p.requireChain(current.Currency, "credit order"); err != nil {
		return err
	}
	// Only an outstanding order is credited. A credited order is already
	// included in the executor's earnings; a refunded order is not credited.
	switch models.TransactionState(current.State) {
	case models.Outstanding:
	case models.Credited, models.Refunded:
		return nil
	default:
		return fmt.Errorf("cannot credit order of %s in state %v", debuglet.Uuid.String(), models.TransactionState(current.State))
	}
	order, err := queries.UpdateDebugletOrderState(ctx, database.UpdateDebugletOrderStateParams{
		State:         int64(models.Credited),
		TransactionID: debuglet.TransactionID,
		OrderID:       debuglet.OrderID,
	})
	if err != nil {
		return fmt.Errorf("Failed to update state of %s: %s", debuglet.Uuid.String(), err.Error())
	}
	if err := p.CreateEarningsIfNotExists(debuglet.ExecutorID, order.Currency, "", queries, ctx); err != nil {
		return fmt.Errorf("failed to create earnings of %s: %w", debuglet.ExecutorID, err)
	}
	if err := queries.AddEarnings(ctx, database.AddEarningsParams{
		Amount:     order.Price,
		ExecutorID: debuglet.ExecutorID,
		Currency:   order.Currency,
	}); err != nil {
		return fmt.Errorf("failed to credit earnings of %s: %w", debuglet.ExecutorID, err)
	}
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
		return fmt.Errorf("Failed to find debuglet order: %w", err)
	}
	if order.State == int64(models.Refunded) {
		return fmt.Errorf("Debuglet has already been refunded")
	}
	if err := p.requireChain(order.Currency, "refund order"); err != nil {
		return err
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
	// The currency and the refund address live on the order rows, so a paid
	// transaction that has none says nothing about where the money would go.
	// It is reported rather than indexed into.
	if len(orders) == 0 {
		return fmt.Errorf("Transaction %s has no orders to refund", transactionId)
	}
	currency := orders[0].Currency
	refundAddress := orders[0].RefundAddress
	if err := p.requireChain(currency, "refund transaction"); err != nil {
		return err
	}
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
		if _, err := queries.UpdateDebugletOrderState(ctx, database.UpdateDebugletOrderStateParams{
			State:         int64(models.Refunded),
			TransactionID: transactionId,
			OrderID:       order.OrderID,
		}); err != nil {
			return err
		}
	}
	// The transaction is refunded, not only its order rows. A submission is
	// admitted on the transaction's status, so a transaction left Paid after
	// its money went back would admit the same batch again and have the work
	// done a second time for a payment that no longer exists.
	if err := queries.UpdateTransactionStatus(ctx, database.UpdateTransactionStatusParams{
		Status: int64(models.Refunded), ID: transactionId,
	}); err != nil {
		return err
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

func (p *PaymentHandler) CreateEarningsIfNotExists(execID string, currency string, wallet string, queries *database.Queries, ctx context.Context) error {
	_, err := queries.GetEarningsIn(ctx, database.GetEarningsInParams{
		ExecutorID: execID,
		Currency:   currency,
	})
	if errors.Is(err, sql.ErrNoRows) {
		_, err = queries.CreateEarnings(ctx, database.CreateEarningsParams{
			ExecutorID:       execID,
			Currency:         currency,
			SuiWalletAddress: wallet,
		})
	}
	return err
}

func (p *PaymentHandler) TransferUSDC(amount uint64, receiver string, ctx context.Context) error {
	if err := p.requireChain("USDC", "transfer USDC"); err != nil {
		return err
	}
	// This backend's signature takes ctx last, unlike the rest of this package.
	return p.sui.TransferCoins(amount, receiver, sui.GetCoinType("USDC", p.cfg.Sui.Network), ctx)
}

func (p *PaymentHandler) PayoutExecutor(earning database.Earning, ctx context.Context) error {
	if err := p.requireChain(earning.Currency, "pay out earnings"); err != nil {
		return err
	}
	switch earning.Currency {
	case "USDC":
		return p.sui.TransferCoins(uint64(earning.CurrentBalance), sui.GetCoinType("USDC", p.cfg.Sui.Network), earning.SuiWalletAddress, ctx)
	default:
		return fmt.Errorf("Unknown/unallowed currency %s", earning.Currency)
	}
}
