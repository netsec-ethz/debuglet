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
	"math"
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
	// ErrTransactionClaimed means an unadmitted-only refund found admitted work.
	ErrTransactionClaimed = errors.New("payment transaction has admitted runs")
)

// chainBackend is the subset of *sui.SuiPaymentHandler that PaymentHandler
// uses. It exists so construction tests can script the chain side without a
// network or key file; *sui.SuiPaymentHandler satisfies it unchanged.
type chainBackend interface {
	Start(ctx context.Context) error
	CreatePaymentIntent(db database.DBTX, transactionId string, price int64, currency string, hash string, ctx context.Context) (sui.SuiPaymentIntent, error)
	RefundDebuglet(debugletOrder *database.DebugletOrder, refundAddress string, ctx context.Context) error
	// TransferCoins is PrepareTransfer followed by ExecuteTransfer. It returns
	// the transfer's digest whenever one was computed, also with an error.
	TransferCoins(amount uint64, cointype string, receiver string, ctx context.Context) (string, error)
	PrepareTransfer(ctx context.Context, amount uint64, coinType string, receiver string) (*sui.PreparedTransfer, error)
	ExecuteTransfer(ctx context.Context, prepared *sui.PreparedTransfer) error
	LookupTransfer(ctx context.Context, digest string, expect *sui.TransferExpectation) (sui.TransferOutcome, bool, error)
}

// payoutLoop is the subset of *PayoutTicker that PaymentHandler uses.
type payoutLoop interface {
	StartPayoutLoop(ctx context.Context) error
}

// paymentDeps carries the constructors of the two chain-mode services. The
// production set is defined by productionDeps; tests substitute scripted ones.
// newChain fails on an unusable [sui] configuration.
type paymentDeps struct {
	newChain  func(cfg *config.DispatcherConfig, db *sql.DB, logger *zap.Logger, tf sui.TransactionFulfiller) (chainBackend, error)
	newPayout func(db *sql.DB, h Handler, logger *zap.Logger) payoutLoop
}

func productionDeps() paymentDeps {
	return paymentDeps{
		newChain: func(cfg *config.DispatcherConfig, db *sql.DB, logger *zap.Logger, tf sui.TransactionFulfiller) (chainBackend, error) {
			h, err := sui.NewSuiPaymentHandler(cfg, db, logger, tf)
			if err != nil {
				return nil, err // not a typed nil inside the interface
			}
			return h, nil
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

func NewPaymentHandler(db *sql.DB, cfg *config.DispatcherConfig, logger *zap.Logger) (*PaymentHandler, error) {
	return newPaymentHandler(db, cfg, logger, productionDeps())
}

// newPaymentHandler is the single construction path. In disabled mode neither
// factory is invoked, so no chain client, event listener, keystore read or
// payout ticker exists; the handler then serves database-backed TEST payments
// only and construction cannot fail. In enabled mode both factories are
// invoked exactly once, the payout factory only after the chain backend was
// built.
func newPaymentHandler(db *sql.DB, cfg *config.DispatcherConfig, logger *zap.Logger, deps paymentDeps) (*PaymentHandler, error) {
	handler := &PaymentHandler{db: db, logger: logger, cfg: cfg}
	if cfg.Sui.Disabled {
		logger.Info("blockchain payments are disabled; only TEST payments are available")
		return handler, nil
	}
	chain, err := deps.newChain(cfg, db, logger, handler)
	if err != nil {
		return nil, fmt.Errorf("blockchain payments: %w", err)
	}
	handler.sui = chain
	handler.pt = deps.newPayout(db, handler, logger)
	return handler, nil
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
	return p.CreatePaymentIntentIn(p.db, transactionId, price, method, hash, ctx)
}

// CreatePaymentIntentIn is CreatePaymentIntent writing the transaction row
// through db, so a caller can store the intent and its orders in one SQL
// transaction.
func (p *PaymentHandler) CreatePaymentIntentIn(db database.DBTX, transactionId string, price int64, method string, hash string, ctx context.Context) (PaymentIntent, error) {
	switch method {
	case "USDC":
		fallthrough
	case "SUI":
		if err := p.requireChain(method, "create payment intent"); err != nil {
			return PaymentIntent{}, err
		}
		suiIntent, err := p.sui.CreatePaymentIntent(db, transactionId, price, method, hash, ctx)
		if err != nil {
			return PaymentIntent{}, fmt.Errorf("Failed to get Intent: %w", err)
		}
		return PaymentIntent{method: method, Intent: suiIntent}, nil
	case "TEST":
		err := p.createDummyIntent(db, transactionId, price, hash, ctx)
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
	return p.createDummyIntent(p.db, transactionId, price, hash, ctx)
}

// testIntentLifetime is how long a TEST intent stays valid after it is created.
const testIntentLifetime = 5 * time.Minute

func (p *PaymentHandler) createDummyIntent(db database.DBTX, transactionId string, price int64, hash string, ctx context.Context) error {
	//TODO check if we can fetch a timestamp from chain to avoid drift
	expiresAt := time.Now().Add(testIntentLifetime)

	queries := database.New(db)
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

// Settlement kinds recorded in order_settlements.
const (
	settlementCredit = "credit"
	settlementRefund = "refund"
)

// SettleTerminalOrder applies the payment decision for the order of a run that
// reached its terminal state: exit code 0 credits the executor, any other exit
// refunds the buyer. A USDC order is refunded on chain; a TEST order moves no
// funds and is only recorded as refunded. The decision is taken once per order:
// an order that is already credited or refunded is left as it is and nil is
// returned, so the terminal path and the settlement sweep may both deliver it.
func (p *PaymentHandler) SettleTerminalOrder(ctx context.Context, deb *database.Debuglet, exitCode int32) error {
	if exitCode == 0 {
		return p.settleOrder(ctx, deb, settlementCredit, "", false)
	}
	return p.settleOrder(ctx, deb, settlementRefund, "", false)
}

// SetDebugletOrderComplete credits the executor with the price of the run's
// order. It is the credit leg of SettleTerminalOrder.
func (p *PaymentHandler) SetDebugletOrderComplete(debuglet *database.Debuglet, ctx context.Context) error {
	return p.settleOrder(ctx, debuglet, settlementCredit, "", false)
}

// RefundDebugletOrder returns the price of the run's order to its buyer on
// chain. TEST orders hold no funds and are refused; SettleTerminalOrder records
// their refund locally instead.
func (p *PaymentHandler) RefundDebugletOrder(debuglet *database.Debuglet, refundAddress string, ctx context.Context) error {
	return p.settleOrder(ctx, debuglet, settlementRefund, refundAddress, true)
}

// settleOrder moves an Outstanding order to Credited or Refunded and records
// the decision in order_settlements in the same SQL transaction, together with
// the earnings credit or the chain refund. The conditional state write is the
// cheap guard against a second settlement, the settlement row's primary key the
// durable one; any failure rolls back all of it. A USDC refund instead goes
// through the transfer lifecycle, which marks the order Refunded in the SQL
// transaction that reserves its transfer, before the chain is called; an
// uncertain outcome is then the transfer's and is resolved by reconciliation.
func (p *PaymentHandler) settleOrder(ctx context.Context, debuglet *database.Debuglet, kind string, refundAddress string, chainOnly bool) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	queries := database.New(p.db).WithTx(tx)
	key := database.GetDebugletOrderParams{TransactionID: debuglet.TransactionID, OrderID: debuglet.OrderID}
	// Read the order first: its currency decides whether the settlement is
	// allowed before any state is changed.
	order, err := queries.GetDebugletOrder(ctx, key)
	if err != nil {
		return fmt.Errorf("Failed to find debuglet order of %s: %w", debuglet.Uuid.String(), err)
	}
	to := models.Credited
	if kind == settlementRefund {
		to = models.Refunded
		if err := p.requireChain(order.Currency, "refund order"); err != nil {
			return err
		}
		if order.Currency != "USDC" && (chainOnly || order.Currency != "TEST") {
			return fmt.Errorf("Refunds not supported for currency %s", order.Currency)
		}
	} else if err := p.requireChain(order.Currency, "credit order"); err != nil {
		return err
	}
	if kind == settlementRefund && order.Currency == "USDC" && order.State == int64(models.Outstanding) {
		// The chain refund is not sent inside this SQL transaction: the
		// transfer lifecycle commits the decision with the reserved transfer
		// before it calls the chain.
		tx.Rollback()
		order.ExecutorID = debuglet.ExecutorID
		if _, err := p.refundOnChain(ctx, order.TransactionID, []database.DebugletOrder{order}, nil); !errors.Is(err, errAlreadySettled) {
			return err
		}
		// Settled concurrently: an order leaves Outstanding only as Credited
		// or Refunded.
		return nil
	}

	changed, err := recordSettlement(ctx, queries, order, debuglet.ExecutorID, kind)
	if err != nil {
		return fmt.Errorf("failed to settle order of %s: %w", debuglet.Uuid.String(), err)
	}
	if !changed {
		// Only an outstanding order is settled. A credited order is already
		// included in the executor's earnings; a refunded order is not credited.
		current, err := queries.GetDebugletOrder(ctx, key)
		if err != nil {
			return fmt.Errorf("Failed to find debuglet order of %s: %w", debuglet.Uuid.String(), err)
		}
		switch models.TransactionState(current.State) {
		case models.Credited, models.Refunded:
			return nil
		default:
			return fmt.Errorf("cannot settle order of %s in state %v", debuglet.Uuid.String(), models.TransactionState(current.State))
		}
	}
	order.State = int64(to)

	if kind == settlementCredit {
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
	}
	return tx.Commit()
}

// recordSettlement moves an Outstanding order to Credited or Refunded and
// records the decision in order_settlements, through queries. It reports false
// and writes nothing when the order is no longer Outstanding.
func recordSettlement(ctx context.Context, queries *database.Queries, order database.DebugletOrder, executorID string, kind string) (bool, error) {
	to := models.Credited
	if kind == settlementRefund {
		to = models.Refunded
	}
	changed, err := queries.TransitionDebugletOrder(ctx, database.TransitionDebugletOrderParams{
		ToState: int64(to), TransactionID: order.TransactionID, OrderID: order.OrderID, FromState: int64(models.Outstanding),
	})
	if err != nil {
		return false, fmt.Errorf("update order state: %w", err)
	}
	if changed == 0 {
		return false, nil
	}
	if err := queries.InsertOrderSettlement(ctx, database.InsertOrderSettlementParams{
		TransactionID: order.TransactionID,
		OrderID:       order.OrderID,
		Kind:          kind,
		Amount:        order.Price,
		Currency:      order.Currency,
		ExecutorID:    executorID,
		DebugletID:    order.DebugletID,
		RecordedAt:    models.NewUTCTime(time.Now()),
	}); err != nil {
		return false, fmt.Errorf("record settlement: %w", err)
	}
	return true, nil
}

// refundOnChain refunds orders, Outstanding orders of one transaction with one
// currency and refund address, in one transfer of their total. Each order
// becomes Refunded with its refund settlement row, together with the writes
// of extra, in the SQL transaction that reserves the transfer. If any order
// is no longer Outstanding, nothing is written or sent and errAlreadySettled is
// returned. A transfer that then fails or stays unknown leaves the refund
// decided: the amount is owed and visible on the transfer row. The state
// recorded on that row is returned, empty when nothing was transferred.
func (p *PaymentHandler) refundOnChain(ctx context.Context, transactionID string, orders []database.DebugletOrder, extra func(*database.Queries) error) (string, error) {
	transfer := database.ChainTransfer{Kind: transferRefund, TransactionID: transactionID}
	for _, order := range orders {
		if order.Price < 0 {
			return "", fmt.Errorf("refund order %d of transaction %s: amount must not be negative", order.OrderID, transactionID)
		}
		if order.Price > math.MaxInt64-transfer.Amount {
			return "", fmt.Errorf("refund transaction %s: total amount exceeds the supported range", transactionID)
		}
		transfer.Amount += order.Price
		transfer.Currency, transfer.Receiver = order.Currency, order.RefundAddress
	}
	if len(orders) == 1 {
		transfer.OrderID = sql.NullInt64{Int64: orders[0].OrderID, Valid: true}
	}
	return p.sendTransfer(ctx, transfer, func(queries *database.Queries) error {
		if extra != nil {
			if err := extra(queries); err != nil {
				return err
			}
		}
		for _, order := range orders {
			changed, err := recordSettlement(ctx, queries, order, order.ExecutorID, settlementRefund)
			if err != nil {
				return fmt.Errorf("refund order %d of transaction %s: %w", order.OrderID, transactionID, err)
			}
			if !changed {
				return errAlreadySettled
			}
		}
		return nil
	})
}

// SettlePendingOrders applies SettleTerminalOrder to at most limit Outstanding
// orders whose run is terminal with a recorded exit code and whose run id is
// above after, in run order. A run without a recorded exit code is not settled:
// nothing infers its outcome. A chain refund is taken only while no refund
// transfer covers the order: one reserved by an earlier attempt, in any state,
// is left to ReconcileTransfers, so a pass never sends a refund twice. While
// chain payments are disabled, chain-currency orders are counted as deferred
// and not attempted. An order that fails stays Outstanding for a later pass and
// the others are still settled. next is the last run id attempted, or 0 once the
// listing is exhausted, so that the following pass continues after it and a
// failing order never keeps later ones from being attempted. The first failure
// is returned with the counts.
func (p *PaymentHandler) SettlePendingOrders(ctx context.Context, after int64, limit int) (settled, failed, deferred int, next int64, err error) {
	pending, err := database.New(p.db).ListPendingSettlements(ctx, database.ListPendingSettlementsParams{
		OutstandingState: int64(models.Outstanding), ExitedState: models.RunStateExited, AfterID: after, RowLimit: int64(limit),
	})
	if err != nil {
		return 0, 0, 0, after, fmt.Errorf("failed to list pending settlements: %w", err)
	}
	var first error
	exhausted := len(pending) < limit
	for _, row := range pending {
		if ctx.Err() != nil {
			exhausted = false
			break
		}
		run := row.Debuglet
		next = run.ID
		if isChainCurrency(row.Currency) && p.chainDisabled() {
			deferred++
			continue
		}
		if err := p.SettleTerminalOrder(ctx, &run, int32(row.ExitCode.Int64)); err != nil {
			p.logger.Debug("Order settlement remains pending", zap.String("debugletID", run.Uuid.String()))
			failed++
			if first == nil {
				first = err
			}
			continue
		}
		settled++
		p.logger.Info("Settled order of terminal run", zap.String("debugletID", run.Uuid.String()), zap.Int64("exitCode", row.ExitCode.Int64))
	}
	if deferred > 0 {
		p.logger.Debug("Chain settlements wait while chain payments are disabled", zap.Int("deferred", deferred))
	}
	if exhausted {
		next = 0
	} else if next == 0 {
		next = after
	}
	return settled, failed, deferred, next, first
}

// RefundTransaction retains transaction-wide refunds, including claimed orders.
// A submission caller uses it only after its own admission committed.
func (p *PaymentHandler) RefundTransaction(transactionId string, ctx context.Context) error {
	_, err := p.refundTransaction(transactionId, ctx, false)
	return err
}

// RefundUnadmittedTransaction refunds a paid intent only while none of its
// orders has been claimed. Its SQL write excludes a concurrent admission before
// any refund is sent to the chain backend. An error means nothing was decided
// and the intent stays spendable; otherwise the outcome says what became of
// the money.
func (p *PaymentHandler) RefundUnadmittedTransaction(transactionId string, ctx context.Context) (RefundOutcome, error) {
	return p.refundTransaction(transactionId, ctx, true)
}

// RefundOutcome is what a decided refund did with the money.
type RefundOutcome int

const (
	// RefundLocal: nothing was transferred on chain, as for a TEST refund.
	RefundLocal RefundOutcome = iota
	// RefundSent: the chain accepted the refund transfer.
	RefundSent
	// RefundPending: the refund transfer is recorded and its outcome is not
	// known yet; reconciliation resolves it.
	RefundPending
	// RefundFailed: the refund transfer is recorded but could not be sent; the
	// amount is owed to the refund address.
	RefundFailed
)

// refundOutcome maps the state of a refund transfer row; "" is no row.
func refundOutcome(state string) RefundOutcome {
	switch state {
	case transferSent, transferConfirmed:
		return RefundSent
	case transferReserved, transferUnknown:
		return RefundPending
	case transferFailed:
		return RefundFailed
	default:
		return RefundLocal
	}
}

// RefundOutcomeOf reports the outcome of the newest refund transfer of a
// transaction, RefundLocal when it has none.
func (p *PaymentHandler) RefundOutcomeOf(ctx context.Context, transactionId string) (RefundOutcome, error) {
	state, err := database.New(p.db).GetLatestRefundTransferState(ctx, transactionId)
	if errors.Is(err, sql.ErrNoRows) {
		return RefundLocal, nil
	}
	if err != nil {
		return RefundLocal, err
	}
	return refundOutcome(state), nil
}

func (p *PaymentHandler) refundTransaction(transactionId string, ctx context.Context, unadmittedOnly bool) (RefundOutcome, error) {
	// The transaction and its orders are read from one snapshot; the writes
	// are conditional and decide again when the refund is reserved.
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return RefundLocal, fmt.Errorf("Failed to begin transaction: %s", err.Error())
	}
	defer tx.Rollback()
	queries := database.New(p.db).WithTx(tx)
	transaction, err := queries.GetTransactionByID(ctx, transactionId)
	if err != nil {
		return RefundLocal, err
	}
	if transaction.Status != int64(models.Paid) {
		return RefundLocal, fmt.Errorf("Tried to refund transaction that has not been payed: %s", transactionId)
	}
	orders, err := queries.GetTransactionOrders(ctx, transactionId)
	if err != nil {
		return RefundLocal, err
	}
	// The currency and the refund address live on the order rows, so a paid
	// transaction that has none says nothing about where the money would go.
	// It is reported rather than indexed into.
	if len(orders) == 0 {
		return RefundLocal, fmt.Errorf("Transaction %s has no orders to refund", transactionId)
	}
	currency := orders[0].Currency
	refundAddress := orders[0].RefundAddress
	if err := p.requireChain(currency, "refund transaction"); err != nil {
		return RefundLocal, err
	}
	var outstanding []database.DebugletOrder
	for _, order := range orders {
		if order.Currency != currency || order.RefundAddress != refundAddress {
			// should never happen because these values are always set together but let's guard anyway
			return RefundLocal, fmt.Errorf("Inconsistent orders in transaction %s", transactionId)
		}
		if unadmittedOnly && order.DebugletID.Valid {
			return RefundLocal, ErrTransactionClaimed
		}
		if order.State != int64(models.Outstanding) {
			// A credited order was paid for with work; a refunded one is owed already.
			p.logger.Warn("Order has already been settled", zap.String("transactionID", transactionId), zap.Int64("orderID", order.OrderID))
			continue
		}
		outstanding = append(outstanding, order)
	}
	if currency != "USDC" {
		return RefundLocal, fmt.Errorf("Refunds are not supported for currency %s", currency)
	}
	tx.Rollback()

	// The transaction is refunded, not only its order rows. A submission is
	// admitted on the transaction's status, so a transaction left Paid after
	// its money went back would admit the same batch again and have the work
	// done a second time for a payment that no longer exists.
	state, err := p.refundOnChain(ctx, transactionId, outstanding, func(queries *database.Queries) error {
		if unadmittedOnly {
			changed, err := queries.RefundUnadmittedTransaction(ctx, database.RefundUnadmittedTransactionParams{
				RefundedStatus: int64(models.Refunded), TransactionID: transactionId, PaidStatus: int64(models.Paid),
			})
			if err != nil {
				return err
			}
			if changed != 1 {
				return ErrTransactionClaimed
			}
			return nil
		}
		changed, err := queries.RefundPaidTransaction(ctx, database.RefundPaidTransactionParams{
			Refunded: int64(models.Refunded), ID: transactionId, Paid: int64(models.Paid),
		})
		if err != nil {
			return err
		}
		if changed != 1 {
			return fmt.Errorf("Tried to refund transaction that has not been payed: %s", transactionId)
		}
		return nil
	})
	if errors.Is(err, errAlreadySettled) {
		return RefundLocal, fmt.Errorf("orders of transaction %s were settled during the refund; nothing was refunded", transactionId)
	}
	return refundOutcome(state), err
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
	coinType := sui.GetCoinType("USDC", p.cfg.Sui.Network)
	if coinType == "" {
		return fmt.Errorf("transfer USDC: no USDC coin type on network %q", p.cfg.Sui.Network)
	}
	if err := sui.ValidAddress(receiver); err != nil {
		return fmt.Errorf("transfer USDC: receiver: %w", err)
	}
	// This backend's signature takes ctx last, unlike the rest of this package.
	_, err := p.sui.TransferCoins(amount, coinType, receiver, ctx)
	return err
}

func (p *PaymentHandler) PayoutExecutor(earning database.Earning, ctx context.Context) error {
	if err := p.requireChain(earning.Currency, "pay out earnings"); err != nil {
		return err
	}
	if earning.Currency != "USDC" {
		return fmt.Errorf("Unknown/unallowed currency %s", earning.Currency)
	}
	if earning.CurrentBalance <= 0 {
		return nil
	}
	// Exactly the balance read is reserved, so earnings credited meanwhile
	// stay in the balance for the next payout.
	payout := database.ChainTransfer{
		Kind: transferPayout, ExecutorID: earning.ExecutorID, Amount: earning.CurrentBalance,
		Currency: earning.Currency, Receiver: earning.SuiWalletAddress,
	}
	_, err := p.sendTransfer(ctx, payout, func(queries *database.Queries) error {
		reserved, err := queries.ReservePayout(ctx, database.ReservePayoutParams{
			Amount: earning.CurrentBalance, ExecutorID: earning.ExecutorID, Currency: earning.Currency,
		})
		if err != nil {
			return fmt.Errorf("reserve payout: %w", err)
		}
		if reserved != 1 {
			return errPayoutNotReserved
		}
		return nil
	})
	return err
}
