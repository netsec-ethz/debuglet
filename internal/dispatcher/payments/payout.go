// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"database/sql"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"time"

	"go.uber.org/zap"
)

// Handler pays out one executor's earnings and reconciles outbound transfers
// whose outcome is not known yet.
type Handler interface {
	PayoutExecutor(database.Earning, context.Context) error
	ReconcileTransfers(ctx context.Context, limit int) error
}
type PayoutTicker struct {
	ticker    *time.Ticker
	reconcile *time.Ticker
	database  *sql.DB
	handler   Handler
	logger    *zap.Logger
}

// Reconciliation looks up at most reconcileLimit open transfers every
// reconcileInterval.
const (
	reconcileInterval = time.Minute
	reconcileLimit    = 100
)

func NextTickDuration() time.Duration {
	now := time.Now()
	//Ticks every day at midnight
	nextTick := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	if nextTick.Before(now) {
		nextTick = nextTick.Add(24 * time.Hour)
	}
	return nextTick.Sub(now)
}

func NewPayoutTicker(db *sql.DB, h Handler, logger *zap.Logger) *PayoutTicker {
	return &PayoutTicker{
		ticker:    time.NewTicker(NextTickDuration()),
		reconcile: time.NewTicker(reconcileInterval),
		database:  db,
		handler:   h,
		logger:    logger,
	}
}

// StartPayoutLoop pays executors on every payout tick and reconciles open
// transfers on every reconciliation tick until ctx is cancelled. On
// cancellation it stops both tickers and returns nil, mirroring the Sui
// listener, so PaymentHandler.Start can join both loops promptly instead of
// waiting for the next midnight.
func (pt *PayoutTicker) StartPayoutLoop(ctx context.Context) error {
	defer pt.ticker.Stop()
	defer pt.reconcile.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-pt.ticker.C:
			pt.logger.Info("Starting payout")
			pt.PayExecutors(ctx)
			pt.ticker.Reset(NextTickDuration())
		case <-pt.reconcile.C:
			if err := pt.handler.ReconcileTransfers(ctx, reconcileLimit); err != nil {
				pt.logger.Error("Failed to reconcile transfers", zap.String("error", err.Error()))
			}
		}
	}
}

// PayExecutors pays out every positive chain balance. A balance without a
// payout wallet is not paid out; how many there are is logged once per pass.
func (pt *PayoutTicker) PayExecutors(ctx context.Context) {
	queries := database.New(pt.database)
	earnings, err := queries.GetEarnings(ctx)
	if err != nil {
		pt.logger.Error("Failed to query earnings", zap.String("error", err.Error()))
		return
	}
	withoutWallet := 0
	for _, earning := range earnings {
		if ctx.Err() != nil {
			return
		}
		// TEST earnings are bookkeeping only and are never paid out.
		if earning.CurrentBalance <= 0 || !isChainCurrency(earning.Currency) {
			continue
		}
		if earning.SuiWalletAddress == "" {
			withoutWallet++
			continue
		}
		if err := pt.handler.PayoutExecutor(earning, ctx); err != nil {
			pt.logger.Error("Failed to Settle Earnings", zap.String("execID", earning.ExecutorID), zap.String("error", err.Error()))
		}
	}
	if withoutWallet > 0 {
		pt.logger.Warn("Earnings without a payout wallet were not paid out", zap.Int("balances", withoutWallet))
	}
}
