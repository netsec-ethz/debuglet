// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"database/sql"
	"debuglet/internal/dispatcher/database"
	"time"

	"go.uber.org/zap"
)

type Handler interface {
	PayoutExecutor(database.Earning, context.Context) error
}
type PayoutTicker struct {
	ticker   *time.Ticker
	database *sql.DB
	handler  Handler
	logger   *zap.Logger
}

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
		ticker:   time.NewTicker(NextTickDuration()),
		database: db,
		handler:  h,
		logger:   logger,
	}
}

func (pt *PayoutTicker) StartPayoutLoop(ctx context.Context) error {

	for {
		<-pt.ticker.C
		pt.logger.Info("Starting payout")
		pt.PayExecutors(ctx)
		pt.ticker.Reset(NextTickDuration())
	}
}

func (pt *PayoutTicker) PayExecutors(ctx context.Context) {
	queries := database.New(pt.database)
	earnings, err := queries.GetEarnings(ctx)
	if err != nil {
		pt.logger.Error("Failed to query earnings", zap.String("error", err.Error()))
		return
	}
	for _, earning := range earnings {
		err := pt.handler.PayoutExecutor(earning, ctx)
		if err == nil {
			queries.SettleEarning(ctx, database.SettleEarningParams{
				ExecutorID: earning.ExecutorID,
				Currency:   earning.Currency,
			})
		} else {
			pt.logger.Error("Failed to Settle Earnings", zap.String("execID", earning.ExecutorID), zap.String("error", err.Error()))
		}
	}
}
