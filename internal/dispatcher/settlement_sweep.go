// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"time"

	"github.com/netsec-ethz/debuglet/internal/daemonlog"
	"go.uber.org/zap"
)

const (
	settlementSweepInterval = 30 * time.Second
	settlementSweepBound    = 5 * time.Second
	settlementSweepLimit    = 32
)

// sweepPendingSettlements delivers the payment decision of terminal runs whose
// order is still Outstanding, for example because the settlement after the
// terminal report failed. The terminal row and its recorded exit code are the
// request and settlement is idempotent per order, so an order settled by the
// terminal path meanwhile is left as it is. Each pass attempts at most
// settlementSweepLimit orders, continuing after the last run the previous pass
// attempted and starting over once the listing is exhausted. A chain refund is
// sent from here only while no refund transfer covers the order; one that
// exists, whatever its outcome, is resolved by transfer reconciliation.
func (d *Dispatcher) sweepPendingSettlements(last time.Time) time.Time {
	now := d.now()
	if !last.IsZero() && now.Sub(last) < settlementSweepInterval {
		return last
	}
	d.mu.RLock()
	closed := d.closed
	d.mu.RUnlock()
	if closed || d.Payment == nil {
		return last
	}
	ctx, cancel := context.WithTimeout(context.Background(), settlementSweepBound)
	defer cancel()
	settled, failed, _, next, err := d.Payment.SettlePendingOrders(ctx, d.settlementAfter, settlementSweepLimit)
	d.settlementAfter = next
	if err != nil {
		d.logger.Warn("Pending order settlements remain", zap.Int("settled", settled), zap.Int("failed", failed))
		d.logger.Debug("Private runtime diagnostic", zap.String("error", daemonlog.Diagnostic(err)))
	}
	return now
}
