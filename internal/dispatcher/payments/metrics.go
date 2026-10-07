// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"database/sql"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

const metricsRowLimit = 10000

// SettlementMetrics is a read-only observation of durable payment obligations.
// Pending orders and transfers are separate stages, not amounts or proof of a
// chain outcome. Failed transfers require operator attention; they are not
// automatically retried. Counts include records retained while payments are
// disabled. Unavailable discards the entire observation, never a partial total.
type SettlementMetrics struct {
	Unavailable                     string
	PendingCredit, PendingRefund    int
	Reserved, Sent, Unknown, Failed int
}

// CollectMetrics reads bounded scalar rows in one SQLite snapshot without
// contacting a chain, starting settlement, or holding any runtime guard.
func (p *PaymentHandler) CollectMetrics(ctx context.Context) SettlementMetrics {
	if p == nil || p.db == nil {
		return SettlementMetrics{Unavailable: "unavailable"}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return SettlementMetrics{Unavailable: "storage"}
	}
	defer tx.Rollback()
	// Keep eligibility identical to ListPendingSettlements, the settlement
	// sweep's contract. Select only its decision, not payloads or credentials.
	rows, err := tx.QueryContext(ctx, `SELECT e.exit_code IS NOT NULL AND e.exit_code = 0
		FROM debuglet_order o JOIN debuglets d ON d.id = o.debuglet_id
		  AND d.transaction_id = o.transaction_id AND d.order_id = o.order_id
		LEFT JOIN measurement_execution e ON e.debuglet_id = d.id
		LEFT JOIN debuglet_cancellations c ON c.debuglet_id = d.id
		WHERE o.state = ? AND d.state = ?
		  AND (e.exit_code IS NOT NULL OR c.terminal_recorded_at IS NOT NULL)
		  AND NOT EXISTS (SELECT 1 FROM chain_transfers t
		    WHERE t.kind = 'refund' AND t.transaction_id = o.transaction_id
		      AND (t.order_id IS NULL OR t.order_id = o.order_id))
		LIMIT ?`, models.Outstanding, models.RunStateExited, metricsRowLimit+1)
	if err != nil {
		return SettlementMetrics{Unavailable: "storage"}
	}
	result := SettlementMetrics{}
	for rows.Next() {
		var credit bool
		if err := rows.Scan(&credit); err != nil {
			rows.Close()
			return SettlementMetrics{Unavailable: "storage"}
		}
		if credit {
			result.PendingCredit++
		} else {
			result.PendingRefund++
		}
		if result.PendingCredit+result.PendingRefund > metricsRowLimit {
			rows.Close()
			return SettlementMetrics{Unavailable: "limit"}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return SettlementMetrics{Unavailable: "storage"}
	}
	rows, err = tx.QueryContext(ctx, `SELECT substr(state, 1, 16) FROM chain_transfers
		WHERE state <> 'confirmed' LIMIT ?`, metricsRowLimit+1)
	if err != nil {
		return SettlementMetrics{Unavailable: "storage"}
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var state string
		if err := rows.Scan(&state); err != nil {
			return SettlementMetrics{Unavailable: "storage"}
		}
		count++
		if count > metricsRowLimit {
			return SettlementMetrics{Unavailable: "limit"}
		}
		switch state {
		case transferReserved:
			result.Reserved++
		case transferSent:
			result.Sent++
		case transferUnknown:
			result.Unknown++
		case transferFailed:
			result.Failed++
		default:
			return SettlementMetrics{Unavailable: "storage"}
		}
	}
	if rows.Err() != nil {
		return SettlementMetrics{Unavailable: "storage"}
	}
	return result
}
