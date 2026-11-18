// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
)

var ErrInvalidHostingApproval = errors.New("approved executors must be distinct and owned by the account")

// EligibleHostingExecutors returns operator-approved owned nodes with a fresh
// connected heartbeat. This is a snapshot, not evidence of a full day's uptime.
// Keeping the approved owner in the join prevents approval surviving a transfer.
func EligibleHostingExecutors(ctx context.Context, db database.DBTX, account uuid.UUID, now time.Time) ([]uuid.UUID, error) {
	rows, err := db.QueryContext(ctx, `SELECT o.executor_id FROM owned_executors o
 JOIN users u ON u.id=o.user_id
 JOIN hosting_approvals a ON a.executor_id=o.executor_id AND a.user_id=o.user_id
 JOIN probe_status p ON p.executor_id=o.executor_id
 WHERE u.uuid=? AND p.connected=1 AND p.last_connected BETWEEN ? AND ?
 ORDER BY o.executor_id`, account, now.Unix()-120, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]uuid.UUID, 0)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// SetAllowanceEligibility replaces explicit operator approval. Prior daily
// decisions and credit reservations are deliberately left intact.
func (p *PaymentHandler) SetAllowanceEligibility(ctx context.Context, account, operator uuid.UUID, researcher bool, ids []uuid.UUID) error {
	if len(ids) > 100 {
		return ErrInvalidHostingApproval
	}
	seen := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		if id == uuid.Nil || seen[id] {
			return ErrInvalidHostingApproval
		}
		seen[id] = true
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO allowance_eligibility(user_id,researcher,approved_by,updated_at)
 SELECT u.id,?,o.id,? FROM users u JOIN users o ON o.uuid=? AND o.role='operator' WHERE u.uuid=?
 ON CONFLICT(user_id) DO UPDATE SET researcher=excluded.researcher,approved_by=excluded.approved_by,updated_at=excluded.updated_at`, researcher, time.Now().Unix(), operator, account)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrUnknownAccount
	}
	// Keep unchanged approvals: a settings update must not interrupt already
	// observed hosting. Removing approval closes its interval immediately.
	rows, err := tx.QueryContext(ctx, `SELECT executor_id FROM hosting_approvals WHERE user_id=(SELECT id FROM users WHERE uuid=?)`, account)
	if err != nil {
		return err
	}
	var removed []string
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		if !seen[id] {
			removed = append(removed, id.String())
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range removed {
		if _, err = tx.ExecContext(ctx, `DELETE FROM hosting_approvals WHERE executor_id=? AND user_id=(SELECT id FROM users WHERE uuid=?)`, id, account); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE allowance_hosting SET incarnation='',session_id='',fingerprint='',observed_at=0 WHERE executor_id=? AND user_id=(SELECT id FROM users WHERE uuid=?)`, id, account); err != nil {
			return err
		}
	}
	for _, id := range ids {
		result, err = tx.ExecContext(ctx, `INSERT INTO hosting_approvals(executor_id,user_id,approved_by,updated_at)
 SELECT e.executor_id,e.user_id,o.id,? FROM owned_executors e JOIN users u ON u.id=e.user_id
 JOIN users o ON o.uuid=? WHERE u.uuid=? AND e.executor_id=?
 ON CONFLICT(executor_id) DO UPDATE SET
 approved_by=CASE WHEN hosting_approvals.user_id=excluded.user_id THEN hosting_approvals.approved_by ELSE excluded.approved_by END,
 updated_at=CASE WHEN hosting_approvals.user_id=excluded.user_id THEN hosting_approvals.updated_at ELSE excluded.updated_at END,
 user_id=excluded.user_id`, time.Now().Unix(), operator, account, id.String())
		if err != nil {
			return err
		}
		n, err = result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrInvalidHostingApproval
		}
	}
	return tx.Commit()
}
