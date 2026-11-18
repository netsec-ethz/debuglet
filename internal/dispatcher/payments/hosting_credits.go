// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
)

// HostingObservation comes only from the dispatcher's authenticated live
// registry. Seen is the server's heartbeat receipt time, not an executor clock.
type HostingObservation struct {
	ExecutorID, Fingerprint string
	Binding                 controlsession.Binding
	Seen                    time.Time
}

type hostingCursor struct {
	executor                          string
	user                              int64
	incarnation, session, fingerprint string
	at, seconds, credited, remainder  int64
}

// ApplyHostingObservations is called by the existing minute maintenance pass.
// A new session starts an observation interval; it never proves earlier uptime.
// Missing/revoked approvals, stale heartbeats and gaps over two minutes close
// the interval. Credit, fractional remainder and cursor commit atomically.
func (p *PaymentHandler) ApplyHostingObservations(ctx context.Context, now time.Time, observations []HostingObservation) error {
	cfg := p.cfg.Allowance
	if !cfg.Automatic() || cfg.BalanceCap == 0 {
		return nil
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	issuer, err := uuid.Parse(cfg.PolicyIssuer)
	if err != nil {
		return err
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Serialize with credit issuance and reservation before reading balances.
	if _, err = tx.ExecContext(ctx, `UPDATE allowance_hosting SET observed_at=observed_at WHERE 0`); err != nil {
		return err
	}
	accounts, err := creditAccounts(ctx, tx)
	if err != nil {
		return err
	}
	for _, account := range accounts {
		if _, err = p.applyAllowancePolicyIn(ctx, tx, account, now); err != nil {
			return err
		}
	}
	cursors, err := hostingCursors(ctx, tx)
	if err != nil {
		return err
	}
	processed := make(map[string]bool)
	for _, observation := range observations {
		seen := observation.Seen.Unix()
		if !observation.Binding.Valid() || observation.ExecutorID == "" || observation.Fingerprint == "" || seen <= 0 || seen > now.Unix() || now.Unix()-seen > 120 {
			continue
		}
		var owner uuid.UUID
		var uid int64
		err = tx.QueryRowContext(ctx, `SELECT u.uuid,u.id FROM owned_executors o
 JOIN users u ON u.id=o.user_id
 JOIN hosting_approvals a ON a.executor_id=o.executor_id AND a.user_id=o.user_id
 JOIN executor_enrollments e ON e.executor_id=o.executor_id AND e.fingerprint=?
 WHERE o.executor_id=?`, observation.Fingerprint, observation.ExecutorID).Scan(&owner, &uid)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		key := fmt.Sprintf("%s:%d", observation.ExecutorID, uid)
		if processed[key] {
			continue
		}
		processed[key] = true
		cursor, exists := cursors[key]
		if !exists {
			cursor = hostingCursor{executor: observation.ExecutorID, user: uid}
		}
		var seconds int64
		sameSession := cursor.incarnation == observation.Binding.Incarnation && cursor.session == observation.Binding.SessionID && cursor.fingerprint == observation.Fingerprint
		if sameSession && seen < cursor.at {
			delete(cursors, key)
			continue
		}
		if sameSession && cursor.at > 0 && seen-cursor.at <= 120 {
			seconds = seen - cursor.at
		}
		// Decompose the multiplication: a bounded observation cannot overflow
		// even when the configured hourly rate is near the int64 limit.
		whole := cfg.HostingHourlyRate / 3600 * seconds
		fraction := cfg.HostingHourlyRate%3600*seconds + cursor.remainder
		requested := whole + fraction/3600
		remainder := fraction % 3600
		grantKey := fmt.Sprintf("hosting:%s:%s:%s:%d", observation.ExecutorID, observation.Binding.Incarnation, observation.Binding.SessionID, seen)
		credited, err := p.grantManagedCreditIn(ctx, tx, owner, issuer, requested, "executor hosting", grantKey, now)
		if err != nil {
			return err
		}
		if credited < requested {
			remainder = 0
		}
		if remainder != 0 {
			balance, err := readAllowance(ctx, database.New(tx), owner)
			if err != nil {
				return err
			}
			if balance.Granted-balance.Consumed >= cfg.BalanceCap {
				remainder = 0
			}
		}
		if cursor.seconds > math.MaxInt64-seconds || cursor.credited > math.MaxInt64-credited {
			return errors.New("hosting credit history overflows")
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO allowance_hosting(executor_id,user_id,incarnation,session_id,fingerprint,observed_at,observed_seconds,credited,remainder)
 VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(executor_id,user_id) DO UPDATE SET
 incarnation=excluded.incarnation,session_id=excluded.session_id,fingerprint=excluded.fingerprint,observed_at=excluded.observed_at,
 observed_seconds=excluded.observed_seconds,credited=excluded.credited,remainder=excluded.remainder`, observation.ExecutorID, uid,
			observation.Binding.Incarnation, observation.Binding.SessionID, observation.Fingerprint, seen, cursor.seconds+seconds, cursor.credited+credited, remainder)
		if err != nil {
			return err
		}
		delete(cursors, key)
	}
	// Preserve earned history but do not join observations across an absence.
	for _, cursor := range cursors {
		if _, err = tx.ExecContext(ctx, `UPDATE allowance_hosting SET incarnation='',session_id='',fingerprint='',observed_at=0 WHERE executor_id=? AND user_id=?`, cursor.executor, cursor.user); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func creditAccounts(ctx context.Context, db database.DBTX) ([]uuid.UUID, error) {
	rows, err := db.QueryContext(ctx, `SELECT uuid FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		accounts = append(accounts, id)
	}
	return accounts, rows.Err()
}

func hostingCursors(ctx context.Context, db database.DBTX) (map[string]hostingCursor, error) {
	rows, err := db.QueryContext(ctx, `SELECT executor_id,user_id,incarnation,session_id,fingerprint,observed_at,observed_seconds,credited,remainder FROM allowance_hosting`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cursors := make(map[string]hostingCursor)
	for rows.Next() {
		var cursor hostingCursor
		if err := rows.Scan(&cursor.executor, &cursor.user, &cursor.incarnation, &cursor.session, &cursor.fingerprint, &cursor.at, &cursor.seconds, &cursor.credited, &cursor.remainder); err != nil {
			return nil, err
		}
		cursors[fmt.Sprintf("%s:%d", cursor.executor, cursor.user)] = cursor
	}
	return cursors, rows.Err()
}
