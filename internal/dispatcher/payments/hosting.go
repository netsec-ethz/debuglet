// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
	"go.uber.org/zap"
)

// Hosting rewards are a daily approval-and-liveness snapshot, not an uptime
// attestation. Only an explicit operator subsidy receipt can fund an award.
func (p *PaymentHandler) AwardHosting(ctx context.Context, now time.Time) error {
	cfg := p.cfg.Sui
	if cfg.HostingRewardMIST == 0 {
		return nil
	}
	if cfg.HostingRewardMIST < 0 || cfg.HostingDailyCapMIST < cfg.HostingRewardMIST || cfg.HostingMaxNodesPerAccount < 1 || cfg.HostingMaxNodesPerAccount > 100 {
		return errors.New("invalid hosting award policy")
	}
	if err := p.requireChain("SUI", "award hosting"); err != nil {
		return err
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Acquire the writer lock before reading the shared subsidy and daily cap.
	if _, err = tx.ExecContext(ctx, `UPDATE prepaid_topups SET network=network WHERE purpose='hosting'`); err != nil {
		return err
	}
	var funded, awarded, today int64
	day := now.UTC().Format("2006-01-02")
	err = tx.QueryRowContext(ctx, `SELECT
 COALESCE((SELECT SUM(t.price) FROM prepaid_topups d JOIN transactions t ON t.id=d.transaction_id WHERE d.purpose='hosting' AND d.network=? AND d.coin_type=? AND t.status=?),0),
 COALESCE((SELECT SUM(amount) FROM hosting_awards WHERE network=?),0)+COALESCE((SELECT SUM(amount) FROM native_gas_reservations WHERE network=?),0),
 COALESCE((SELECT SUM(amount) FROM hosting_awards WHERE network=? AND day=?),0)`, cfg.Network, sui.GetCoinType("SUI", cfg.Network), models.Paid, cfg.Network, cfg.Network, cfg.Network, day).Scan(&funded, &awarded, &today)
	if err != nil {
		return err
	}
	if funded < 0 || awarded < 0 || today < 0 {
		return errors.New("invalid hosting award history")
	}
	remaining := funded - awarded
	if cap := cfg.HostingDailyCapMIST - today; cap < remaining {
		remaining = cap
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT u.uuid FROM users u JOIN hosting_approvals a ON a.user_id=u.id ORDER BY u.uuid`)
	if err != nil {
		return err
	}
	var owners []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		owners = append(owners, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	q := database.New(tx)
	for _, owner := range owners {
		if remaining < cfg.HostingRewardMIST {
			break
		}
		ids, err := EligibleHostingExecutors(ctx, tx, owner, now)
		if err != nil {
			return err
		}
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM hosting_awards a JOIN users u ON u.id=a.user_id WHERE u.uuid=? AND a.day=?`, owner, day).Scan(&count); err != nil {
			return err
		}
		for _, id := range ids {
			if count >= cfg.HostingMaxNodesPerAccount || remaining < cfg.HostingRewardMIST {
				break
			}
			var wallet string
			err = tx.QueryRowContext(ctx, `SELECT sui_wallet_address FROM earnings WHERE executor_id=? AND currency='SUI'`, id.String()).Scan(&wallet)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if sui.ValidAddress(wallet) != nil {
				continue
			}
			result, err := tx.ExecContext(ctx, `INSERT INTO hosting_awards(executor_id,day,user_id,amount,network) SELECT ?,?,id,?,? FROM users WHERE uuid=? ON CONFLICT(executor_id,day) DO NOTHING`, id.String(), day, cfg.HostingRewardMIST, cfg.Network, owner)
			if err != nil {
				return err
			}
			n, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if n == 0 {
				continue
			}
			if err = p.CreateEarningsIfNotExists(id.String(), "SUI", "", q, ctx); err != nil {
				return err
			}
			if err = q.AddEarnings(ctx, database.AddEarningsParams{Amount: cfg.HostingRewardMIST, ExecutorID: id.String(), Currency: "SUI"}); err != nil {
				return err
			}
			remaining -= cfg.HostingRewardMIST
			count++
		}
	}
	return tx.Commit()
}

func (p *PaymentHandler) hostingAwardLoop(ctx context.Context) error {
	if p.cfg.Sui.HostingRewardMIST == 0 {
		return nil
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if err := p.AwardHosting(ctx, time.Now()); err != nil && ctx.Err() == nil {
			p.logger.Error("Hosting award failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Reserve the full signed gas ceiling. Actual gas can be smaller, but retaining
// the ceiling keeps failures/restarts safe without inventing a second settlement
// mechanism. Operator subsidy top-ups cover both awards and native transfer gas.
func (p *PaymentHandler) reserveNativeGas(ctx context.Context, db database.DBTX, transferID, budget int64) error {
	var available int64
	err := db.QueryRowContext(ctx, `SELECT
 COALESCE((SELECT SUM(t.price) FROM prepaid_topups d JOIN transactions t ON t.id=d.transaction_id WHERE d.purpose='hosting' AND d.network=? AND d.coin_type=? AND t.status=?),0)
 - COALESCE((SELECT SUM(amount) FROM hosting_awards WHERE network=?),0)
 - COALESCE((SELECT SUM(amount) FROM native_gas_reservations WHERE network=?),0)`, p.cfg.Sui.Network, sui.GetCoinType("SUI", p.cfg.Sui.Network), models.Paid, p.cfg.Sui.Network, p.cfg.Sui.Network).Scan(&available)
	if err != nil {
		return err
	}
	if available < budget {
		return errors.New("operator subsidy does not cover native transfer gas; customer funds are reserved")
	}
	_, err = db.ExecContext(ctx, `INSERT INTO native_gas_reservations(transfer_id,amount,network) VALUES(?,?,?)`, transferID, budget, p.cfg.Sui.Network)
	return err
}

// Once this Testnet wallet has accepted native custody, every transfer's SUI
// gas (including USDC transfers) must be funded separately from that principal.
func (p *PaymentHandler) nativeCustody(ctx context.Context, db database.DBTX) (bool, error) {
	if p.cfg.Sui.Network != "testnet" {
		return false, nil
	}
	var active bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM transactions WHERE currency='SUI')`).Scan(&active)
	return active, err
}
