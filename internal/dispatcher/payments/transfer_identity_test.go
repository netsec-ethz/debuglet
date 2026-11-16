// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/block-vision/sui-go-sdk/utils"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

// The normal fixture makes every preparation unique. A real chain builder
// produces identical bytes for equal transfers using the same coin version.
type sameCoinTransferChain struct {
	*rehearsalChain
	prepared *sui.PreparedTransfer
	barrier  *sync.WaitGroup
}

func (c *sameCoinTransferChain) PrepareTransfer(context.Context, uint64, string, string) (*sui.PreparedTransfer, error) {
	c.record("PrepareTransfer")
	prepared := c.prepared
	if c.barrier != nil {
		c.barrier.Done()
		c.barrier.Wait()
	}
	return prepared, nil
}

func identityPrepared(t *testing.T, coinVersion string) *sui.PreparedTransfer {
	t.Helper()
	data := []byte("equal transfer using coin version " + coinVersion)
	digest, err := utils.GetTxDigestFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	p, err := sui.RestorePreparedTransfer(digest, data, "retained signature")
	if err != nil {
		t.Fatal(err)
	}
	p.GasBudgetMIST = 3
	return p
}

func identityConnection(t *testing.T, db *sql.DB) *sql.DB {
	t.Helper()
	var seq int64
	var name, path string
	if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	other, err := sqlitedb.Open(path, sqlitedb.BusyTimeout(5000))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close() })
	return other
}

func TestConcurrentEqualRefundsCannotShareTransferIdentity(t *testing.T) {
	for _, currency := range []string{"SUI", "USDC"} {
		t.Run(currency, func(t *testing.T) {
			f := newCommunityPaymentFixture(t)
			applyReceipt(t, f.handler, personalTopUp(t, f, "gas", "hosting", 6))
			r := &rehearsal{t: t, db: f.db, h: f.handler, chain: f.chain, cfg: f.handler.cfg}
			const txID = "equal-refund-orders"
			if err := r.intent(txID, currency, 3, 3); err != nil {
				t.Fatal(err)
			}
			receipt := r.receipt("paid-refunds", txID, 6, 1)
			receipt.CoinType = sui.GetCoinType(currency, "testnet")
			r.applyReceipt(receipt, sui.ReceiptApplied)
			first, second := r.mustAdmit(txID, 1), r.mustAdmit(txID, 2)
			r.terminate(first, 2)
			r.terminate(second, 2)
			barrier := &sync.WaitGroup{}
			barrier.Add(2)
			chain := &sameCoinTransferChain{rehearsalChain: f.chain, prepared: identityPrepared(t, "1"), barrier: barrier}
			f.handler.sui = chain
			other := identityConnection(t, f.db)
			h2, _ := newEnabledHandler(t, other, f.handler.cfg)
			h2.sui = chain
			errs := raceCalls([]func() error{
				func() error { return f.handler.SettleTerminalOrder(t.Context(), &first, 2) },
				func() error { return h2.SettleTerminalOrder(t.Context(), &second, 2) },
			})
			accepted, deferred := 0, 0
			for _, err := range errs {
				switch {
				case err == nil:
					accepted++
				case errors.Is(err, errTransferDigestReserved):
					deferred++
				default:
					t.Fatal(err)
				}
			}
			if accepted != 1 || deferred != 1 || len(chain.Executed()) != 1 || len(transferRows(t, f.db)) != 1 {
				t.Fatalf("accepted=%d deferred=%d broadcasts=%d transfers=%d", accepted, deferred, len(chain.Executed()), len(transferRows(t, f.db)))
			}
			var outstanding, settlements, gas int64
			if err := f.db.QueryRow(`SELECT count(*) FROM debuglet_order WHERE transaction_id=? AND state=?`, txID, models.Outstanding).Scan(&outstanding); err != nil {
				t.Fatal(err)
			}
			if err := f.db.QueryRow(`SELECT count(*) FROM order_settlements WHERE transaction_id=?`, txID).Scan(&settlements); err != nil {
				t.Fatal(err)
			}
			if err := f.db.QueryRow(`SELECT SUM(amount) FROM native_gas_reservations`).Scan(&gas); err != nil {
				t.Fatal(err)
			}
			if outstanding != 1 || settlements != 1 || gas != 3 {
				t.Fatalf("collision consumed another obligation: outstanding=%d settlements=%d gas=%d", outstanding, settlements, gas)
			}
			// Restart with the durable database. Re-preparing the same transaction
			// still cannot settle the other order, even after the first was sent.
			chain.barrier = nil
			restarted, _ := newEnabledHandler(t, identityConnection(t, f.db), f.handler.cfg)
			restarted.sui = chain
			if settled, failed, _, _, err := restarted.SettlePendingOrders(t.Context(), 0, 10); settled != 0 || failed != 1 || !errors.Is(err, errTransferDigestReserved) {
				t.Fatalf("restart reused digest: settled=%d failed=%d err=%v", settled, failed, err)
			}
			// Once the first transfer changes its coin version, the existing sweep
			// can build a different transaction and discharge the second obligation.
			chain.prepared = identityPrepared(t, "2")
			if settled, failed, _, _, err := restarted.SettlePendingOrders(t.Context(), 0, 10); settled != 1 || failed != 0 || err != nil {
				t.Fatalf("fresh digest: settled=%d failed=%d err=%v", settled, failed, err)
			}
			rows := transferRows(t, f.db)
			if len(rows) != 2 || rows[0].Digest == rows[1].Digest || len(chain.Executed()) != 2 {
				t.Fatal("the two refunds did not receive distinct chain identities")
			}
			if settled, failed, _, _, err := restarted.SettlePendingOrders(t.Context(), 0, 10); settled != 0 || failed != 0 || err != nil || len(chain.Executed()) != 2 {
				t.Fatalf("repeat sweep duplicated refund: %d %d %v", settled, failed, err)
			}
			if err := f.db.QueryRow(`SELECT SUM(amount) FROM native_gas_reservations`).Scan(&gas); err != nil || gas != 6 {
				t.Fatalf("gas=%d err=%v", gas, err)
			}
		})
	}
}
