// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"math"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

func TestRefundRejectsInvalidStoredAmountsBeforeEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prices []int64
		want   string
	}{
		{"empty orders", nil, "has no orders to refund"},
		{"negative order", []int64{-1}, "amount must not be negative"},
		{"negative offset by positive", []int64{2, -1}, "amount must not be negative"},
		{"total wraps negative", []int64{math.MaxInt64, 1}, "total amount exceeds the supported range"},
		{"total wraps positive", []int64{math.MaxInt64, math.MaxInt64, 3}, "total amount exceeds the supported range"},
	} {
		for _, unadmittedOnly := range []bool{false, true} {
			name := tc.name + "/transaction"
			if unadmittedOnly {
				name = tc.name + "/unadmitted"
			}
			t.Run(name, func(t *testing.T) {
				db, h, chain := transferFixture(t)
				seedUSDCTransaction(t, db, tc.prices...)
				before := dumpAll(t, db)
				var err error
				if unadmittedOnly {
					_, err = h.RefundUnadmittedTransaction(testTxID, t.Context())
				} else {
					err = h.RefundTransaction(testTxID, t.Context())
				}
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("refund error = %v, want %q", err, tc.want)
				}
				if calls := chain.Calls(); len(calls) != 0 {
					t.Fatalf("invalid stored amount reached the chain: %v", calls)
				}
				var seq int64
				var name, path string
				if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := sqlitedb.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
				if after := dumpAll(t, reopened); after != before {
					t.Fatalf("rejected refund changed persistent state\nbefore:\n%s\nafter:\n%s", before, after)
				}
			})
		}
	}
}

func TestRefundStoredAmountBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prices []int64
		want   int64
	}{
		{"zero", []int64{0, 0}, 0},
		{"maximum", []int64{math.MaxInt64 - 1, 1}, math.MaxInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, h, chain := transferFixture(t)
			seedUSDCTransaction(t, db, tc.prices...)
			if err := h.RefundTransaction(testTxID, t.Context()); err != nil {
				t.Fatal(err)
			}
			status, orders, settlements := refundState(t, db)
			if status != models.Refunded || settlements != len(tc.prices) {
				t.Fatalf("refund state = %v, %d settlements", status, settlements)
			}
			for _, state := range orders {
				if state != models.Refunded {
					t.Fatalf("order state = %v, want Refunded", state)
				}
			}
			if tc.want == 0 {
				if calls := chain.Calls(); len(calls) != 0 || len(transferRows(t, db)) != 0 {
					t.Fatalf("zero refund reached the chain or created a transfer: %v", calls)
				}
			} else if row := onlyTransfer(t, db); row.Amount != tc.want || row.State != transferSent || chain.transferAmount != uint64(tc.want) {
				t.Fatalf("refund transfer = %+v, prepared amount %d", row, chain.transferAmount)
			}
		})
	}
}
