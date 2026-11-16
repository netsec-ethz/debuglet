// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"errors"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
)

func TestHostingAwardsRequireEarmarkedFundingAndRespectCaps(t *testing.T) {
	f := newCommunityPaymentFixture(t)
	now := time.Now().UTC()
	f.handler.cfg.Sui.HostingRewardMIST = 4
	f.handler.cfg.Sui.HostingDailyCapMIST = 8
	f.handler.cfg.Sui.HostingMaxNodesPerAccount = 1
	owners := []database.User{f.owner, f.member}
	for _, owner := range owners {
		for range 2 {
			id := uuid.NewString()
			if _, err := f.db.Exec(`INSERT INTO owned_executors(executor_id,user_id,name,created_at) VALUES(?,?,'node',?)`, id, owner.ID, now); err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.Exec(`INSERT INTO hosting_approvals(executor_id,user_id,approved_by,updated_at) VALUES(?,?,?,?)`, id, owner.ID, f.owner.ID, now.Unix()); err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.Exec(`INSERT INTO probe_status(executor_id,connected,first_connected,last_connected,status_since,total_uptime,is_public,host_tags,version) VALUES(?,1,?,?,?,0,1,'[]','test')`, id, now.Unix(), now.Unix(), now.Unix()); err != nil {
				t.Fatal(err)
			}
			if err := f.handler.CreateEarningsIfNotExists(id, "SUI", testRefund, database.New(f.db), t.Context()); err != nil {
				t.Fatal(err)
			}
		}
	}
	count := func(want int) {
		t.Helper()
		var got int
		if err := f.db.QueryRow(`SELECT count(*) FROM hosting_awards`).Scan(&got); err != nil || got != want {
			t.Fatalf("awards %d want %d: %v", got, want, err)
		}
	}
	applyReceipt(t, f.handler, personalTopUp(t, f, "customer", "personal", 100))
	if err := f.handler.AwardHosting(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	count(0)
	subsidy := personalTopUp(t, f, "subsidy", "hosting", 20)
	if err := f.handler.AwardHosting(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	count(0)
	applyReceipt(t, f.handler, subsidy)
	for range 2 {
		if err := f.handler.AwardHosting(t.Context(), now); err != nil {
			t.Fatal(err)
		}
	}
	count(2)
	h, _ := newEnabledHandler(t, f.db, f.handler.cfg)
	h.sui = f.chain
	f.handler = h
	if err := h.AwardHosting(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	count(2)
	var income int64
	if err := f.db.QueryRow(`SELECT SUM(current_balance) FROM earnings WHERE currency='SUI'`).Scan(&income); err != nil || income != 8 {
		t.Fatalf("income %d: %v", income, err)
	}
	assertPersonal(t, f, CommunityBudget{Funded: 100, Available: 100})
	tomorrow := now.Add(24 * time.Hour)
	// Stale heartbeats earn nothing on another day.
	if err := h.AwardHosting(t.Context(), tomorrow); err != nil {
		t.Fatal(err)
	}
	count(2)
	for day := 1; day <= 3; day++ {
		when := now.Add(time.Duration(day) * 24 * time.Hour)
		if _, err := f.db.Exec(`UPDATE probe_status SET last_connected=?`, when.Unix()); err != nil {
			t.Fatal(err)
		}
		if err := h.AwardHosting(t.Context(), when); err != nil {
			t.Fatal(err)
		}
	}
	count(5) // Five 4-MIST awards consume exactly the 20-MIST subsidy.
	var spent int64
	if err := f.db.QueryRow(`SELECT SUM(amount) FROM hosting_awards`).Scan(&spent); err != nil || spent != 20 {
		t.Fatalf("subsidy spend %d: %v", spent, err)
	}
}

func TestNativeGasCannotSpendCustomerPrincipal(t *testing.T) {
	f := newCommunityPaymentFixture(t)
	applyReceipt(t, f.handler, personalTopUp(t, f, "customer", "personal", 100))
	applyReceipt(t, f.handler, personalTopUp(t, f, "awards", "hosting", 10))
	q := database.New(f.db)
	if err := f.handler.CreateEarningsIfNotExists("host", "SUI", testRefund, q, t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := q.AddEarnings(t.Context(), database.AddEarningsParams{ExecutorID: "host", Currency: "SUI", Amount: 10}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO hosting_awards(executor_id,day,user_id,amount,network) VALUES('host','2026-11-16',?,10,'testnet')`, f.owner.ID); err != nil {
		t.Fatal(err)
	}
	earning, err := q.GetEarningsIn(t.Context(), database.GetEarningsInParams{ExecutorID: "host", Currency: "SUI"})
	if err != nil {
		t.Fatal(err)
	}
	f.chain.gasBudget = 3
	if err := f.handler.PayoutExecutor(earning, t.Context()); err == nil {
		t.Fatal("customer principal used as gas")
	}
	if len(f.chain.Executed()) != 0 {
		t.Fatal("unfunded gas was broadcast")
	}
	if len(transferRows(t, f.db)) != 0 {
		t.Fatal("unfunded payout decision committed")
	}
	applyReceipt(t, f.handler, personalTopUp(t, f, "gas", "hosting", 3))
	f.chain.executeErrs = []error{errors.New("connection lost")}
	if err := f.handler.PayoutExecutor(earning, t.Context()); err != nil {
		t.Fatal(err)
	}
	h, _ := newEnabledHandler(t, f.db, f.handler.cfg)
	h.sui = f.chain
	f.handler = h
	if err := h.PayoutExecutor(earning, t.Context()); err == nil {
		t.Fatal("uncertain payout paid twice")
	}
	f.chain.lookups = []lookupResult{{outcome: sui.TransferConfirmed, verified: true}}
	if err := h.ReconcileTransfers(t.Context(), 10); err != nil {
		t.Fatal(err)
	}
	var gas int64
	if err := f.db.QueryRow(`SELECT SUM(amount) FROM native_gas_reservations`).Scan(&gas); err != nil || gas != 3 {
		t.Fatalf("gas reservation %d: %v", gas, err)
	}
	if len(f.chain.Executed()) != 1 {
		t.Fatal("recovery sent another payout")
	}
	assertPersonal(t, f, CommunityBudget{Funded: 100, Available: 100})
}

func TestUSDCPayoutGasAlsoProtectsNativeCustody(t *testing.T) {
	f := newCommunityPaymentFixture(t)
	applyReceipt(t, f.handler, personalTopUp(t, f, "customer", "personal", 100))
	earning := seedEarning(t, f.db, "usdc-host", 7, testRefund)
	f.chain.gasBudget = 3
	if err := f.handler.PayoutExecutor(earning, t.Context()); err == nil {
		t.Fatal("USDC payout spent native customer principal as gas")
	}
	if len(f.chain.Executed()) != 0 {
		t.Fatal("unfunded USDC payout broadcast")
	}
	applyReceipt(t, f.handler, personalTopUp(t, f, "gas", "hosting", 3))
	if err := f.handler.PayoutExecutor(earning, t.Context()); err != nil {
		t.Fatal(err)
	}
	assertPersonal(t, f, CommunityBudget{Funded: 100, Available: 100})
	var gas int64
	if err := f.db.QueryRow(`SELECT SUM(amount) FROM native_gas_reservations`).Scan(&gas); err != nil || gas != 3 {
		t.Fatalf("gas %d: %v", gas, err)
	}
}
