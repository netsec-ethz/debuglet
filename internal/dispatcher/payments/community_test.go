// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

type communityPaymentFixture struct {
	db                 *sql.DB
	handler            *PaymentHandler
	chain              *rehearsalChain
	owner, member      database.User
	community, project string
}

func newCommunityPaymentFixture(t *testing.T) communityPaymentFixture {
	t.Helper()
	db := newRefundDatabase(t)
	h, _ := newEnabledHandler(t, db, enabledConfig(t))
	chain := &rehearsalChain{transferChain: &transferChain{fakeChain: newFakeChain()}}
	h.sui = chain
	q := database.New(db)
	var users [2]database.User
	for i, name := range []string{"owner", "member"} {
		var err error
		users[i], err = q.CreateUser(t.Context(), database.CreateUserParams{Uuid: uuid.New(), Name: name})
		if err != nil {
			t.Fatal(err)
		}
	}
	f := communityPaymentFixture{db: db, handler: h, chain: chain, owner: users[0], member: users[1], community: uuid.NewString(), project: uuid.NewString()}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO communities(id,name,description,created_by,created_at)
VALUES(?, 'Research group', '', ?, ?)`, f.community, f.owner.ID, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	for _, user := range users {
		if _, err := db.ExecContext(t.Context(), `INSERT INTO community_members(community_id,user_id,joined_at) VALUES(?,?,?)`,
			f.community, user.ID, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO community_projects(id,community_id,name,description,created_by,created_at)
VALUES(?, ?, 'Measurements', '', ?, ?)`, f.project, f.community, f.owner.ID, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f communityPaymentFixture) topUp(t *testing.T, amount int64) sui.PaymentReceipt {
	t.Helper()
	tx, err := f.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	id := uuid.NewString()
	if _, err := f.handler.CreateCommunityTopUpIn(tx, f.owner.Uuid, f.community, id, amount, testRefund, t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	r := validReceipt(uuid.NewString())
	r.Nonce, r.Amount = id, uint64(amount)
	return r
}

func (f communityPaymentFixture) fund(t *testing.T, amount int64) {
	t.Helper()
	if got := applyReceipt(t, f.handler, f.topUp(t, amount)); got != sui.ReceiptApplied {
		t.Fatalf("funding receipt: %s", got)
	}
}

func (f communityPaymentFixture) reserve(t *testing.T, db *sql.DB, id string, price int64) error {
	t.Helper()
	return f.reserveCurrency(t, db, id, price, "USDC")
}

func (f communityPaymentFixture) reserveCurrency(t *testing.T, db *sql.DB, id string, price int64, currency string) error {
	t.Helper()
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := f.handler.CreateCommunityIntentIn(tx, f.member.Uuid, f.project, id, price, currency, testHash, t.Context()); err != nil {
		return err
	}
	q := database.New(tx)
	if _, err := q.CreateDebugletOrder(t.Context(), database.CreateDebugletOrderParams{
		TransactionID: id, OrderID: testOrderID, ExecutorID: testExecutor, Price: price,
		Currency: currency, RefundAddress: testRefund, State: int64(models.Outstanding),
	}); err != nil {
		return err
	}
	if err := q.SetTransactionOwner(t.Context(), database.SetTransactionOwnerParams{TransactionID: id, Uuid: f.member.Uuid}); err != nil {
		return err
	}
	return tx.Commit()
}

func (f communityPaymentFixture) assertBudget(t *testing.T, want CommunityBudget) {
	t.Helper()
	got, err := f.handler.CommunityBalance(t.Context(), f.db, f.community, "USDC")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("community budget %+v, want %+v", got, want)
	}
}

func TestCommunityTopUpUsesVerifiedReceiptOnce(t *testing.T) {
	f := newCommunityPaymentFixture(t)
	r := f.topUp(t, 10)
	f.assertBudget(t, CommunityBudget{})
	wrong := r
	wrong.Digest, wrong.Amount = "wrong-amount", 11
	if got := applyReceipt(t, f.handler, wrong); got != sui.ReceiptMismatch {
		t.Fatalf("wrong funding amount: %s", got)
	}
	f.assertBudget(t, CommunityBudget{})
	if got := applyReceipt(t, f.handler, r); got != sui.ReceiptApplied {
		t.Fatalf("valid funding receipt: %s", got)
	}
	if got := applyReceipt(t, f.handler, r); got != sui.ReceiptDuplicate {
		t.Fatalf("repeated funding receipt: %s", got)
	}
	r.Digest = "second-payment"
	if got := applyReceipt(t, f.handler, r); got != sui.ReceiptMismatch {
		t.Fatalf("second payment of the same top-up: %s", got)
	}
	f.assertBudget(t, CommunityBudget{Funded: 10, Available: 10})
}

func TestCommunityReservationsCannotOverspendOnSeparateHandles(t *testing.T) {
	f := newCommunityPaymentFixture(t)
	f.fund(t, 10)
	var seq int64
	var name, path string
	if err := f.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	other, err := sqlitedb.Open(path, sqlitedb.BusyTimeout(5000))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	ids := []string{"community-first", "community-second"}
	errs := raceCalls([]func() error{
		func() error { return f.reserve(t, f.db, ids[0], 7) },
		func() error { return f.reserve(t, other, ids[1], 7) },
	})
	var accepted int
	for i, err := range errs {
		if err == nil {
			accepted++
			continue
		}
		var insufficient *CommunityFundsError
		if !errors.As(err, &insufficient) || insufficient.Available != 3 || insufficient.Required != 7 {
			t.Fatalf("reservation failed for another reason: %v", err)
		}
		if _, lookupErr := database.New(f.db).GetTransactionByID(t.Context(), ids[i]); !errors.Is(lookupErr, sql.ErrNoRows) {
			t.Fatalf("refused reservation left an intent: %v", lookupErr)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d reservations from a budget for one: %v", accepted, errs)
	}
	f.assertBudget(t, CommunityBudget{Funded: 10, Reserved: 7, Available: 3})
}

func TestCommunitySettlementCreditsOrReturnsBudgetWithoutChainTransfer(t *testing.T) {
	for _, exitCode := range []int32{0, 3} {
		name := "successful"
		if exitCode != 0 {
			name = "failed"
		}
		t.Run(name, func(t *testing.T) {
			f := newCommunityPaymentFixture(t)
			f.fund(t, 10)
			if err := f.reserve(t, f.db, testTxID, testPrice); err != nil {
				t.Fatal(err)
			}
			if claimed, err := claimRefundOrder(t.Context(), f.db); err != nil || !claimed {
				t.Fatalf("claim: %t, %v", claimed, err)
			}
			for range 2 {
				if err := f.handler.SettleTerminalOrder(t.Context(), testDebuglet(), exitCode); err != nil {
					t.Fatal(err)
				}
			}
			wantBudget := CommunityBudget{Funded: 10, Available: 10}
			wantState, wantIncome := models.Refunded, int64(0)
			if exitCode == 0 {
				wantBudget.Spent, wantBudget.Available = testPrice, 10-testPrice
				wantState, wantIncome = models.Credited, testPrice
			}
			f.assertBudget(t, wantBudget)
			if got := orderState(t, f.db); got != wantState {
				t.Fatalf("order state %v, want %v", got, wantState)
			}
			var income, balance int64
			if err := f.db.QueryRow(`SELECT COALESCE(SUM(total_income),0),COALESCE(SUM(current_balance),0)
FROM earnings WHERE executor_id=? AND currency='USDC'`, testExecutor).Scan(&income, &balance); err != nil {
				t.Fatal(err)
			}
			if income != wantIncome || balance != wantIncome {
				t.Fatalf("executor income/balance %d/%d, want %d", income, balance, wantIncome)
			}
			var count int
			if err := f.db.QueryRow("SELECT COUNT(*) FROM order_settlements WHERE transaction_id=?", testTxID).Scan(&count); err != nil || count != 1 {
				t.Fatalf("settlements %d, want 1: %v", count, err)
			}
			if calls := f.chain.Calls(); len(calls) != 1 || calls[0] != "CreatePaymentIntent" {
				t.Fatalf("community settlement reached the chain: %v", calls)
			}
		})
	}
}

func TestCommunityUnadmittedRefundReturnsWholeBudget(t *testing.T) {
	for _, unadmittedOnly := range []bool{true, false} {
		name := "unadmitted"
		if !unadmittedOnly {
			name = "transaction fallback"
		}
		t.Run(name, func(t *testing.T) {
			f := newCommunityPaymentFixture(t)
			f.fund(t, testPrice)
			if err := f.reserve(t, f.db, testTxID, testPrice); err != nil {
				t.Fatal(err)
			}
			if unadmittedOnly {
				outcome, err := f.handler.RefundUnadmittedTransaction(testTxID, t.Context())
				if err != nil || outcome != RefundLocal {
					t.Fatalf("unadmitted refund: %v, %v", outcome, err)
				}
			} else if err := f.handler.RefundTransaction(testTxID, t.Context()); err != nil {
				t.Fatal(err)
			}
			f.assertBudget(t, CommunityBudget{Funded: testPrice, Available: testPrice})
			if transactionStatus(t, f.db) != models.Refunded || orderState(t, f.db) != models.Refunded {
				t.Fatal("refunded reservation remains spendable")
			}
			if claimed, err := claimRefundOrder(t.Context(), f.db); err != nil || claimed {
				t.Fatalf("refunded order admitted: %t, %v", claimed, err)
			}
			if calls := f.chain.Calls(); len(calls) != 1 || calls[0] != "CreatePaymentIntent" {
				t.Fatalf("community refund reached the chain: %v", calls)
			}
		})
	}
}

func TestCommunityExpiryReleasesOnlyUnadmittedReservations(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		name := "unadmitted"
		if admitted {
			name = "admitted"
		}
		t.Run(name, func(t *testing.T) {
			f := newCommunityPaymentFixture(t)
			f.fund(t, testPrice)
			if err := f.reserve(t, f.db, testTxID, testPrice); err != nil {
				t.Fatal(err)
			}
			if admitted {
				if claimed, err := claimRefundOrder(t.Context(), f.db); err != nil || !claimed {
					t.Fatalf("claim: %t, %v", claimed, err)
				}
			}
			expireIntent(t, f.db, testTxID)
			err := f.reserve(t, f.db, "replacement", testPrice)
			if admitted {
				var insufficient *CommunityFundsError
				if !errors.As(err, &insufficient) || transactionStatus(t, f.db) != models.Paid {
					t.Fatalf("admitted reservation released: %v", err)
				}
			} else if err != nil || transactionStatus(t, f.db) != models.Expired {
				t.Fatalf("expired unadmitted reservation not released: %v", err)
			}
			f.assertBudget(t, CommunityBudget{Funded: testPrice, Reserved: testPrice})
		})
	}
}

func TestCommunityFundingChecksCurrentActorAndNetwork(t *testing.T) {
	f := newCommunityPaymentFixture(t)
	r := f.topUp(t, 10)
	if got := applyReceipt(t, f.handler, r); got != sui.ReceiptApplied {
		t.Fatal(got)
	}
	if err := f.handler.CheckCommunitySubmission(t.Context(), f.db, r.Nonce, f.owner.Uuid); !errors.Is(err, ErrCommunityDeposit) {
		t.Fatalf("deposit can be used as a measurement: %v", err)
	}
	f.handler.cfg.Sui.Network = "mainnet"
	f.assertBudget(t, CommunityBudget{})
	if err := f.reserve(t, f.db, "wrong-network", 1); !errors.As(err, new(*CommunityFundsError)) {
		t.Fatalf("testnet funds spendable on mainnet: %v", err)
	}
	f.handler.cfg.Sui.Network = "testnet"
	if err := f.reserve(t, f.db, testTxID, testPrice); err != nil {
		t.Fatal(err)
	}
	if err := f.handler.CheckCommunitySubmission(t.Context(), f.db, testTxID, f.member.Uuid); err != nil {
		t.Fatal(err)
	}
	if err := f.handler.CheckCommunitySubmission(t.Context(), f.db, testTxID, f.owner.Uuid); !errors.Is(err, ErrCommunityNotFound) {
		t.Fatalf("owner can submit another member's intent: %v", err)
	}
	if _, err := f.db.ExecContext(t.Context(), "DELETE FROM community_members WHERE community_id=? AND user_id=?", f.community, f.member.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.handler.CheckCommunitySubmission(t.Context(), f.db, testTxID, f.member.Uuid); !errors.Is(err, ErrCommunityNotFound) {
		t.Fatalf("removed member can use reserved funds: %v", err)
	}
	if claimed, err := claimRefundOrder(t.Context(), f.db); err != nil || claimed {
		t.Fatalf("admission ignored membership removal: %t, %v", claimed, err)
	}
	if err := f.reserve(t, f.db, "after-removal", 1); !errors.Is(err, ErrCommunityNotFound) {
		t.Fatalf("removed member can reserve funds: %v", err)
	}
	f.assertBudget(t, CommunityBudget{Funded: 10, Reserved: testPrice, Available: 10 - testPrice})
}

func TestCommunityTESTUsesSponsorAllowanceOnce(t *testing.T) {
	for _, exitCode := range []int32{0, 3} {
		name := "successful"
		if exitCode != 0 {
			name = "failed"
		}
		t.Run(name, func(t *testing.T) {
			f := newCommunityPaymentFixture(t)
			f.handler.cfg.Allowance.Enabled = true
			mustGrant(t, f.handler, f.owner.Uuid, f.owner.Uuid, 10, "community")
			if err := f.reserveCurrency(t, f.db, testTxID, testPrice, "TEST"); err != nil {
				t.Fatal(err)
			}
			assertAllowance(t, f.handler, f.owner.Uuid, Allowance{Granted: 10, Reserved: testPrice})
			assertAllowance(t, f.handler, f.member.Uuid, Allowance{})
			if claimed, err := claimRefundOrder(t.Context(), f.db); err != nil || !claimed {
				t.Fatalf("claim: %t, %v", claimed, err)
			}
			if err := f.handler.SettleTerminalOrder(t.Context(), testDebuglet(), exitCode); err != nil {
				t.Fatal(err)
			}
			assertAllowance(t, f.handler, f.owner.Uuid, Allowance{Granted: 10, Consumed: testPrice})
			assertAllowance(t, f.handler, f.member.Uuid, Allowance{})
			if err := f.reserveCurrency(t, f.db, "another", testPrice, "TEST"); !errors.As(err, new(*AllowanceExceededError)) {
				t.Fatalf("spent sponsor allowance was reused: %v", err)
			}
			if calls := f.chain.Calls(); len(calls) != 0 {
				t.Fatalf("sponsored TEST work reached the chain: %v", calls)
			}
		})
	}
}

func TestCommunityFundingCannotCrossNetworksAfterCreation(t *testing.T) {
	f := newCommunityPaymentFixture(t)
	receipt := f.topUp(t, 10)
	f.handler.cfg.Sui.Network = "mainnet"
	wrongNetwork := receipt
	wrongNetwork.Digest = "mainnet-payment"
	wrongNetwork.CoinType = sui.GetCoinType("USDC", "mainnet")
	if got := applyReceipt(t, f.handler, wrongNetwork); got != sui.ReceiptMismatch {
		t.Fatalf("testnet deposit funded on mainnet: %s", got)
	}
	transaction, err := database.New(f.db).GetTransactionByID(t.Context(), receipt.Nonce)
	if err != nil || transaction.Status != int64(models.Outstanding) {
		t.Fatalf("wrong-network receipt changed deposit: %+v, %v", transaction, err)
	}
	f.handler.cfg.Sui.Network = "testnet"
	if got := applyReceipt(t, f.handler, receipt); got != sui.ReceiptApplied {
		t.Fatal(got)
	}
	if err := f.reserve(t, f.db, testTxID, testPrice); err != nil {
		t.Fatal(err)
	}
	f.handler.cfg.Sui.Network = "mainnet"
	if err := f.handler.CheckCommunitySubmission(t.Context(), f.db, testTxID, f.member.Uuid); !errors.Is(err, ErrCommunityNetwork) {
		t.Fatalf("testnet reservation admitted on mainnet: %v", err)
	}
	if err := f.handler.SettleTerminalOrder(t.Context(), testDebuglet(), 0); !errors.Is(err, ErrCommunityNetwork) {
		t.Fatalf("testnet order credited on mainnet: %v", err)
	}
	if orderState(t, f.db) != models.Outstanding {
		t.Fatal("network mismatch changed the order")
	}
	var earnings int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM earnings").Scan(&earnings); err != nil || earnings != 0 {
		t.Fatalf("network mismatch credited earnings: %d, %v", earnings, err)
	}
	f.handler.cfg.Sui.Network = "testnet"
	if err := f.handler.CheckCommunitySubmission(t.Context(), f.db, testTxID, f.member.Uuid); err != nil {
		t.Fatal(err)
	}
	if err := f.handler.SettleTerminalOrder(t.Context(), testDebuglet(), 0); err != nil {
		t.Fatal(err)
	}
	f.assertBudget(t, CommunityBudget{Funded: 10, Spent: testPrice, Available: 10 - testPrice})
}

func TestCommunityFullySettledTransactionCannotBeRefunded(t *testing.T) {
	f := newCommunityPaymentFixture(t)
	f.fund(t, 10)
	if err := f.reserve(t, f.db, testTxID, testPrice); err != nil {
		t.Fatal(err)
	}
	if err := f.handler.SettleTerminalOrder(t.Context(), testDebuglet(), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.handler.RefundTransaction(testTxID, t.Context()); err == nil || !strings.Contains(err.Error(), "already settled") {
		t.Fatalf("fully settled refund: %v", err)
	}
	if transactionStatus(t, f.db) != models.Paid || orderState(t, f.db) != models.Credited {
		t.Fatal("refund changed fully settled work")
	}
	f.assertBudget(t, CommunityBudget{Funded: 10, Spent: testPrice, Available: 10 - testPrice})
}
