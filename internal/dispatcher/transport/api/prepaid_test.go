// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/block-vision/sui-go-sdk/signer"
	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	"go.uber.org/zap"
)

// Uses the real signer/intent and receipt verifier, SQLite and admission stack;
// no chain RPC is permitted. The sole fixture receipt represents finality.
func TestPersonalPrepaidIntentSubmissionAndRetry(t *testing.T) {
	f := ccNewFixturePeer(t, zap.NewNop(), &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "SUI"})
	account, token, _ := authAccount(t, f, "native buyer")
	chain := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("unexpected chain RPC")
		http.Error(w, "unexpected", 500)
	}))
	defer chain.Close()
	seed := bytes.Repeat([]byte{7}, 32)
	key := signer.NewSigner(seed)
	encoded, _ := json.Marshal([]string{base64.StdEncoding.EncodeToString(append([]byte{0}, seed...))})
	keyPath := filepath.Join(t.TempDir(), "test.keystore")
	if err := os.WriteFile(keyPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.DispatcherConfig{Sui: config.SuiConfig{Network: "testnet", GRPCEndpoint: chain.Listener.Addr().String(), GraphQLURL: chain.URL, Address: key.Address, KeystorePath: keyPath, PaymentRegistryId: "0x1", PaymentKitPackage: "0x2"}}
	ph, err := payments.NewPaymentHandler(f.db, cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	f.d.Payment = ph
	var deposit struct {
		Method string    `json:"method"`
		Intent SuiIntent `json:"intent"`
	}
	communityRequest(t, f, token, http.MethodPost, "/me/wallet/top-ups", map[string]string{"amount": "20000", "refund_address": "0xbb", "idempotency_key": "fund"}, 201, &deposit)
	if deposit.Method != "SUI" {
		t.Fatal(deposit.Method)
	}
	receipt := sui.PaymentReceipt{Digest: "fixture-paid", Nonce: deposit.Intent.TransactionId, Amount: 20000, CoinType: sui.GetCoinType("SUI", "testnet"), Receiver: key.Address, Timestamp: time.Now()}
	if got, err := ph.ApplyPaymentReceipt(t.Context(), receipt); err != nil || got != sui.ReceiptApplied {
		t.Fatalf("receipt: %s %v", got, err)
	}
	request := PaymentIntentRequest{Prepaid: true, PaymentMethod: "SUI", Debuglets: []DebugletRequest{iaDebuglet(1, 1000, 2000), iaDebuglet(2, 1000, 2000)}}
	if _, err := f.db.Exec(`CREATE TRIGGER reject_second_order BEFORE INSERT ON debuglet_order WHEN NEW.order_id=2 BEGIN SELECT RAISE(ABORT,'injected order failure'); END`); err != nil {
		t.Fatal(err)
	}
	communityRequest(t, f, token, http.MethodPut, "/payment/intent", request, 500, nil)
	if n := iaCount(t, f.db, "personal_funding"); n != 0 {
		t.Fatalf("partial batch reserved credit: %d", n)
	}
	if n := iaCount(t, f.db, "debuglet_order"); n != 0 {
		t.Fatalf("partial batch left %d orders", n)
	}
	if _, err := f.db.Exec(`DROP TRIGGER reject_second_order`); err != nil {
		t.Fatal(err)
	}
	var intent communityFundingIntent
	communityRequest(t, f, token, http.MethodPut, "/payment/intent", request, 200, &intent)
	if intent.Method != "CREDITS" || intent.Currency != "SUI" {
		t.Fatalf("intent: %+v", intent)
	}
	var ids []string
	communityRequest(t, f, token, http.MethodPut, "/debuglet", SubmitDebugletsRequest{Debuglets: request.Debuglets, TransactionId: intent.Intent.TransactionID}, 200, &ids)
	if len(ids) != 2 {
		t.Fatalf("coordinated batch admitted %d", len(ids))
	}
	request.Debuglets = request.Debuglets[:1]
	request.Retry = &wire.RetryLink{ParentRunID: ids[0], RequestID: uuid.NewString()}
	var first, again communityFundingIntent
	communityRequest(t, f, token, http.MethodPut, "/payment/intent", request, 200, &first)
	communityRequest(t, f, token, http.MethodPut, "/payment/intent", request, 200, &again)
	if again != first || again.Method != "CREDITS" {
		t.Fatalf("retry changed funding: %+v / %+v", first, again)
	}
	var wallet communityWalletResponse
	communityRequest(t, f, token, http.MethodGet, "/me/wallet", nil, 200, &wallet)
	if wallet.Currency != "SUI" || wallet.Funded != "20000" {
		t.Fatalf("wallet %+v", wallet)
	}
	if n := iaCount(t, f.db, "personal_funding"); n != 2 {
		t.Fatalf("retry reserved %d intents", n)
	}
	_ = account
}
