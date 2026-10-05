// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/block-vision/sui-go-sdk/signer"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

// The real enabled handler uses only local fixtures. A chain connection,
// including one that fails before sending an RPC, is counted and refused.
func TestPaymentIntentRefundAddressValidationChainEnabled(t *testing.T) {
	var chainConnections atomic.Int64
	chain := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unexpected chain request", http.StatusInternalServerError)
	}))
	chain.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			chainConnections.Add(1)
		}
	}
	chain.StartTLS()
	t.Cleanup(chain.Close)

	seed := bytes.Repeat([]byte{7}, 32)
	key := signer.NewSigner(seed)
	keystore, err := json.Marshal([]string{base64.StdEncoding.EncodeToString(append([]byte{0}, seed...))})
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "sui.keystore")
	if err := os.WriteFile(keyPath, keystore, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "dispatcher.sqlite"), sqlitedb.Create())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatal(err)
	}
	cfg := &config.DispatcherConfig{Sui: config.SuiConfig{
		Network: "testnet", GRPCEndpoint: chain.Listener.Addr().String(), GraphQLURL: chain.URL,
		Address: key.Address, KeystorePath: keyPath, PaymentRegistryId: "0x1", PaymentKitPackage: "0x2",
	}}
	logger := zap.NewNop()
	ph, err := payments.NewPaymentHandler(db, cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	d, err := dispatcher.New(logger, db, "refund-address-test", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	owner := apiTestOwner(t, d, wfExecutorID)
	if err := apiTestRegister(t.Context(), d, owner, &protocol.HelloResponse{
		ExecutorId: wfExecutorID, Version: "test", PricePerBwS: wfPricePerBwS, Currency: "TEST",
	}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if !owner.MarkRegistered() {
		t.Fatal("executor owner retired before registration completed")
	}
	wfSetCapacity(t, d, owner, wfHighCapacity)
	e := echo.New()
	NewHandler(d, db, logger, LocalDevelopment(true)).RegisterRoutes(e)
	f := &modeFixture{t: t, e: e}
	contract := oaContract(t)

	for _, tc := range []struct {
		name, method, address string
		valid                 bool
	}{
		{"USDC empty", "USDC", "", false},
		{"USDC missing prefix", "USDC", "1234", false},
		{"USDC empty digits", "USDC", "0x", false},
		{"USDC non-hexadecimal", "USDC", "0xrefund", false},
		{"USDC whitespace", "USDC", "0x1 ", false},
		{"USDC too long", "USDC", "0x" + strings.Repeat("a", 65), false},
		{"USDC short", "USDC", "0x1", true},
		{"USDC full", "USDC", "0x" + strings.Repeat("a", 64), true},
		{"USDC mixed case digits", "USDC", "0xaBcD", true},
		{"TEST empty", "TEST", "", true},
		{"TEST arbitrary", "TEST", "not a chain address", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.t = t
			before := wfTakeSnapshot(t, db)
			rec := f.do(http.MethodPut, "/payment/intent", PaymentIntentRequest{
				Debuglets: wfDebuglets(), PaymentMethod: tc.method, RefundAddress: tc.address,
			})
			oaCheckResponse(t, contract, http.MethodPut, "/payment/intent", rec.Code, rec.Body.Bytes())
			if !tc.valid {
				modeAssertStatus(t, rec, http.StatusBadRequest)
				var envelope ErrorResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
					t.Fatal(err)
				}
				if envelope.Code != CodeInvalidRequest || len(envelope.FieldErrors) != 1 ||
					envelope.Message != "refund_address must be a Sui address: 0x followed by 1 to 64 hexadecimal digits" {
					t.Fatalf("invalid address response = %+v", envelope)
				}
				field := envelope.FieldErrors[0]
				if field.Field != "refund_address" || field.Code != "invalid_address" || field.OrderID != nil || field.Message != envelope.Message {
					t.Fatalf("refund address field error = %+v", field)
				}
				if after := wfTakeSnapshot(t, db); after != before {
					t.Fatalf("invalid address changed payment state:\nbefore: %s\nafter: %s", before, after)
				}
			} else {
				modeAssertStatus(t, rec, http.StatusOK)
				var response struct {
					Intent struct {
						TransactionID string `json:"transaction_id"`
					} `json:"intent"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				var stored string
				if err := db.QueryRow("SELECT refund_address FROM debuglet_order WHERE transaction_id = ?", response.Intent.TransactionID).Scan(&stored); err != nil {
					t.Fatal(err)
				}
				if stored != tc.address {
					t.Fatalf("stored refund address = %q, want %q", stored, tc.address)
				}
			}
			if got := chainConnections.Load(); got != 0 {
				t.Fatalf("intent creation attempted %d chain connections", got)
			}
		})
	}
}
