// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

// iaSentinel is the diagnostic the refusing triggers raise. It belongs in the
// log only, never in a response.
const iaSentinel = "ia_write_refused"

// iaDebuglet is one order for the fixture's registered executor, with its
// ceiling at its floor.
func iaDebuglet(orderID, floorBW, timeoutMS int64) DebugletRequest {
	return DebugletRequest{
		OrderID:    orderID,
		ExecutorID: ccExecutorID,
		Wasm:       base64.StdEncoding.EncodeToString(ccGuest),
		Policy:     DebugletPolicyRequest{FloorBW: floorBW, CeilBW: floorBW, TimeoutMS: timeoutMS},
	}
}

// iaPutIntent requests a TEST intent for debuglets, as the account holding
// token or, with an empty token, anonymously. It returns the status, the
// decoded error envelope (empty on success), the transaction id (empty on
// failure) and the raw body.
func iaPutIntent(t *testing.T, f *ccFixture, token string, debuglets ...DebugletRequest) (int, ErrorResponse, string, []byte) {
	t.Helper()
	body, err := json.Marshal(PaymentIntentRequest{Debuglets: debuglets, PaymentMethod: "TEST"})
	if err != nil {
		t.Fatalf("encode the intent: %v", err)
	}
	status, _, data, _ := authRequest(t, f, http.MethodPut, "/payment/intent", body, authBearer(token))
	var envelope ErrorResponse
	var intent struct {
		Intent struct {
			TransactionID string `json:"transaction_id"`
		} `json:"intent"`
	}
	if status == http.StatusOK {
		if err := json.Unmarshal(data, &intent); err != nil {
			t.Fatalf("decode the intent %s: %v", data, err)
		}
	} else if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("the refusal is not the documented envelope: %v: %s", err, data)
	}
	return status, envelope, intent.Intent.TransactionID, data
}

// iaCount counts the rows of table.
func iaCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var rows int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&rows); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return rows
}

// iaReopen opens the fixture's database file a second time, read-only, so a
// check reads what the file holds rather than what one connection saw.
func iaReopen(t *testing.T, f *ccFixture) *sql.DB {
	t.Helper()
	var seq int64
	var name, file string
	if err := f.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &file); err != nil {
		t.Fatalf("locate the database file: %v", err)
	}
	db, err := sqlitedb.Open(file, sqlitedb.ReadOnly())
	if err != nil {
		t.Fatalf("reopen %s: %v", file, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// A payment intent writes its transaction, its orders and its owner in one SQL
// transaction. Whichever of those writes fails, the request is answered as a
// failure of the server and nothing of the intent is stored: not in the
// connection that served it, and not in the file when it is opened again.
// Once the refusal is gone, the same request stores all of it.
func TestPaymentIntentFailureAtEachWriteStoresNothing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trigger string
		message string
	}{
		{
			name:    "the transaction insert fails",
			trigger: "BEFORE INSERT ON transactions",
			message: "failed to create the payment intent",
		},
		{
			name:    "the second order insert fails",
			trigger: "BEFORE INSERT ON debuglet_order WHEN NEW.order_id = 2",
			message: "failed to store the order",
		},
		{
			name:    "the owner write fails",
			trigger: "BEFORE INSERT ON transaction_users",
			message: "failed to record the payment order owner",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := ccNewFixtureWith(t)
			_, token, _ := authAccount(t, f, "intent owner")
			batch := []DebugletRequest{iaDebuglet(1, ccFloorBW, ccDurationMS), iaDebuglet(2, ccFloorBW, ccDurationMS)}
			tables := []string{"transactions", "debuglet_order", "transaction_users"}

			if _, err := f.db.Exec("CREATE TRIGGER ia_refuse " + tc.trigger + " BEGIN SELECT RAISE(ABORT, '" + iaSentinel + "'); END"); err != nil {
				t.Fatalf("create trigger: %v", err)
			}
			status, envelope, _, data := iaPutIntent(t, f, token, batch...)
			if status != http.StatusInternalServerError || envelope.Code != CodeInternal || envelope.Message != tc.message {
				t.Fatalf("failed write answered %d %+v, want 500 %s %q", status, envelope, CodeInternal, tc.message)
			}
			if strings.Contains(string(data), iaSentinel) {
				t.Fatalf("the database diagnostic reached the client: %s", data)
			}
			for _, table := range tables {
				if n := iaCount(t, f.db, table); n != 0 {
					t.Fatalf("the failed intent left %d %s rows", n, table)
				}
			}
			reopened := iaReopen(t, f)
			for _, table := range tables {
				if n := iaCount(t, reopened, table); n != 0 {
					t.Fatalf("the reopened file holds %d %s rows of the failed intent", n, table)
				}
			}

			if _, err := f.db.Exec("DROP TRIGGER ia_refuse"); err != nil {
				t.Fatalf("drop trigger: %v", err)
			}
			if status, envelope, _, _ := iaPutIntent(t, f, token, batch...); status != http.StatusOK {
				t.Fatalf("the intent without the refusal answered %d %+v", status, envelope)
			}
			for table, want := range map[string]int{"transactions": 1, "debuglet_order": 2, "transaction_users": 1} {
				if n := iaCount(t, reopened, table); n != want {
					t.Fatalf("the reopened file holds %d %s rows after a stored intent, want %d", n, table, want)
				}
			}
		})
	}
}
