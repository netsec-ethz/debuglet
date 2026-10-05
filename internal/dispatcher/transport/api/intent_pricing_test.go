package api

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"

	"github.com/DATA-DOG/go-sqlmock"
)

// ipDebuglet is one valid order for the registered mode executor with the given
// order id, floor and timeout.
func ipDebuglet(orderID, floorBW, timeoutMS int64) DebugletRequest {
	return DebugletRequest{
		OrderID:    orderID,
		ExecutorID: modeExecutorID,
		Wasm:       base64.StdEncoding.EncodeToString([]byte("\x00asm pricing")),
		Policy: DebugletPolicyRequest{
			FloorBW:   floorBW,
			CeilBW:    floorBW,
			TimeoutMS: timeoutMS,
		},
	}
}

func ipIntentBody(debuglets ...DebugletRequest) PaymentIntentRequest {
	body := modeIntentBody("TEST")
	body.Debuglets = debuglets
	return body
}

// TestIpIntentPriceIsExact: an order is priced price_per_bw_s × floor_bw ×
// timeout_ms / 1000, rounded up to a whole unit, and that exact value is the
// price stored on the order row. A timeout below one second is not free and a
// fraction of a second is not dropped.
func TestIpIntentPriceIsExact(t *testing.T) {
	cases := []struct {
		name      string
		floorBW   int64
		timeoutMS int64
		want      int64
	}{
		{"one millisecond", 1, 1, 1},
		{"just below a second", 100, 999, 100},
		{"one second", 100, 1000, 100},
		{"just above a second", 100, 1001, 101},
		{"whole seconds", modeFloorBW, modeTimeoutMS, modeOrderPrice},
		{"large product", 1_000_000_000_000_000, 9_000_000, 9_000_000_000_000_000_000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := modeNewFixture(t)
			f.registerExecutor()

			f.mock.ExpectQuery(modeCreateOrderQuery).
				WithArgs(modeChainTxID, modeOrderID, modeExecutorID, tc.want, "TEST", modeRefundAddr, int64(models.Outstanding)).
				WillReturnRows(sqlmock.NewRows(modeOrderColumns).AddRow(
					modeChainTxID, modeOrderID, modeExecutorID, tc.want, "TEST", int64(models.Outstanding), modeRefundAddr, nil))

			price, err := f.h.LockPrice(ipIntentBody(ipDebuglet(modeOrderID, tc.floorBW, tc.timeoutMS)),
				modeChainTxID, modeRefundAddr, t.Context())
			if err != nil {
				t.Fatalf("LockPrice error = %v", err)
			}
			if price != tc.want {
				t.Fatalf("LockPrice price = %d, want %d", price, tc.want)
			}
			f.expectationsMet("priced intent")
		})
	}
}

// TestIpOverflowingIntentWritesNothing: a price that does not fit the stored
// integer is rejected as an invalid policy before any order row is written,
// whether one order overflows or only the batch total does. sqlmock has no
// order expectation, so any write fails the test.
func TestIpOverflowingIntentWritesNothing(t *testing.T) {
	t.Run("one order", func(t *testing.T) {
		f := modeNewFixture(t)
		f.registerExecutor()
		body := ipIntentBody(ipDebuglet(modeOrderID, 1_000_000_000_000_000, 9_223_372_036_854))
		rec := f.do(http.MethodPut, "/payment/intent", body)
		assertEnvelope(t, "overflowing order", rec, http.StatusBadRequest, CodeInvalidPolicy,
			"invalid policy (order 1): the price of the order overflows")
		f.expectationsMet("overflowing order")
	})

	t.Run("batch total", func(t *testing.T) {
		f := modeNewFixture(t)
		f.registerExecutor()
		body := ipIntentBody(
			ipDebuglet(1, 1_000_000_000_000_000, 5_000_000),
			ipDebuglet(2, 1_000_000_000_000_000, 5_000_000),
		)
		rec := f.do(http.MethodPut, "/payment/intent", body)
		assertEnvelope(t, "overflowing batch", rec, http.StatusBadRequest, CodeInvalidPolicy,
			"invalid policy: the total price of the batch overflows")
		f.expectationsMet("overflowing batch")
	})
}

// TestIpInvalidBatchWritesNoOrder: the whole batch is validated before the
// first order row is written, so a later order that is rejected leaves no row
// from an earlier valid one. sqlmock has no order expectation.
func TestIpInvalidBatchWritesNoOrder(t *testing.T) {
	unknown := ipDebuglet(2, modeFloorBW, modeTimeoutMS)
	unknown.ExecutorID = "not-registered"
	invalid := ipDebuglet(2, modeFloorBW, modeTimeoutMS)
	invalid.Policy.CeilBW = modeFloorBW - 1

	cases := []struct {
		name      string
		debuglets []DebugletRequest
		code      string
		message   string
	}{
		{"unknown executor", []DebugletRequest{ipDebuglet(1, modeFloorBW, modeTimeoutMS), unknown},
			CodeUnknownExecutor, "unknown executor: not-registered"},
		{"invalid policy", []DebugletRequest{ipDebuglet(1, modeFloorBW, modeTimeoutMS), invalid},
			CodeInvalidPolicy, "invalid policy (order 2): ceil_bw must be at least floor_bw"},
		{"repeated order", []DebugletRequest{ipDebuglet(1, modeFloorBW, modeTimeoutMS), ipDebuglet(1, modeFloorBW, modeTimeoutMS)},
			CodeInvalidPolicy, "invalid policy (order 1): order_id is repeated in the batch"},
		{"empty batch", []DebugletRequest{},
			CodeInvalidRequest, "no debuglets provided"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := modeNewFixture(t)
			f.registerExecutor()
			rec := f.do(http.MethodPut, "/payment/intent", ipIntentBody(tc.debuglets...))
			assertEnvelope(t, tc.name, rec, http.StatusBadRequest, tc.code, tc.message)
			f.expectationsMet(tc.name)
		})
	}
}

// ipStored reads the stored transaction of an intent and the prices and
// currencies of its orders, in order_id order, from db.
func ipStored(t *testing.T, db *sql.DB, txID string) (price int64, currency, method string, status int64, orders [][2]any) {
	t.Helper()
	if err := db.QueryRow("SELECT price, currency, method, status FROM transactions WHERE id = ?", txID).
		Scan(&price, &currency, &method, &status); err != nil {
		t.Fatalf("stored transaction %s: %v", txID, err)
	}
	rows, err := db.Query("SELECT price, currency FROM debuglet_order WHERE transaction_id = ? ORDER BY order_id", txID)
	if err != nil {
		t.Fatalf("stored orders of %s: %v", txID, err)
	}
	defer rows.Close()
	for rows.Next() {
		var orderPrice int64
		var orderCurrency string
		if err := rows.Scan(&orderPrice, &orderCurrency); err != nil {
			t.Fatalf("scan order: %v", err)
		}
		orders = append(orders, [2]any{orderPrice, orderCurrency})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("stored orders of %s: %v", txID, err)
	}
	return price, currency, method, status, orders
}

// ipAssertPricingRule checks that the stored transaction of an intent names
// the rule that priced it.
func ipAssertPricingRule(t *testing.T, db *sql.DB, txID string) {
	t.Helper()
	var rule string
	if err := db.QueryRow("SELECT pricing_rule FROM transactions WHERE id = ?", txID).Scan(&rule); err != nil {
		t.Fatalf("stored pricing rule of %s: %v", txID, err)
	}
	if rule != PricingRule {
		t.Fatalf("stored pricing rule %q, want %q", rule, PricingRule)
	}
}

// TestIpIntentPricesAtTheLimitsOnSQLite drives PUT /payment/intent against a
// real database at the edges of the pricing rule. The executor charges one
// unit per bit per second and second. A price, of one order or of the batch,
// that is exactly the largest signed 64-bit integer is accepted and stored as
// it is; one unit more is refused as invalid_policy, as is a negative number,
// and a refused intent writes no row.
func TestIpIntentPricesAtTheLimitsOnSQLite(t *testing.T) {
	const maximum = int64(math.MaxInt64)
	for _, tc := range []struct {
		name      string
		debuglets []DebugletRequest
		// prices are the stored order prices of an accepted intent.
		prices []int64
		// refusal is the message of a refused one.
		refusal string
	}{
		{
			// 989865002246749 × 9317808 / 1000 leaves a remainder, so the
			// maximum is reached by rounding up.
			name:      "one order rounded up to the maximum",
			debuglets: []DebugletRequest{iaDebuglet(1, 989865002246749, 9317808)},
			prices:    []int64{maximum},
		},
		{
			name:      "one order one unit above the maximum",
			debuglets: []DebugletRequest{iaDebuglet(1, 989773224860235, 9318672)},
			refusal:   "invalid policy (order 1): the price of the order overflows",
		},
		{
			name:      "a batch totalling the maximum",
			debuglets: []DebugletRequest{iaDebuglet(1, 987974896708116, 9335634), iaDebuglet(2, 1, 1000)},
			prices:    []int64{maximum - 1, 1},
		},
		{
			name:      "a batch one unit above the maximum",
			debuglets: []DebugletRequest{iaDebuglet(1, 987974896708116, 9335634), iaDebuglet(2, 1, 1001)},
			refusal:   "invalid policy: the total price of the batch overflows",
		},
		{
			name:      "a negative floor",
			debuglets: []DebugletRequest{iaDebuglet(1, -1, 1000)},
			refusal:   fmt.Sprintf("invalid policy (order 1): floor_bw must be between 0 and %d bits per second", maxBandwidthBPS),
		},
		{
			name: "a negative ceiling",
			debuglets: func() []DebugletRequest {
				d := iaDebuglet(1, 0, 1000)
				d.Policy.CeilBW = -1
				return []DebugletRequest{d}
			}(),
			refusal: fmt.Sprintf("invalid policy (order 1): ceil_bw must be between 0 and %d bits per second", maxBandwidthBPS),
		},
		{
			name:      "a negative timeout",
			debuglets: []DebugletRequest{iaDebuglet(1, 1000, -1)},
			refusal:   fmt.Sprintf("invalid policy (order 1): timeout_ms must be positive and at most %d", maxTimeoutMS),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := ccNewFixture(t)
			status, envelope, txID, data := iaPutIntent(t, f, "", tc.debuglets...)
			if tc.refusal != "" {
				if status != http.StatusBadRequest || envelope.Code != CodeInvalidPolicy || envelope.Message != tc.refusal {
					t.Fatalf("answered %d %+v, want 400 %s %q", status, envelope, CodeInvalidPolicy, tc.refusal)
				}
				for _, table := range []string{"transactions", "debuglet_order"} {
					if n := iaCount(t, f.db, table); n != 0 {
						t.Fatalf("the refused intent wrote %d %s rows", n, table)
					}
				}
				return
			}
			if status != http.StatusOK {
				t.Fatalf("answered %d: %s", status, data)
			}
			var total int64
			for _, price := range tc.prices {
				total += price
			}
			reopened := iaReopen(t, f)
			price, _, _, _, orders := ipStored(t, reopened, txID)
			ipAssertPricingRule(t, reopened, txID)
			if price != total || total != maximum {
				t.Fatalf("stored total %d, want %d", price, maximum)
			}
			if len(orders) != len(tc.prices) {
				t.Fatalf("stored orders %v, want prices %v", orders, tc.prices)
			}
			for i, order := range orders {
				if order[0] != tc.prices[i] {
					t.Fatalf("stored order %d price %v, want %d", i+1, order[0], tc.prices[i])
				}
			}
		})
	}
}

// TestIpTESTIntentTotalsSurviveReopen: a TEST transaction records the total of
// its batch as its price and TEST as its currency, and every order row its own
// price and TEST. A batch whose floor is zero costs nothing and is stored with
// the total 0. What the file holds after it is opened again is the same.
func TestIpTESTIntentTotalsSurviveReopen(t *testing.T) {
	for _, tc := range []struct {
		name      string
		debuglets []DebugletRequest
		prices    []int64
	}{
		{"a zero total", []DebugletRequest{iaDebuglet(1, 0, 1000)}, []int64{0}},
		{"several orders", []DebugletRequest{
			iaDebuglet(1, 1000, 2000), iaDebuglet(2, 3000, 1500), iaDebuglet(3, 1, 1),
		}, []int64{2000, 4500, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := ccNewFixture(t)
			status, _, txID, data := iaPutIntent(t, f, "", tc.debuglets...)
			if status != http.StatusOK {
				t.Fatalf("answered %d: %s", status, data)
			}
			var total int64
			want := make([][2]any, len(tc.prices))
			for i, price := range tc.prices {
				total += price
				want[i] = [2]any{price, "TEST"}
			}
			for _, source := range []struct {
				name string
				db   *sql.DB
			}{{"serving connection", f.db}, {"reopened file", iaReopen(t, f)}} {
				price, currency, method, state, orders := ipStored(t, source.db, txID)
				if price != total || currency != "TEST" || method != "TEST" || state != int64(models.Paid) {
					t.Fatalf("%s: transaction price=%d currency=%q method=%q status=%d, want %d TEST TEST %d",
						source.name, price, currency, method, state, total, models.Paid)
				}
				if fmt.Sprint(orders) != fmt.Sprint(want) {
					t.Fatalf("%s: orders %v, want %v", source.name, orders, want)
				}
				ipAssertPricingRule(t, source.db, txID)
			}
		})
	}
}
