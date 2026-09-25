package api

import (
	"encoding/base64"
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
					modeChainTxID, modeOrderID, modeExecutorID, tc.want, "TEST", int64(models.Outstanding), modeRefundAddr))

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
