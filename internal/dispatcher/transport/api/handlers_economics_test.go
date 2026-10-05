// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// ecQuote asks for a quote of debuglets, paid with method, as the account
// holding token or, with an empty token, anonymously. It returns the status,
// the decoded quote (on 200) or error envelope, and the raw body.
func ecQuote(t *testing.T, f *ccFixture, token, method string, debuglets ...DebugletRequest) (int, wire.Quote, ErrorResponse, []byte) {
	t.Helper()
	body, err := json.Marshal(PaymentIntentRequest{Debuglets: debuglets, PaymentMethod: method})
	if err != nil {
		t.Fatalf("encode the quote request: %v", err)
	}
	return ecQuoteBody(t, f, token, body)
}

func ecQuoteBody(t *testing.T, f *ccFixture, token string, body []byte) (int, wire.Quote, ErrorResponse, []byte) {
	t.Helper()
	status, _, data, _ := authRequest(t, f, http.MethodPost, "/payment/quote", body, authBearer(token))
	var quote wire.Quote
	var envelope ErrorResponse
	if status == http.StatusOK {
		if err := json.Unmarshal(data, &quote); err != nil {
			t.Fatalf("decode the quote %s: %v", data, err)
		}
	} else if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("the refusal is not the documented envelope: %v: %s", err, data)
	}
	return status, quote, envelope, data
}

// ecRowCounts counts the rows a payment intent or a submission would write.
func ecRowCounts(t *testing.T, f *ccFixture) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, table := range []string{"transactions", "debuglet_order", "transaction_users", "debuglets", "retry_requests"} {
		counts[table] = iaCount(t, f.db, table)
	}
	return counts
}

// TestQuoteWritesNothing: a quote, of a valid batch or of one the intent
// would refuse, prices it and stores nothing: no transaction, order, owner,
// run or retry row, in the serving connection or in the file. It carries no
// transaction id and no auth key.
func TestQuoteWritesNothing(t *testing.T) {
	f := ccNewFixture(t)
	before := ecRowCounts(t, f)

	status, quote, _, data := ecQuote(t, f, "", "TEST", iaDebuglet(1, 1000, 2000), iaDebuglet(2, 3000, 1500))
	if status != http.StatusOK {
		t.Fatalf("quote answered %d: %s", status, data)
	}
	want := wire.Quote{
		PricingRule: PricingRule, Currency: "TEST", Unit: "TEST units", Total: "6500",
		Orders: []wire.QuotedOrder{
			{OrderID: 1, ExecutorID: ccExecutorID, Price: "2000", Errors: []wire.FieldError{}},
			{OrderID: 2, ExecutorID: ccExecutorID, Price: "4500", Errors: []wire.FieldError{}},
		},
		Errors: []wire.FieldError{},
	}
	if !reflect.DeepEqual(quote, want) {
		t.Fatalf("quote = %+v, want %+v", quote, want)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("decode the quote fields: %v", err)
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, []string{"currency", "errors", "orders", "pricing_rule", "total", "unit"}) {
		t.Fatalf("quote fields = %v, want no transaction id or auth key", keys)
	}

	if status, _, _, data := ecQuote(t, f, "", "TEST", iaDebuglet(1, 1000, 2000), iaDebuglet(1, 1000, 2000)); status != http.StatusOK {
		t.Fatalf("quote of an invalid batch answered %d: %s", status, data)
	}

	if after := ecRowCounts(t, f); !reflect.DeepEqual(after, before) {
		t.Fatalf("rows after the quotes %v, before %v", after, before)
	}
	reopened := iaReopen(t, f)
	for table, rows := range before {
		var stored int
		if err := reopened.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&stored); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if stored != rows {
			t.Fatalf("the file holds %d %s rows, want %d", stored, table, rows)
		}
	}
}

// TestQuoteAgreesWithIntent: the intent of a batch returns the same quote as
// the quote of that batch, and the prices it stores are the quoted ones.
func TestQuoteAgreesWithIntent(t *testing.T) {
	f := ccNewFixture(t)
	batch := []DebugletRequest{iaDebuglet(1, 1000, 2000), iaDebuglet(2, 3000, 1500), iaDebuglet(3, 1, 1)}
	status, quote, _, data := ecQuote(t, f, "", "TEST", batch...)
	if status != http.StatusOK {
		t.Fatalf("quote answered %d: %s", status, data)
	}
	status, _, txID, data := iaPutIntent(t, f, "", batch...)
	if status != http.StatusOK {
		t.Fatalf("intent answered %d: %s", status, data)
	}
	var intent IntentResponse
	if err := json.Unmarshal(data, &intent); err != nil {
		t.Fatalf("decode the intent: %v", err)
	}
	if intent.Quote == nil || !reflect.DeepEqual(*intent.Quote, quote) {
		t.Fatalf("intent quote = %+v, want the quote %+v", intent.Quote, quote)
	}
	price, _, _, _, orders := ipStored(t, f.db, txID)
	if strconv.FormatInt(price, 10) != quote.Total || len(orders) != len(quote.Orders) {
		t.Fatalf("stored total %d and %d orders, quoted %s and %d", price, len(orders), quote.Total, len(quote.Orders))
	}
	for i, order := range orders {
		if strconv.FormatInt(order[0].(int64), 10) != quote.Orders[i].Price {
			t.Fatalf("stored order %d price %v, quoted %s", i+1, order[0], quote.Orders[i].Price)
		}
	}
}

// TestQuoteReportsEveryProblem: a batch the intent refuses at its first
// problem is quoted with all of them, each on the order it concerns, and with
// no total. Problems of the batch as a whole are the quote's own errors.
func TestQuoteReportsEveryProblem(t *testing.T) {
	f := ccNewFixture(t)
	orderID := func(id int64) *int64 { return &id }

	unknown := iaDebuglet(2, 1000, 2000)
	unknown.ExecutorID = "not-registered"
	belowFloor := iaDebuglet(3, 1000, 2000)
	belowFloor.Policy.CeilBW = 999
	batch := []DebugletRequest{
		iaDebuglet(1, 1000, 2000),
		unknown,
		belowFloor,
		iaDebuglet(1, 1000, 2000),
		iaDebuglet(5, 1000, 0),
		iaDebuglet(6, 989773224860235, 9318672),
	}
	status, quote, _, data := ecQuote(t, f, "", "TEST", batch...)
	if status != http.StatusOK {
		t.Fatalf("quote answered %d: %s", status, data)
	}
	if quote.Total != "" || len(quote.Errors) != 0 || len(quote.Orders) != len(batch) {
		t.Fatalf("quote total %q, errors %v, %d orders; want no total and every order", quote.Total, quote.Errors, len(quote.Orders))
	}
	if quote.Orders[0].Price != "2000" || len(quote.Orders[0].Errors) != 0 {
		t.Fatalf("the valid order is quoted %+v", quote.Orders[0])
	}
	for i, want := range []wire.FieldError{
		{Field: "executor_id", Code: CodeUnknownExecutor, Message: "unknown executor: not-registered", OrderID: orderID(2)},
		{Field: "policy.ceil_bw", Code: "below_floor", Message: "ceil_bw must be at least floor_bw", OrderID: orderID(3)},
		{Field: "order_id", Code: CodeInvalidPolicy, Message: "invalid policy (order 1): order_id is repeated in the batch", OrderID: orderID(1)},
		{Field: "policy.timeout_ms", Code: "out_of_range", Message: "timeout_ms must be positive and at most 9223372036854", OrderID: orderID(5)},
		{Field: "policy", Code: CodeInvalidPolicy, Message: "invalid policy (order 6): the price of the order overflows", OrderID: orderID(6)},
	} {
		order := quote.Orders[i+1]
		if order.Price != "" || !reflect.DeepEqual(order.Errors, []wire.FieldError{want}) {
			t.Fatalf("order %d quoted price %q errors %+v, want %+v", i+1, order.Price, order.Errors, want)
		}
	}
	// The intent of the same batch still stops at the first problem.
	status, envelope, _, _ := iaPutIntent(t, f, "", batch...)
	if status != http.StatusBadRequest || envelope.Code != CodeUnknownExecutor {
		t.Fatalf("intent answered %d %+v, want 400 %s", status, envelope, CodeUnknownExecutor)
	}

	for _, tc := range []struct {
		name      string
		debuglets []DebugletRequest
		want      wire.FieldError
		prices    []string
	}{
		{"an empty batch", []DebugletRequest{},
			wire.FieldError{Field: "debuglets", Code: CodeInvalidRequest, Message: "no debuglets provided"}, []string{}},
		{"a total above the maximum", []DebugletRequest{iaDebuglet(1, 987974896708116, 9335634), iaDebuglet(2, 1, 1001)},
			wire.FieldError{Field: "debuglets", Code: CodeInvalidPolicy, Message: "invalid policy: the total price of the batch overflows"},
			[]string{"9223372036854775806", "2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, quote, _, data := ecQuote(t, f, "", "TEST", tc.debuglets...)
			if status != http.StatusOK {
				t.Fatalf("quote answered %d: %s", status, data)
			}
			if quote.Total != "" || !reflect.DeepEqual(quote.Errors, []wire.FieldError{tc.want}) {
				t.Fatalf("quote total %q errors %+v, want no total and %+v", quote.Total, quote.Errors, tc.want)
			}
			prices := []string{}
			for _, order := range quote.Orders {
				prices = append(prices, order.Price)
			}
			if !reflect.DeepEqual(prices, tc.prices) {
				t.Fatalf("order prices %v, want %v", prices, tc.prices)
			}
		})
	}
}

// TestQuoteKeepsTheIntentRefusals: a request the intent could not read, a
// payment method it does not admit and a caller it does not serve are
// answered as the intent answers them.
func TestQuoteKeepsTheIntentRefusals(t *testing.T) {
	f := ccNewFixture(t)
	valid := iaDebuglet(1, 1000, 2000)
	for _, tc := range []struct {
		name   string
		status int
		code   string
		send   func() (int, wire.Quote, ErrorResponse, []byte)
	}{
		{"malformed JSON", http.StatusBadRequest, CodeInvalidRequest, func() (int, wire.Quote, ErrorResponse, []byte) {
			return ecQuoteBody(t, f, "", []byte(`{"debuglets":`))
		}},
		{"an unknown field", http.StatusBadRequest, CodeInvalidRequest, func() (int, wire.Quote, ErrorResponse, []byte) {
			return ecQuoteBody(t, f, "", []byte(`{"debuglets":[],"payment_method":"TEST","price":1}`))
		}},
		{"a disabled chain method", http.StatusServiceUnavailable, CodePaymentsDisabled, func() (int, wire.Quote, ErrorResponse, []byte) {
			return ecQuote(t, f, "", "USDC", valid)
		}},
		{"an unknown method", http.StatusBadRequest, CodeUnsupportedPaymentMethod, func() (int, wire.Quote, ErrorResponse, []byte) {
			return ecQuote(t, f, "", "BTC", valid)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, _, envelope, data := tc.send()
			if status != tc.status || envelope.Code != tc.code {
				t.Fatalf("answered %d: %s, want %d %s", status, data, tc.status, tc.code)
			}
		})
	}

	enforced := ccNewFixtureWith(t)
	body, _ := json.Marshal(PaymentIntentRequest{Debuglets: []DebugletRequest{valid}, PaymentMethod: "TEST"})
	if status, _, envelope, _ := ecQuoteBody(t, enforced, "", body); status != http.StatusUnauthorized || envelope.Code != CodeUnauthorized {
		t.Fatalf("anonymous quote answered %d %+v, want 401", status, envelope)
	}
	if status, code := authStatus(t, enforced, http.MethodPost, "/payment/quote", nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("anonymous empty quote answered %d %s, want 401", status, code)
	}
}

// TestMeReportsTheAccountEconomics: GET /me states the payment features of a
// dispatcher with blockchain payments disabled.
func TestMeReportsTheAccountEconomics(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, _, authenticated := authAccount(t, f, "economics")
	ctx, cancel := f.requestCtx()
	defer cancel()
	me, err := authenticated.Whoami(ctx)
	if err != nil {
		t.Fatalf("Whoami: %v", err)
	}
	want := &wire.Economics{PaymentMethods: []string{"TEST"}, ChainPayments: false, Allowances: false}
	if !reflect.DeepEqual(me.Economics, want) {
		t.Fatalf("economics = %+v, want %+v", me.Economics, want)
	}
}

// TestOrderHistoryPagesTheCallersIntents: GET /me/orders lists the caller's
// own intents newest first, in pages, each with its orders and the run an
// admitted order started. Another account sees none of them, not even by
// presenting a cursor of the first account.
func TestOrderHistoryPagesTheCallersIntents(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, aliceToken, alice := authAccount(t, f, "alice")
	_, _, bob := authAccount(t, f, "bob")
	ctx, cancel := f.requestCtx()
	defer cancel()

	var created []string
	for _, debuglets := range [][]DebugletRequest{
		{iaDebuglet(1, 1000, 2000)},
		{iaDebuglet(1, 1000, 2000), iaDebuglet(2, 3000, 1500)},
	} {
		status, _, txID, data := iaPutIntent(t, f, aliceToken, debuglets...)
		if status != http.StatusOK {
			t.Fatalf("intent answered %d: %s", status, data)
		}
		created = append(created, txID)
	}
	batch, err := client.Prepare([]client.Request{ccRequest([]string{"127.0.0.1:8080"})})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	submission, err := alice.SubmitTEST(ctx, batch)
	if err != nil {
		t.Fatalf("SubmitTEST: %v", err)
	}
	created = append(created, submission.TransactionID)
	// Settle two unadmitted orders the way the payment handler records it, so
	// each settlement value is listed.
	for _, settle := range []struct {
		state   models.TransactionState
		txID    string
		orderID int64
	}{{models.Credited, created[0], 1}, {models.Refunded, created[1], 2}} {
		if _, err := f.db.Exec("UPDATE debuglet_order SET state = ? WHERE transaction_id = ? AND order_id = ?",
			int64(settle.state), settle.txID, settle.orderID); err != nil {
			t.Fatalf("settle order %d of %s: %v", settle.orderID, settle.txID, err)
		}
	}

	first, err := alice.Orders(ctx, client.OrdersPage{Limit: 2})
	if err != nil {
		t.Fatalf("Orders: %v", err)
	}
	if len(first.Intents) != 2 || first.Next != first.Intents[1].ID {
		t.Fatalf("first page %+v, want two intents and a cursor", first)
	}
	second, err := alice.Orders(ctx, client.OrdersPage{Limit: 2, Before: first.Next})
	if err != nil {
		t.Fatalf("Orders after %s: %v", first.Next, err)
	}
	if len(second.Intents) != 1 || second.Next != "" {
		t.Fatalf("second page %+v, want the last intent and no cursor", second)
	}
	listed := []string{first.Intents[0].ID, first.Intents[1].ID, second.Intents[0].ID}
	if !reflect.DeepEqual(listed, []string{created[2], created[1], created[0]}) {
		t.Fatalf("listed %v, want newest first %v", listed, created)
	}

	submitted := first.Intents[0]
	ccPrice := strconv.FormatInt(ccPricePerBwS*ccFloorBW*ccDurationMS/1000, 10)
	if submitted.Method != "TEST" || submitted.Status != "paid" || submitted.Currency != "TEST" ||
		submitted.Price != ccPrice || submitted.PricingRule != PricingRule || submitted.ExpiresAt.IsZero() {
		t.Fatalf("submitted intent %+v", submitted)
	}
	// The run may already have finished and its TEST order been credited.
	if len(submitted.Orders) != 1 {
		t.Fatalf("submitted orders %+v, want one", submitted.Orders)
	}
	admitted := submitted.Orders[0]
	if admitted.Settlement != "pending" && admitted.Settlement != "credited" {
		t.Fatalf("admitted order settlement %q", admitted.Settlement)
	}
	admitted.Settlement = ""
	if admitted != (wire.OrderHistoryOrder{OrderID: 0, ExecutorID: ccExecutorID, Price: ccPrice, Currency: "TEST", RunID: submission.IDs[0]}) {
		t.Fatalf("admitted order %+v, want run %s", submitted.Orders[0], submission.IDs[0])
	}
	unadmitted := first.Intents[1]
	if unadmitted.Price != "6500" || len(unadmitted.Orders) != 2 ||
		unadmitted.Orders[0] != (wire.OrderHistoryOrder{OrderID: 1, ExecutorID: ccExecutorID, Price: "2000", Currency: "TEST", Settlement: "pending"}) ||
		unadmitted.Orders[1] != (wire.OrderHistoryOrder{OrderID: 2, ExecutorID: ccExecutorID, Price: "4500", Currency: "TEST", Settlement: "refunded"}) {
		t.Fatalf("unadmitted intent %+v", unadmitted)
	}
	if oldest := second.Intents[0]; len(oldest.Orders) != 1 || oldest.Orders[0].Settlement != "credited" || oldest.Orders[0].RunID != "" {
		t.Fatalf("oldest intent %+v, want its one order credited without a run", oldest)
	}

	for _, page := range []client.OrdersPage{{}, {Before: first.Next}, {Before: created[0]}} {
		history, err := bob.Orders(ctx, page)
		if err != nil {
			t.Fatalf("Orders of another account with %+v: %v", page, err)
		}
		if len(history.Intents) != 0 || history.Next != "" {
			t.Fatalf("another account with %+v sees %+v", page, history)
		}
	}

	for _, target := range []string{"/me/orders?limit=0", "/me/orders?limit=101", "/me/orders?limit=x"} {
		if status, code := authAs(t, f, aliceToken, http.MethodGet, target, nil); status != http.StatusBadRequest || code != CodeInvalidRequest {
			t.Fatalf("%s answered %d %s, want 400 %s", target, status, code, CodeInvalidRequest)
		}
	}
	if status, code := authAs(t, f, "", http.MethodGet, "/me/orders", nil); status != http.StatusUnauthorized {
		t.Fatalf("anonymous history answered %d %s, want 401", status, code)
	}
}

// TestQuoteReportsSubmissionRefusals: an order the submission would refuse
// for its start time or for a capability its executor lacks is not quoted as
// admissible. The quote names the field with no total, and intent creation
// refuses the same body with the same code and field.
func TestQuoteReportsSubmissionRefusals(t *testing.T) {
	f := ccNewFixture(t)
	farStart := iaDebuglet(1, 1000, 2000)
	start := int64(math.MaxInt64)
	farStart.StartTimestamp = &start
	icmp := iaDebuglet(1, 1000, 2000)
	icmp.Policy.RequireICMP = true
	startMessage := fmt.Sprintf("start_time must be a Unix timestamp between %d and %d", minStartTimestamp, maxStartTimestamp)
	orderID := int64(1)
	for _, tc := range []struct {
		name  string
		order DebugletRequest
		code  string
		want  wire.FieldError
	}{
		{"an impossible start time", farStart, CodeInvalidRequest,
			wire.FieldError{Field: "start_time", Code: "out_of_range", Message: startMessage, OrderID: &orderID}},
		{"ICMP on an executor without it", icmp, CodeInvalidPolicy,
			wire.FieldError{Field: "policy.require_icmp", Code: "unsupported", Message: "executor does not support ICMP, but policy requires it", OrderID: &orderID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, quote, _, data := ecQuote(t, f, "", "TEST", tc.order)
			if status != http.StatusOK {
				t.Fatalf("quote answered %d: %s", status, data)
			}
			if quote.Total != "" || len(quote.Orders) != 1 || quote.Orders[0].Price != "" ||
				!reflect.DeepEqual(quote.Orders[0].Errors, []wire.FieldError{tc.want}) {
				t.Fatalf("quote %s, want no total and the order error %+v", data, tc.want)
			}
			status, envelope, _, data := iaPutIntent(t, f, "", tc.order)
			if status != http.StatusBadRequest || envelope.Code != tc.code ||
				!reflect.DeepEqual(envelope.FieldErrors, []wire.FieldError{tc.want}) {
				t.Fatalf("intent answered %d %s, want 400 %s naming %s", status, data, tc.code, tc.want.Field)
			}
		})
	}
}
