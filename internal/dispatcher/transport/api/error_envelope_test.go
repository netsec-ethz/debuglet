package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/pkg/client"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// Every failure of the API answers with the documented envelope: a stable code
// a client branches on and a bounded message. Before this, several paths
// serialized an error value directly and produced an empty JSON object, and
// others returned the raw database or transport diagnostic.

// envelopeOf decodes one response as the documented envelope and rejects any
// other shape, including the empty object that an unserialized error produced.
func envelopeOf(t *testing.T, what string, body []byte) ErrorResponse {
	t.Helper()
	var envelope ErrorResponse
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatalf("%s: response is not the documented envelope: %v; body: %s", what, err, body)
	}
	if envelope.Code == "" {
		t.Fatalf("%s: response carries no failure code; body: %s", what, body)
	}
	if strings.TrimSpace(envelope.Message) == "" {
		t.Fatalf("%s: response carries no message; body: %s", what, body)
	}
	return envelope
}

func assertEnvelope(t *testing.T, what string, rec *httptest.ResponseRecorder, status int, code, message string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("%s: status = %d, want %d; body: %s", what, rec.Code, status, rec.Body.String())
	}
	envelope := envelopeOf(t, what, rec.Body.Bytes())
	if envelope.Code != code {
		t.Fatalf("%s: code = %q, want %q; body: %s", what, envelope.Code, code, rec.Body.String())
	}
	if message != "" && envelope.Message != message {
		t.Fatalf("%s: message = %q, want %q", what, envelope.Message, message)
	}
}

// TestInvalidIntentAnswersWithATypedEnvelope covers the path that used to
// serialize the error value itself and produce {}.
func TestInvalidIntentAnswersWithATypedEnvelope(t *testing.T) {
	t.Run("unknown executor", func(t *testing.T) {
		f := modeNewFixture(t)
		rec := f.do(http.MethodPut, "/payment/intent", modeIntentBody("TEST"))
		assertEnvelope(t, "unknown executor intent", rec, http.StatusBadRequest,
			CodeUnknownExecutor, "unknown executor: "+modeExecutorID)
		f.expectationsMet("unknown executor intent")
	})

	t.Run("invalid policy", func(t *testing.T) {
		f := modeNewFixture(t)
		f.registerExecutor()
		body := modeIntentBody("TEST")
		body.Debuglets[0].Policy.CeilBW = body.Debuglets[0].Policy.FloorBW - 1
		rec := f.do(http.MethodPut, "/payment/intent", body)
		assertEnvelope(t, "invalid policy intent", rec, http.StatusBadRequest, CodeInvalidPolicy, "")
		if !strings.Contains(rec.Body.String(), "ceil_bw") {
			t.Fatalf("the message does not name the rejected field: %s", rec.Body.String())
		}
		f.expectationsMet("invalid policy intent")
	})

	t.Run("unsupported payment method", func(t *testing.T) {
		f := modeNewFixture(t)
		f.registerExecutor()
		rec := f.do(http.MethodPut, "/payment/intent", modeIntentBody("EUR"))
		assertEnvelope(t, "unknown method intent", rec, http.StatusBadRequest,
			CodeUnsupportedPaymentMethod, "unknown payment method: EUR")
		f.expectationsMet("unknown method intent")
	})
}

// TestRejectedTimeoutsMatchTheDocumentedBounds pins the run budget the
// contract advertises to what the server enforces. A zero timeout used to be
// admitted and priced at zero, and a timeout above the bound used to overflow
// time.Duration silently, so the run received a budget nobody asked for.
func TestRejectedTimeoutsMatchTheDocumentedBounds(t *testing.T) {
	cases := []struct {
		name    string
		timeout int64
	}{
		{"zero", 0},
		{"negative", -1},
		{"overflowing", int64(math.MaxInt64)/int64(time.Millisecond) + 1},
		{"maximum overflow", math.MaxInt64},
	}
	for _, tc := range cases {
		t.Run(tc.name+" intent", func(t *testing.T) {
			f := modeNewFixture(t)
			f.registerExecutor()
			body := modeIntentBody("TEST")
			body.Debuglets[0].Policy.TimeoutMS = tc.timeout
			rec := f.do(http.MethodPut, "/payment/intent", body)
			assertEnvelope(t, "intent timeout", rec, http.StatusBadRequest, CodeInvalidPolicy, "")
			if !strings.Contains(rec.Body.String(), "timeout_ms") {
				t.Fatalf("the message does not name the rejected field: %s", rec.Body.String())
			}
			f.expectationsMet("intent timeout")
		})

		t.Run(tc.name+" submission", func(t *testing.T) {
			f := modeNewFixture(t)
			f.registerExecutor()
			debuglets := modeDebuglets()
			debuglets[0].Policy.TimeoutMS = tc.timeout
			// The transaction is scripted with the hash of these very
			// debuglets, so the request passes the intent check and the policy
			// is what rejects it.
			f.mock.ExpectQuery(modeGetTransactionQuery).
				WithArgs(modeChainTxID).
				WillReturnRows(modeTransactionRows(modeChainTxID, "", "TEST", "", modeRequestHash(t, debuglets), models.Paid))

			rec := f.do(http.MethodPut, "/debuglet", modeSubmitBody(modeChainTxID, "", debuglets))
			assertEnvelope(t, "submitted timeout", rec, http.StatusBadRequest, CodeInvalidPolicy, "")
			if !strings.Contains(rec.Body.String(), "timeout_ms") {
				t.Fatalf("the message does not name the rejected field: %s", rec.Body.String())
			}
			f.expectationsMet("submitted timeout")
			if n := f.recentDebugletIDs(); n != 0 {
				t.Fatalf("executor dispatch history has %d entries, want 0", n)
			}
		})
	}

	// The largest admitted budget is the one the contract documents.
	if got := fmt.Sprint(maxTimeoutMS); got != "9223372036854" {
		t.Fatalf("documented maximum timeout_ms = %s, want 9223372036854", got)
	}
}

func TestSubmissionFailuresAnswerWithATypedEnvelope(t *testing.T) {
	const sentinelKey = "sentinel-auth-key-value"

	t.Run("authorization failure", func(t *testing.T) {
		f := modeNewFixture(t)
		f.registerExecutor()
		debuglets := modeDebuglets()
		f.mock.ExpectQuery(modeGetTransactionQuery).
			WithArgs(modeChainTxID).
			WillReturnRows(modeTransactionRows(modeChainTxID, modeChainAuthKey, "TEST", "", modeRequestHash(t, debuglets), models.Paid))

		rec := f.do(http.MethodPut, "/debuglet", modeSubmitBody(modeChainTxID, sentinelKey, debuglets))
		assertEnvelope(t, "wrong auth key", rec, http.StatusUnauthorized, CodeUnauthorized, "unknown transaction or wrong auth key")
		if strings.Contains(rec.Body.String(), sentinelKey) {
			t.Fatalf("the supplied credential was echoed back: %s", rec.Body.String())
		}
		f.expectationsMet("wrong auth key")
	})

	t.Run("intent mismatch", func(t *testing.T) {
		f := modeNewFixture(t)
		f.registerExecutor()
		altered := modeDebuglets()
		altered[0].Args = []string{"--altered-after-intent"}
		f.mock.ExpectQuery(modeGetTransactionQuery).
			WithArgs(modeChainTxID).
			WillReturnRows(modeTransactionRows(modeChainTxID, "", "TEST", "", modeRequestHash(t, modeDebuglets()), models.Paid))

		rec := f.do(http.MethodPut, "/debuglet", modeSubmitBody(modeChainTxID, "", altered))
		assertEnvelope(t, "altered batch", rec, http.StatusBadRequest, CodeIntentMismatch, "Request does not match the intent")
		f.expectationsMet("altered batch")
	})

	t.Run("unpaid transaction", func(t *testing.T) {
		f := modeNewFixture(t)
		f.registerExecutor()
		debuglets := modeDebuglets()
		f.mock.ExpectQuery(modeGetTransactionQuery).
			WithArgs(modeChainTxID).
			WillReturnRows(modeTransactionRows(modeChainTxID, "", "TEST", "", modeRequestHash(t, debuglets), models.Outstanding))

		rec := f.do(http.MethodPut, "/debuglet", modeSubmitBody(modeChainTxID, "", debuglets))
		assertEnvelope(t, "unpaid transaction", rec, http.StatusBadRequest, CodePaymentIncomplete, "")
		f.expectationsMet("unpaid transaction")
	})
}

// TestMissingRunAnswersWithATypedEnvelope covers the lookup handlers.
func TestMissingRunAnswersWithATypedEnvelope(t *testing.T) {
	id := uuid.MustParse(logsPaginationID)
	for _, route := range []string{"/debuglet/" + logsPaginationID + "/state", "/debuglet/" + logsPaginationID + "/logs"} {
		t.Run(route, func(t *testing.T) {
			f := modeNewFixture(t)
			if strings.HasSuffix(route, "/logs") {
				f.mock.ExpectQuery(logsPaginationListQuery).
					WithArgs(id, int64(0), int64(100)).
					WillReturnRows(sqlmock.NewRows([]string{"id", "debuglet_id", "timestamp", "output"}))
			}
			f.mock.ExpectQuery(logsPaginationGetQuery).WithArgs(id).WillReturnError(sql.ErrNoRows)

			rec := oaServe(f.e, http.MethodGet, route, nil, nil)
			assertEnvelope(t, route, rec, http.StatusNotFound, CodeNotFound, "debuglet not found")
			f.expectationsMet(route)
		})
	}

	t.Run("invalid id", func(t *testing.T) {
		f := modeNewFixture(t)
		rec := oaServe(f.e, http.MethodGet, "/debuglet/not-a-uuid/state", nil, nil)
		assertEnvelope(t, "invalid id", rec, http.StatusBadRequest, CodeInvalidRequest, "")
		f.expectationsMet("invalid id")
	})
}

// TestLookupFailuresKeepTheirDiagnosticsPrivate proves that a database failure
// is reported as an internal failure without its own text.
func TestLookupFailuresKeepTheirDiagnosticsPrivate(t *testing.T) {
	const secret = "table debuglets: password=hunter2"
	f := modeNewFixture(t)
	f.mock.ExpectQuery(logsPaginationGetQuery).
		WithArgs(uuid.MustParse(logsPaginationID)).
		WillReturnError(errString(secret))

	rec := oaServe(f.e, http.MethodGet, "/debuglet/"+logsPaginationID+"/state", nil, nil)
	assertEnvelope(t, "database failure", rec, http.StatusInternalServerError, CodeInternal, "failed to query debuglet")
	if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), "debuglets") {
		t.Fatalf("the database diagnostic reached the client: %s", rec.Body.String())
	}
	f.expectationsMet("database failure")
}

// TestCancellationRefusalKeepsTransportDetailPrivate covers the path that
// passed an error value to Echo and leaked the gRPC status text.
func TestCancellationRefusalKeepsTransportDetailPrivate(t *testing.T) {
	f := modeNewFixture(t)
	rec := f.do(http.MethodDelete, "/debuglet", DebugletDeleteRequest{
		DebugletID: uuid.MustParse(logsPaginationID), ExecutorID: modeExecutorID,
	})
	assertEnvelope(t, "refused cancellation", rec, http.StatusBadRequest, CodeCancelRefused, "cancellation refused")
	if strings.Contains(rec.Body.String(), "rpc error") || strings.Contains(rec.Body.String(), "FailedPrecondition") {
		t.Fatalf("the transport diagnostic reached the client: %s", rec.Body.String())
	}
	f.expectationsMet("refused cancellation")
}

// TestUnroutedRequestsAnswerWithATypedEnvelope covers the failures Echo raises
// before any handler runs.
func TestUnroutedRequestsAnswerWithATypedEnvelope(t *testing.T) {
	f := modeNewFixture(t)

	rec := oaServe(f.e, http.MethodGet, "/no-such-route", nil, nil)
	assertEnvelope(t, "unknown route", rec, http.StatusNotFound, CodeNotFound, "")

	rec = oaServe(f.e, http.MethodPost, "/version", nil, nil)
	assertEnvelope(t, "wrong method", rec, http.StatusMethodNotAllowed, CodeMethodNotAllowed, "")

	rec = oaServe(f.e, http.MethodPut, "/user", []byte(`{"name":`), nil)
	assertEnvelope(t, "malformed body", rec, http.StatusBadRequest, CodeInvalidRequest, "")

	rec = oaServe(f.e, http.MethodPut, "/user", []byte(`{"name":"  "}`), nil)
	assertEnvelope(t, "blank name", rec, http.StatusBadRequest, CodeInvalidRequest, "missing user name")
}

// TestUnsupportedContractVersionCarriesItsCode ties the negotiation rejection
// to a code, so a client can distinguish it from an ordinary bad request.
func TestUnsupportedContractVersionCarriesItsCode(t *testing.T) {
	f := modeNewFixture(t)
	rec := oaServe(f.e, http.MethodPut, "/user", []byte(`{"name":"x"}`),
		map[string]string{"Debuglet-API-Version": "2"})
	assertEnvelope(t, "incompatible contract", rec, http.StatusBadRequest, CodeUnsupportedAPIVersion, "")
}

// TestSDKCodesMatchTheDocumentedCodes keeps the SDK's copy of the vocabulary
// exact. The SDK does not import server packages, so nothing else would.
func TestSDKCodesMatchTheDocumentedCodes(t *testing.T) {
	pairs := map[string]string{
		CodeInvalidRequest:           client.CodeInvalidRequest,
		CodeInvalidPolicy:            client.CodeInvalidPolicy,
		CodeUnknownExecutor:          client.CodeUnknownExecutor,
		CodeIntentMismatch:           client.CodeIntentMismatch,
		CodePaymentIncomplete:        client.CodePaymentIncomplete,
		CodeUnsupportedPaymentMethod: client.CodeUnsupportedPaymentMethod,
		CodePaymentsDisabled:         client.CodePaymentsDisabled,
		CodeUnsupportedAPIVersion:    client.CodeUnsupportedAPIVersion,
		CodeUnauthorized:             client.CodeUnauthorized,
		CodeForbidden:                client.CodeForbidden,
		CodeNotFound:                 client.CodeNotFound,
		CodeCapacityExhausted:        client.CodeCapacityExhausted,
		CodeCancelRefused:            client.CodeCancelRefused,
		CodeMethodNotAllowed:         client.CodeMethodNotAllowed,
		CodeUnsupportedMediaType:     client.CodeUnsupportedMediaType,
		CodePayloadTooLarge:          client.CodePayloadTooLarge,
		CodeInternal:                 client.CodeInternal,
		CodeUnavailable:              client.CodeUnavailable,
	}
	for server, sdk := range pairs {
		if server != sdk {
			t.Errorf("the SDK spells %q as %q", server, sdk)
		}
	}
	// The contract document is the published vocabulary; nothing may be
	// answered that it does not list.
	c := oaContract(t)
	schema, err := c.resolve(c.schemas["Error"])
	if err != nil {
		t.Fatalf("resolve the Error schema: %v", err)
	}
	properties, _ := schema["properties"].(map[string]any)
	code, _ := properties["code"].(map[string]any)
	documented := map[string]bool{}
	values, _ := code["enum"].([]any)
	for _, value := range values {
		documented[value.(string)] = true
	}
	for server := range pairs {
		if !documented[server] {
			t.Errorf("code %q is implemented but not documented in the contract", server)
		}
	}
	if len(documented) != len(pairs) {
		t.Errorf("the contract documents %d codes, the API implements %d", len(documented), len(pairs))
	}
}

// errString is a database failure whose text must never be served.
type errString string

func (e errString) Error() string { return string(e) }
